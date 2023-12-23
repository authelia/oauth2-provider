// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"time"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/errorsx"
	"authelia.com/provider/oauth2/storage"
)

// HandleTokenEndpointRequest implements
// * https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3 (everything)
func (c *AuthorizeExplicitGrantHandler) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(errorsx.WithStack(oauth2.ErrUnknownRequest))
	}

	if !request.GetClient().GetGrantTypes().Has(consts.GrantTypeAuthorizationCode) {
		return errorsx.WithStack(oauth2.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant \"authorization_code\"."))
	}

	code := request.GetRequestForm().Get(consts.FormParameterAuthorizationCode)
	signature := c.AuthorizeCodeStrategy.AuthorizeCodeSignature(ctx, code)
	authorizeRequest, err := c.CoreStorage.GetAuthorizeCodeSession(ctx, signature, request.GetSession())

	switch {
	case errors.Is(err, oauth2.ErrInvalidatedAuthorizeCode):
		if authorizeRequest == nil {
			return oauth2.ErrServerError.
				WithHint("Misconfigured code lead to an error that prohibited the OAuth 2.0 Framework from processing this request.").
				WithDebug("GetAuthorizeCodeSession must return a value for \"oauth2.Requester\" when returning \"ErrInvalidatedAuthorizeCode\".")
		}

		// If an authorize code is used twice, we revoke all refresh and access tokens associated with this request.
		reqID := authorizeRequest.GetID()
		hint := "The authorization code has already been used."
		debug := ""

		// TODO: Refactor this similar to the Revocation Handler. Maybe Factorize?
		if revErr := c.TokenRevocationStorage.RevokeAccessToken(ctx, reqID); revErr != nil {
			hint += " Additionally, an error occurred during processing the access token revocation."
			debug += "Revocation of access_token lead to error " + revErr.Error() + "."
		}
		if revErr := c.TokenRevocationStorage.RevokeRefreshToken(ctx, reqID); revErr != nil {
			hint += " Additionally, an error occurred during processing the refresh token revocation."
			debug += "Revocation of refresh_token lead to error " + revErr.Error() + "."
		}

		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint(hint).WithDebug(debug))
	case errors.Is(err, oauth2.ErrNotFound):
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithWrap(err).WithDebugError(err))
	case err != nil:
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	// The authorization server MUST verify that the authorization code is valid
	// This needs to happen after store retrieval for the session to be hydrated properly
	if err = c.AuthorizeCodeStrategy.ValidateAuthorizeCode(ctx, request, code); err != nil {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithWrap(err).WithDebugError(err))
	}

	// Override scopes
	request.SetRequestedScopes(authorizeRequest.GetRequestedScopes())

	// Override audiences
	request.SetRequestedAudience(authorizeRequest.GetRequestedAudience())

	// The authorization server MUST ensure that the authorization code was issued to the authenticated
	// confidential client, or if the client is public, ensure that the
	// code was issued to "client_id" in the request,
	if authorizeRequest.GetClient().GetID() != request.GetClient().GetID() {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The OAuth 2.0 Client ID from this request does not match the one from the authorize request."))
	}

	// ensure that the "redirect_uri" parameter is present if the
	// "redirect_uri" parameter was included in the initial authorization
	// request as described in Section 4.1.1, and if included ensure that
	// their values are identical.
	forcedRedirectURI := authorizeRequest.GetRequestForm().Get(consts.FormParameterRedirectURI)
	if forcedRedirectURI != "" && forcedRedirectURI != request.GetRequestForm().Get(consts.FormParameterRedirectURI) {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The \"redirect_uri\" from this request does not match the one from the authorize request."))
	}

	// Checking of POST client_id skipped, because:
	// If the client type is confidential or the client was issued client
	// credentials (or assigned other authentication requirements), the
	// client MUST authenticate with the authorization server as described
	// in Section 3.2.1.
	request.SetSession(authorizeRequest.GetSession())
	request.SetID(authorizeRequest.GetID())

	atLifespan := oauth2.GetEffectiveLifespan(request.GetClient(), oauth2.GrantTypeAuthorizationCode, oauth2.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	request.GetSession().SetExpiresAt(oauth2.AccessToken, time.Now().UTC().Add(atLifespan).Round(time.Second))

	rtLifespan := oauth2.GetEffectiveLifespan(request.GetClient(), oauth2.GrantTypeAuthorizationCode, oauth2.RefreshToken, c.Config.GetRefreshTokenLifespan(ctx))
	if rtLifespan > -1 {
		request.GetSession().SetExpiresAt(oauth2.RefreshToken, time.Now().UTC().Add(rtLifespan).Round(time.Second))
	}

	return nil
}

func canIssueRefreshToken(ctx context.Context, c *AuthorizeExplicitGrantHandler, request oauth2.Requester) bool {
	scope := c.Config.GetRefreshTokenScopes(ctx)
	// Require one of the refresh token scopes, if set.
	if len(scope) > 0 && !request.GetGrantedScopes().HasOneOf(scope...) {
		return false
	}
	// Do not issue a refresh token to clients that cannot use the refresh token grant type.
	if !request.GetClient().GetGrantTypes().Has(consts.GrantTypeRefreshToken) {
		return false
	}
	return true
}

// PopulateTokenEndpointResponse implements oauth2.TokenEndpointHandler.
//
// TODO: Refactor time permitting.
//
//nolint:gocyclo
func (c *AuthorizeExplicitGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, requester oauth2.AccessRequester, responder oauth2.AccessResponder) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	code := requester.GetRequestForm().Get(consts.FormParameterAuthorizationCode)
	signature := c.AuthorizeCodeStrategy.AuthorizeCodeSignature(ctx, code)
	authorizeRequest, err := c.CoreStorage.GetAuthorizeCodeSession(ctx, signature, requester.GetSession())
	if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	} else if err := c.AuthorizeCodeStrategy.ValidateAuthorizeCode(ctx, requester, code); err != nil {
		// This needs to happen after store retrieval for the session to be hydrated properly
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithWrap(err).WithDebugError(err))
	}

	for _, scope := range authorizeRequest.GetGrantedScopes() {
		requester.GrantScope(scope)
	}

	for _, audience := range authorizeRequest.GetGrantedAudience() {
		requester.GrantAudience(audience)
	}

	access, accessSignature, err := c.AccessTokenStrategy.GenerateAccessToken(ctx, requester)
	if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	var refresh, refreshSignature string
	if canIssueRefreshToken(ctx, c, authorizeRequest) {
		refresh, refreshSignature, err = c.RefreshTokenStrategy.GenerateRefreshToken(ctx, requester)
		if err != nil {
			return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
		}
	}

	ctx, err = storage.MaybeBeginTx(ctx, c.CoreStorage)
	if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}
	defer func() {
		if err != nil {
			if rollBackTxnErr := storage.MaybeRollbackTx(ctx, c.CoreStorage); rollBackTxnErr != nil {
				err = errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugf("error: %s; rollback error: %s", err, rollBackTxnErr))
			}
		}
	}()

	if err = c.CoreStorage.InvalidateAuthorizeCodeSession(ctx, signature); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	} else if err = c.CoreStorage.CreateAccessTokenSession(ctx, accessSignature, requester.Sanitize([]string{})); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	} else if refreshSignature != "" {
		if err = c.CoreStorage.CreateRefreshTokenSession(ctx, refreshSignature, requester.Sanitize([]string{})); err != nil {
			return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
		}
	}

	responder.SetAccessToken(access)
	responder.SetTokenType(oauth2.BearerAccessToken)
	atLifespan := oauth2.GetEffectiveLifespan(requester.GetClient(), oauth2.GrantTypeAuthorizationCode, oauth2.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	responder.SetExpiresIn(getExpiresIn(requester, oauth2.AccessToken, atLifespan, time.Now().UTC()))
	responder.SetScopes(requester.GetGrantedScopes())
	if refresh != "" {
		responder.SetExtra(consts.AccessResponseRefreshToken, refresh)
	}

	if err = storage.MaybeCommitTx(ctx, c.CoreStorage); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	return nil
}

func (c *AuthorizeExplicitGrantHandler) CanSkipClientAuth(ctx context.Context, requester oauth2.AccessRequester) bool {
	return false
}

func (c *AuthorizeExplicitGrantHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester oauth2.AccessRequester) bool {
	// grant_type REQUIRED.
	// Value MUST be set to "authorization_code"
	return requester.GetGrantTypes().ExactOne(consts.GrantTypeAuthorizationCode)
}
