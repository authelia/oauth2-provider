// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"time"

	"github.com/ory/x/errorsx"
	"github.com/pkg/errors"

	"github.com/authelia/goauth2"
	"github.com/authelia/goauth2/storage"
)

// HandleTokenEndpointRequest implements
// * https://tools.ietf.org/html/rfc6749#section-4.1.3 (everything)
func (c *AuthorizeExplicitGrantHandler) HandleTokenEndpointRequest(ctx context.Context, request goauth2.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(errorsx.WithStack(goauth2.ErrUnknownRequest))
	}

	if !request.GetClient().GetGrantTypes().Has("authorization_code") {
		return errorsx.WithStack(goauth2.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant \"authorization_code\"."))
	}

	code := request.GetRequestForm().Get("code")
	signature := c.AuthorizeCodeStrategy.AuthorizeCodeSignature(ctx, code)
	authorizeRequest, err := c.CoreStorage.GetAuthorizeCodeSession(ctx, signature, request.GetSession())
	if errors.Is(err, goauth2.ErrInvalidatedAuthorizeCode) {
		if authorizeRequest == nil {
			return goauth2.ErrServerError.
				WithHint("Misconfigured code lead to an error that prohibited the OAuth 2.0 Framework from processing this request.").
				WithDebug("GetAuthorizeCodeSession must return a value for \"goauth2.Requester\" when returning \"ErrInvalidatedAuthorizeCode\".")
		}

		// If an authorize code is used twice, we revoke all refresh and access tokens associated with this request.
		reqID := authorizeRequest.GetID()
		hint := "The authorization code has already been used."
		debug := ""
		if revErr := c.TokenRevocationStorage.RevokeAccessToken(ctx, reqID); revErr != nil {
			hint += " Additionally, an error occurred during processing the access token revocation."
			debug += "Revocation of access_token lead to error " + revErr.Error() + "."
		}
		if revErr := c.TokenRevocationStorage.RevokeRefreshToken(ctx, reqID); revErr != nil {
			hint += " Additionally, an error occurred during processing the refresh token revocation."
			debug += "Revocation of refresh_token lead to error " + revErr.Error() + "."
		}
		return errorsx.WithStack(goauth2.ErrInvalidGrant.WithHint(hint).WithDebug(debug))
	} else if err != nil && errors.Is(err, goauth2.ErrNotFound) {
		return errorsx.WithStack(goauth2.ErrInvalidGrant.WithWrap(err).WithDebug(err.Error()))
	} else if err != nil {
		return errorsx.WithStack(goauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	// The authorization server MUST verify that the authorization code is valid
	// This needs to happen after store retrieval for the session to be hydrated properly
	if err := c.AuthorizeCodeStrategy.ValidateAuthorizeCode(ctx, request, code); err != nil {
		return errorsx.WithStack(goauth2.ErrInvalidGrant.WithWrap(err).WithDebug(err.Error()))
	}

	// Override scopes
	request.SetRequestedScopes(authorizeRequest.GetRequestedScopes())

	// Override audiences
	request.SetRequestedAudience(authorizeRequest.GetRequestedAudience())

	// The authorization server MUST ensure that the authorization code was issued to the authenticated
	// confidential client, or if the client is public, ensure that the
	// code was issued to "client_id" in the request,
	if authorizeRequest.GetClient().GetID() != request.GetClient().GetID() {
		return errorsx.WithStack(goauth2.ErrInvalidGrant.WithHint("The OAuth 2.0 Client ID from this request does not match the one from the authorize request."))
	}

	// ensure that the "redirect_uri" parameter is present if the
	// "redirect_uri" parameter was included in the initial authorization
	// request as described in Section 4.1.1, and if included ensure that
	// their values are identical.
	forcedRedirectURI := authorizeRequest.GetRequestForm().Get("redirect_uri")
	if forcedRedirectURI != "" && forcedRedirectURI != request.GetRequestForm().Get("redirect_uri") {
		return errorsx.WithStack(goauth2.ErrInvalidGrant.WithHint("The \"redirect_uri\" from this request does not match the one from the authorize request."))
	}

	// Checking of POST client_id skipped, because:
	// If the client type is confidential or the client was issued client
	// credentials (or assigned other authentication requirements), the
	// client MUST authenticate with the authorization server as described
	// in Section 3.2.1.
	request.SetSession(authorizeRequest.GetSession())
	request.SetID(authorizeRequest.GetID())

	atLifespan := goauth2.GetEffectiveLifespan(request.GetClient(), goauth2.GrantTypeAuthorizationCode, goauth2.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	request.GetSession().SetExpiresAt(goauth2.AccessToken, time.Now().UTC().Add(atLifespan).Round(time.Second))

	rtLifespan := goauth2.GetEffectiveLifespan(request.GetClient(), goauth2.GrantTypeAuthorizationCode, goauth2.RefreshToken, c.Config.GetRefreshTokenLifespan(ctx))
	if rtLifespan > -1 {
		request.GetSession().SetExpiresAt(goauth2.RefreshToken, time.Now().UTC().Add(rtLifespan).Round(time.Second))
	}

	return nil
}

func canIssueRefreshToken(ctx context.Context, c *AuthorizeExplicitGrantHandler, request goauth2.Requester) bool {
	scope := c.Config.GetRefreshTokenScopes(ctx)
	// Require one of the refresh token scopes, if set.
	if len(scope) > 0 && !request.GetGrantedScopes().HasOneOf(scope...) {
		return false
	}
	// Do not issue a refresh token to clients that cannot use the refresh token grant type.
	if !request.GetClient().GetGrantTypes().Has("refresh_token") {
		return false
	}
	return true
}

func (c *AuthorizeExplicitGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, requester goauth2.AccessRequester, responder goauth2.AccessResponder) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(goauth2.ErrUnknownRequest)
	}

	code := requester.GetRequestForm().Get("code")
	signature := c.AuthorizeCodeStrategy.AuthorizeCodeSignature(ctx, code)
	authorizeRequest, err := c.CoreStorage.GetAuthorizeCodeSession(ctx, signature, requester.GetSession())
	if err != nil {
		return errorsx.WithStack(goauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	} else if err := c.AuthorizeCodeStrategy.ValidateAuthorizeCode(ctx, requester, code); err != nil {
		// This needs to happen after store retrieval for the session to be hydrated properly
		return errorsx.WithStack(goauth2.ErrInvalidRequest.WithWrap(err).WithDebug(err.Error()))
	}

	for _, scope := range authorizeRequest.GetGrantedScopes() {
		requester.GrantScope(scope)
	}

	for _, audience := range authorizeRequest.GetGrantedAudience() {
		requester.GrantAudience(audience)
	}

	access, accessSignature, err := c.AccessTokenStrategy.GenerateAccessToken(ctx, requester)
	if err != nil {
		return errorsx.WithStack(goauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	var refresh, refreshSignature string
	if canIssueRefreshToken(ctx, c, authorizeRequest) {
		refresh, refreshSignature, err = c.RefreshTokenStrategy.GenerateRefreshToken(ctx, requester)
		if err != nil {
			return errorsx.WithStack(goauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
	}

	ctx, err = storage.MaybeBeginTx(ctx, c.CoreStorage)
	if err != nil {
		return errorsx.WithStack(goauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}
	defer func() {
		if err != nil {
			if rollBackTxnErr := storage.MaybeRollbackTx(ctx, c.CoreStorage); rollBackTxnErr != nil {
				err = errorsx.WithStack(goauth2.ErrServerError.WithWrap(err).WithDebugf("error: %s; rollback error: %s", err, rollBackTxnErr))
			}
		}
	}()

	if err = c.CoreStorage.InvalidateAuthorizeCodeSession(ctx, signature); err != nil {
		return errorsx.WithStack(goauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	} else if err = c.CoreStorage.CreateAccessTokenSession(ctx, accessSignature, requester.Sanitize([]string{})); err != nil {
		return errorsx.WithStack(goauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	} else if refreshSignature != "" {
		if err = c.CoreStorage.CreateRefreshTokenSession(ctx, refreshSignature, requester.Sanitize([]string{})); err != nil {
			return errorsx.WithStack(goauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
	}

	responder.SetAccessToken(access)
	responder.SetTokenType("bearer")
	atLifespan := goauth2.GetEffectiveLifespan(requester.GetClient(), goauth2.GrantTypeAuthorizationCode, goauth2.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	responder.SetExpiresIn(getExpiresIn(requester, goauth2.AccessToken, atLifespan, time.Now().UTC()))
	responder.SetScopes(requester.GetGrantedScopes())
	if refresh != "" {
		responder.SetExtra("refresh_token", refresh)
	}

	if err = storage.MaybeCommitTx(ctx, c.CoreStorage); err != nil {
		return errorsx.WithStack(goauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	return nil
}

func (c *AuthorizeExplicitGrantHandler) CanSkipClientAuth(ctx context.Context, requester goauth2.AccessRequester) bool {
	return false
}

func (c *AuthorizeExplicitGrantHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester goauth2.AccessRequester) bool {
	// grant_type REQUIRED.
	// Value MUST be set to "authorization_code"
	return requester.GetGrantTypes().ExactOne("authorization_code")
}
