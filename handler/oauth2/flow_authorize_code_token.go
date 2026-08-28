// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"time"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

// revokeCodeGrant revokes the access and refresh tokens issued for the request a replayed code belongs to, and returns
// the error the token endpoint answers the replay with. RFC 6749 Section 4.1.2 requires that the authorization server
// deny a code presented more than once and revoke the tokens previously issued from it.
//
// Both the request validation phase and the response population phase re-read the code session, and either can be the
// one to observe the replay depending on how two concurrent redemptions interleave, so both must reach this. Keeping
// it in one place is what stops the two phases from disagreeing about what a replay means.
//
// See: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2
func revokeCodeGrant(ctx context.Context, store TokenRevocationStorage, requestID string) error {
	hint := "The authorization code has already been used."
	debug := ""

	if err := store.RevokeAccessToken(ctx, requestID); err != nil {
		hint += " Additionally, an error occurred during processing the Access Token revocation."
		debug += "Revocation of access_token lead to error " + err.Error() + "."
	}

	if err := store.RevokeRefreshToken(ctx, requestID); err != nil {
		hint += " Additionally, an error occurred during processing the Refresh Token revocation."
		debug += "Revocation of refresh_token lead to error " + err.Error() + "."
	}

	return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint(hint).WithDebug(debug))
}

// HandleTokenEndpointRequest implements
// * https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3 (everything)
func (c *AuthorizeExplicitGrantHandler) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(errorsx.WithStack(oauth2.ErrUnknownRequest))
	}

	if !request.GetClient().GetGrantTypes().Has(consts.GrantTypeAuthorizationCode) {
		return errorsx.WithStack(oauth2.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant 'authorization_code'."))
	}

	code := request.GetRequestForm().Get(consts.FormParameterAuthorizationCode)
	signature := c.AuthorizeCodeStrategy.AuthorizeCodeSignature(ctx, code)
	authorizeRequest, err := c.CoreStorage.GetAuthorizeCodeSession(ctx, signature, request.GetSession())

	switch {
	case errors.Is(err, oauth2.ErrInvalidatedAuthorizeCode):
		if authorizeRequest == nil {
			return oauth2.ErrServerError.
				WithHint("Misconfigured code lead to an error that prohibited the OAuth 2.0 Framework from processing this request.").
				WithDebug("GetAuthorizeCodeSession must return a value for 'oauth2.Requester' when returning 'ErrInvalidatedAuthorizeCode'.")
		}

		return revokeCodeGrant(ctx, c.TokenRevocationStorage, authorizeRequest.GetID())
	case errors.Is(err, oauth2.ErrNotFound):
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithWrap(err).WithDebugf("The authorization code session for the given authorization code was not found."))
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

	// Per RFC 8707 Section 2.2, when the token request omits the 'resource' parameter, fall back
	// to the resources granted at the authorize endpoint. Otherwise the resources requested at the
	// token endpoint MUST be a subset of those granted at the authorize endpoint. The same rule
	// is applied to the 'audience' parameter.
	if len(request.GetRequestedAudience()) == 0 {
		request.SetRequestedAudience(authorizeRequest.GetGrantedAudience())
	} else if err = oauth2.GetAudienceStrategy(ctx, c.Config, request.GetClient())(authorizeRequest.GetGrantedAudience(), request.GetRequestedAudience()); err != nil {
		return err
	}

	if len(request.GetRequestedResource()) == 0 {
		request.SetRequestedResource(authorizeRequest.GetGrantedResource())
	} else if err = oauth2.GetResourceStrategy(ctx, c.Config, request.GetClient())(authorizeRequest.GetGrantedResource(), request.GetRequestedResource()); err != nil {
		return err
	}

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
	redirectURI := authorizeRequest.GetRequestForm().Get(consts.FormParameterRedirectURI)

	switch redirectURI {
	case "":
		if authorizeRequest.GetRequestedScopes().Has(consts.ScopeOpenID) {
			return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The 'redirect_uri' parameter is required when using OpenID Connect 1.0."))
		}
	case request.GetRequestForm().Get(consts.FormParameterRedirectURI):
		break
	default:
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The 'redirect_uri' from this request does not match the one from the authorize request.").WithDebugf("The 'redirect_uri' parameter value '%s' utilized in the Access Request does not match the original 'redirect_uri' parameter value '%s' requested in the Authorize Request which is not permitted.", request.GetRequestForm().Get(consts.FormParameterRedirectURI), redirectURI))
	}

	// Checking of POST client_id skipped, because:
	// If the client type is confidential or the client was issued client
	// credentials (or assigned other authentication requirements), the
	// client MUST authenticate with the authorization server as described
	// in Section 3.2.1.
	request.SetSession(authorizeRequest.GetSession())
	request.SetID(authorizeRequest.GetID())

	atLifespan := oauth2.GetEffectiveLifespan(request.GetClient(), oauth2.GrantTypeAuthorizationCode, oauth2.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	request.GetSession().SetExpiresAt(oauth2.AccessToken, time.Now().UTC().Add(atLifespan).Truncate(jwt.TimePrecision))

	rtLifespan := oauth2.GetEffectiveLifespan(request.GetClient(), oauth2.GrantTypeAuthorizationCode, oauth2.RefreshToken, c.Config.GetRefreshTokenLifespan(ctx))
	if rtLifespan > -1 {
		request.GetSession().SetExpiresAt(oauth2.RefreshToken, time.Now().UTC().Add(rtLifespan).Truncate(jwt.TimePrecision))
	}

	return nil
}

func canIssueRefreshToken(ctx context.Context, c *AuthorizeExplicitGrantHandler, request oauth2.Requester) (issue bool) {
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
func (c *AuthorizeExplicitGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	code := request.GetRequestForm().Get(consts.FormParameterAuthorizationCode)
	signature := c.AuthorizeCodeStrategy.AuthorizeCodeSignature(ctx, code)

	var ar oauth2.Requester

	// This re-read can observe a replay that HandleTokenEndpointRequest could not: two requests bearing the same code
	// both clear that phase while the code is still active, and only one of them goes on to invalidate it. The loser
	// arrives here, so this must reach the same conclusion the first phase would have rather than reporting every
	// error as a server fault, which would answer a replay with a 500 and skip the revocation RFC 6749 Section 4.1.2
	// mandates. That is precisely the window an attacker racing the legitimate client with a stolen code exploits.
	if ar, err = c.CoreStorage.GetAuthorizeCodeSession(ctx, signature, request.GetSession()); err != nil {
		switch {
		case errors.Is(err, oauth2.ErrInvalidatedAuthorizeCode):
			if ar == nil {
				return errorsx.WithStack(oauth2.ErrServerError.
					WithHint("Misconfigured code lead to an error that prohibited the OAuth 2.0 Framework from processing this request.").
					WithDebug("GetAuthorizeCodeSession must return a value for 'oauth2.Requester' when returning 'ErrInvalidatedAuthorizeCode'."))
			}

			return revokeCodeGrant(ctx, c.TokenRevocationStorage, ar.GetID())
		case errors.Is(err, oauth2.ErrNotFound):
			return errorsx.WithStack(oauth2.ErrInvalidGrant.WithWrap(err).WithDebugf("The authorization code session for the given authorization code was not found."))
		default:
			return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
		}
	} else if err = c.AuthorizeCodeStrategy.ValidateAuthorizeCode(ctx, request, code); err != nil {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithWrap(err).WithDebugError(err))
	}

	for _, scope := range ar.GetGrantedScopes() {
		request.GrantScope(scope)
	}

	// Grant the audience and resource requested at the token endpoint. HandleTokenEndpointRequest
	// has already ensured these sets are subsets of the authorize request's granted values (or
	// equal to them when the corresponding parameter was absent at the token endpoint).
	for _, audience := range request.GetRequestedAudience() {
		request.GrantAudience(audience)
	}

	for _, resource := range request.GetRequestedResource() {
		request.GrantResource(resource)
	}

	var access, accessSignature string

	if access, accessSignature, err = c.AccessTokenStrategy.GenerateAccessToken(ctx, request); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	var refresh, refreshSignature string

	if canIssueRefreshToken(ctx, c, ar) {
		if refresh, refreshSignature, err = c.RefreshTokenStrategy.GenerateRefreshToken(ctx, request); err != nil {
			return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
		}
	}

	if ctx, err = storage.MaybeBeginTx(ctx, c.CoreStorage); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	defer func() {
		if err != nil {
			if rollBackTxnErr := storage.MaybeRollbackTx(ctx, c.CoreStorage); rollBackTxnErr != nil {
				err = errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugf("error: %s; rollback error: %s", err, rollBackTxnErr))
			}
		}
	}()

	if err = c.CoreStorage.InvalidateAuthorizeCodeSession(ctx, signature); errors.Is(err, oauth2.ErrInvalidatedAuthorizeCode) {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithDebug("The authorization code has already been exchanged.").WithWrap(err))
	} else if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	} else if err = c.CoreStorage.CreateAccessTokenSession(ctx, accessSignature, request.Sanitize([]string{})); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	} else if refreshSignature != "" {
		if err = c.CoreStorage.CreateRefreshTokenSession(ctx, refreshSignature, accessSignature, request.Sanitize([]string{})); err != nil {
			return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
		}
	}

	atLifespan := oauth2.GetEffectiveLifespan(request.GetClient(), oauth2.GrantTypeAuthorizationCode, oauth2.AccessToken, c.Config.GetAccessTokenLifespan(ctx))

	response.SetAccessToken(access)
	response.SetTokenType(oauth2.BearerAccessToken)
	response.SetExpiresIn(getExpiresIn(request, oauth2.AccessToken, atLifespan, time.Now().UTC()))
	response.SetScopes(request.GetGrantedScopes())

	if refresh != "" {
		response.SetExtra(consts.AccessResponseRefreshToken, refresh)
	}

	if err = storage.MaybeCommitTx(ctx, c.CoreStorage); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	return nil
}

func (c *AuthorizeExplicitGrantHandler) CanSkipClientAuth(ctx context.Context, request oauth2.AccessRequester) (skip bool) {
	return false
}

func (c *AuthorizeExplicitGrantHandler) CanHandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) (handle bool) {
	// The 'grant_type' parameter is REQUIRED and the value MUST be set to 'authorization_code'.
	return request.GetGrantTypes().ExactOne(consts.GrantTypeAuthorizationCode)
}
