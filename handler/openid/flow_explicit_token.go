// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// HandleTokenEndpointRequest always returns oauth2.ErrUnknownRequest as this handler only acts when the token response
// is populated.
func (c *OpenIDConnectExplicitHandler) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) (err error) {
	return errorsx.WithStack(oauth2.ErrUnknownRequest)
}

// PopulateTokenEndpointResponse issues an ID Token for an authorization code grant. It loads the OpenID Connect 1.0
// session stored under the authorization code, deletes it, and adds the 'id_token' with an 'at_hash' claim to the
// response. It returns oauth2.ErrUnknownRequest when no such session exists.
func (c *OpenIDConnectExplicitHandler) PopulateTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	code := request.GetRequestForm().Get(consts.FormParameterAuthorizationCode)

	authorize, err := c.OpenIDConnectRequestStorage.GetOpenIDConnectSession(ctx, code, request)
	if errors.Is(err, ErrNoSessionFound) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest.WithWrap(err).WithDebugError(err))
	} else if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	if !authorize.GetGrantedScopes().Has(consts.ScopeOpenID) {
		return errorsx.WithStack(oauth2.ErrMisconfiguration.WithDebug("An OpenID Connect 1.0 session was found but the 'openid' scope is missing, probably due to a broken code configuration."))
	}

	if !request.GetClient().GetGrantTypes().Has(consts.GrantTypeAuthorizationCode) {
		return errorsx.WithStack(oauth2.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use the authorization grant 'authorization_code'."))
	}

	session, ok := authorize.GetSession().(Session)
	if !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to generate ID Token because the session is not of type 'openid.Session' which is required."))
	}

	claims := session.IDTokenClaims()
	if claims.Subject == "" {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to generate ID Token because subject is an empty string."))
	}

	if err = c.OpenIDConnectRequestStorage.DeleteOpenIDConnectSession(ctx, code); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	claims.AccessTokenHash = c.GetAccessTokenHash(ctx, request, response)

	// The response type `id_token` is only required when performing the implicit or hybrid flow, see:
	// https://openid.net/specs/openid-connect-registration-1_0.html
	//
	// if !requester.GetClient().GetResponseTypes().Has("id_token") {
	// 	return errorsx.WithStack(oauth2.ErrInvalidGrant.WithDebug("The client is not allowed to use response type id_token"))
	// }

	lifespan := oauth2.GetEffectiveLifespan(request.GetClient(), oauth2.GrantTypeAuthorizationCode, oauth2.IDToken, c.Config.GetIDTokenLifespan(ctx))

	return c.IssueExplicitIDToken(ctx, lifespan, authorize, response)
}

// CanSkipClientAuth always returns false, client authentication is never skipped by this handler.
func (c *OpenIDConnectExplicitHandler) CanSkipClientAuth(ctx context.Context, request oauth2.AccessRequester) (skip bool) {
	return false
}

// CanHandleTokenEndpointRequest reports whether the 'grant_type' is exactly 'authorization_code'.
func (c *OpenIDConnectExplicitHandler) CanHandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) (handle bool) {
	return request.GetGrantTypes().ExactOne(consts.GrantTypeAuthorizationCode)
}
