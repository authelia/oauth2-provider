// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"time"

	"github.com/google/uuid"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

type OpenIDConnectRefreshHandler struct {
	*IDTokenHandleHelper

	Config interface {
		oauth2.IDTokenLifespanProvider
	}
}

// HandleTokenEndpointRequest handles a refresh token grant which was granted the 'openid' scope. It requires the client
// to be registered for the 'refresh_token' grant type and clears the 'exp', 'jti', 'at_hash' and 'c_hash' claims of the
// session so the refreshed ID Token does not inherit them.
func (c *OpenIDConnectRefreshHandler) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	if !request.GetGrantedScopes().Has(consts.ScopeOpenID) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	if !request.GetClient().GetGrantTypes().Has(consts.GrantTypeRefreshToken) {
		return errorsx.WithStack(oauth2.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use the authorization grant 'refresh_token'."))
	}

	session, ok := request.GetSession().(Session)
	if !ok {
		return errorsx.WithStack(oauth2.ErrServerError.
			WithDebug("Failed to generate ID Token because the session is not of type 'openid.Session' which is required."))
	}

	session.IDTokenClaims().ExpirationTime = jwt.NewNumericDate(time.Time{})
	session.IDTokenClaims().JTI = ""
	session.IDTokenClaims().AccessTokenHash = ""
	session.IDTokenClaims().CodeHash = ""

	return nil
}

// PopulateTokenEndpointResponse issues a refreshed ID Token for a refresh token grant which was granted the 'openid'
// scope. The token has a new 'jti', 'iat' and 'at_hash', and no 'c_hash' or 'nonce' claim.
func (c *OpenIDConnectRefreshHandler) PopulateTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	if !request.GetGrantedScopes().Has(consts.ScopeOpenID) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	if !request.GetClient().GetGrantTypes().Has(consts.GrantTypeRefreshToken) {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The OAuth 2.0 Client is not allowed to use the authorization grant 'refresh_token'."))
	}

	session, ok := request.GetSession().(Session)
	if !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to generate ID Token because the session is not of type 'openid.Session' which is required."))
	}

	claims := session.IDTokenClaims()
	if claims.Subject == "" {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to generate ID Token because subject is an empty string."))
	}

	claims.AccessTokenHash = c.GetAccessTokenHash(ctx, request, response)
	claims.JTI = uuid.New().String()
	claims.CodeHash = ""

	// OpenID Connect Core 1.0 Section 12.2: a refreshed ID Token SHOULD NOT have a nonce claim.
	claims.Nonce = ""
	claims.IssuedAt = jwt.Now()

	lifespan := oauth2.GetEffectiveLifespan(request.GetClient(), oauth2.GrantTypeRefreshToken, oauth2.IDToken, c.Config.GetIDTokenLifespan(ctx))

	return c.IssueExplicitIDToken(ctx, lifespan, request, response)
}

// CanSkipClientAuth always returns false, client authentication is never skipped by this handler.
func (c *OpenIDConnectRefreshHandler) CanSkipClientAuth(ctx context.Context, request oauth2.AccessRequester) (skip bool) {
	return false
}

// CanHandleTokenEndpointRequest reports whether the 'grant_type' is exactly 'refresh_token'.
func (c *OpenIDConnectRefreshHandler) CanHandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) (handle bool) {
	return request.GetGrantTypes().ExactOne(consts.GrantTypeRefreshToken)
}

var (
	_ oauth2.TokenEndpointHandler = (*OpenIDConnectRefreshHandler)(nil)
)
