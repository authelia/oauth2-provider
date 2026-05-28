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

func (c *OpenIDConnectRefreshHandler) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) error {
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

func (c *OpenIDConnectRefreshHandler) PopulateTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) error {
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
	claims.IssuedAt = jwt.Now()

	lifespan := oauth2.GetEffectiveLifespan(request.GetClient(), oauth2.GrantTypeRefreshToken, oauth2.IDToken, c.Config.GetIDTokenLifespan(ctx))

	return c.IssueExplicitIDToken(ctx, lifespan, request, response)
}

func (c *OpenIDConnectRefreshHandler) CanSkipClientAuth(ctx context.Context, request oauth2.AccessRequester) bool {
	return false
}

func (c *OpenIDConnectRefreshHandler) CanHandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) bool {
	return request.GetGrantTypes().ExactOne(consts.GrantTypeRefreshToken)
}
