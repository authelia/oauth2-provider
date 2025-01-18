// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"

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

	// Refresh tokens can only be issued by an authorize_code which in turn disables the need to check if the id_token
	// response type is enabled by the client.
	//
	// if !request.GetClient().GetResponseTypes().Has("id_token") {
	// 	return errorsx.WithStack(oauth2.ErrUnknownRequest.WithDebug("The client is not allowed to use response type id_token"))
	// }

	sess, ok := request.GetSession().(Session)
	if !ok {
		return errors.New("Failed to generate id token because session must be of type oauth2/handler/openid.Session")
	}

	// We need to reset the expires at value as this would be the previous expiry.
	sess.IDTokenClaims().ExpirationTime = jwt.NewNumericDate(time.Time{})

	// These will be recomputed in PopulateTokenEndpointResponse
	sess.IDTokenClaims().JTI = ""
	sess.IDTokenClaims().AccessTokenHash = ""

	// We are not issuing a code so there is no need for this field.
	sess.IDTokenClaims().CodeHash = ""

	return nil
}

func (c *OpenIDConnectRefreshHandler) PopulateTokenEndpointResponse(ctx context.Context, requester oauth2.AccessRequester, responder oauth2.AccessResponder) error {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	if !requester.GetGrantedScopes().Has(consts.ScopeOpenID) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	if !requester.GetClient().GetGrantTypes().Has(consts.GrantTypeRefreshToken) {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The OAuth 2.0 Client is not allowed to use the authorization grant 'refresh_token'."))
	}

	// Disabled because this is already handled at the authorize_request_handler
	// if !requester.GetClient().GetResponseTypes().Has("id_token") {
	// 	 return errorsx.WithStack(oauth2.ErrUnknownRequest.WithDebug("The client is not allowed to use response type id_token"))
	// }

	sess, ok := requester.GetSession().(Session)
	if !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to generate id token because session must be of type oauth2/handler/openid.Session."))
	}

	claims := sess.IDTokenClaims()
	if claims.Subject == "" {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to generate id token because subject is an empty string."))
	}

	claims.AccessTokenHash = c.GetAccessTokenHash(ctx, requester, responder)
	claims.JTI = uuid.New().String()
	claims.CodeHash = ""
	claims.IssuedAt = jwt.Now()

	idTokenLifespan := oauth2.GetEffectiveLifespan(requester.GetClient(), oauth2.GrantTypeRefreshToken, oauth2.IDToken, c.Config.GetIDTokenLifespan(ctx))
	return c.IssueExplicitIDToken(ctx, idTokenLifespan, requester, responder)
}

func (c *OpenIDConnectRefreshHandler) CanSkipClientAuth(ctx context.Context, requester oauth2.AccessRequester) bool {
	return false
}

func (c *OpenIDConnectRefreshHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester oauth2.AccessRequester) bool {
	// grant_type REQUIRED.
	// Value MUST be set to "refresh_token"
	return requester.GetGrantTypes().ExactOne(consts.GrantTypeRefreshToken)
}
