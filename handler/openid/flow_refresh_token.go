// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"

	"github.com/authelia/goauth2"
	"github.com/authelia/goauth2/internal/errorsx"
)

type OpenIDConnectRefreshHandler struct {
	*IDTokenHandleHelper

	Config interface {
		goauth2.IDTokenLifespanProvider
	}
}

func (c *OpenIDConnectRefreshHandler) HandleTokenEndpointRequest(ctx context.Context, request goauth2.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(goauth2.ErrUnknownRequest)
	}

	if !request.GetGrantedScopes().Has("openid") {
		return errorsx.WithStack(goauth2.ErrUnknownRequest)
	}

	if !request.GetClient().GetGrantTypes().Has("refresh_token") {
		return errorsx.WithStack(goauth2.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use the authorization grant \"refresh_token\"."))
	}

	// Refresh tokens can only be issued by an authorize_code which in turn disables the need to check if the id_token
	// response type is enabled by the client.
	//
	// if !request.GetClient().GetResponseTypes().Has("id_token") {
	// 	return errorsx.WithStack(goauth2.ErrUnknownRequest.WithDebug("The client is not allowed to use response type id_token"))
	// }

	sess, ok := request.GetSession().(Session)
	if !ok {
		return errors.New("Failed to generate id token because session must be of type goauth2/handler/openid.Session")
	}

	// We need to reset the expires at value as this would be the previous expiry.
	sess.IDTokenClaims().ExpiresAt = time.Time{}

	// These will be recomputed in PopulateTokenEndpointResponse
	sess.IDTokenClaims().JTI = ""
	sess.IDTokenClaims().AccessTokenHash = ""

	// We are not issuing a code so there is no need for this field.
	sess.IDTokenClaims().CodeHash = ""

	return nil
}

func (c *OpenIDConnectRefreshHandler) PopulateTokenEndpointResponse(ctx context.Context, requester goauth2.AccessRequester, responder goauth2.AccessResponder) error {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(goauth2.ErrUnknownRequest)
	}

	if !requester.GetGrantedScopes().Has("openid") {
		return errorsx.WithStack(goauth2.ErrUnknownRequest)
	}

	if !requester.GetClient().GetGrantTypes().Has("refresh_token") {
		return errorsx.WithStack(goauth2.ErrInvalidGrant.WithHint("The OAuth 2.0 Client is not allowed to use the authorization grant \"refresh_token\"."))
	}

	// Disabled because this is already handled at the authorize_request_handler
	// if !requester.GetClient().GetResponseTypes().Has("id_token") {
	// 	 return errorsx.WithStack(goauth2.ErrUnknownRequest.WithDebug("The client is not allowed to use response type id_token"))
	// }

	sess, ok := requester.GetSession().(Session)
	if !ok {
		return errorsx.WithStack(goauth2.ErrServerError.WithDebug("Failed to generate id token because session must be of type goauth2/handler/openid.Session."))
	}

	claims := sess.IDTokenClaims()
	if claims.Subject == "" {
		return errorsx.WithStack(goauth2.ErrServerError.WithDebug("Failed to generate id token because subject is an empty string."))
	}

	claims.AccessTokenHash = c.GetAccessTokenHash(ctx, requester, responder)
	claims.JTI = uuid.New().String()
	claims.CodeHash = ""
	claims.IssuedAt = time.Now().Truncate(time.Second)

	idTokenLifespan := goauth2.GetEffectiveLifespan(requester.GetClient(), goauth2.GrantTypeRefreshToken, goauth2.IDToken, c.Config.GetIDTokenLifespan(ctx))
	return c.IssueExplicitIDToken(ctx, idTokenLifespan, requester, responder)
}

func (c *OpenIDConnectRefreshHandler) CanSkipClientAuth(ctx context.Context, requester goauth2.AccessRequester) bool {
	return false
}

func (c *OpenIDConnectRefreshHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester goauth2.AccessRequester) bool {
	// grant_type REQUIRED.
	// Value MUST be set to "refresh_token"
	return requester.GetGrantTypes().ExactOne("refresh_token")
}
