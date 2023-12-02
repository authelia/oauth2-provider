// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"

	"github.com/pkg/errors"

	"github.com/authelia/goauth2"
	"github.com/authelia/goauth2/internal/errorsx"
)

func (c *OpenIDConnectExplicitHandler) HandleTokenEndpointRequest(ctx context.Context, request goauth2.AccessRequester) error {
	return errorsx.WithStack(goauth2.ErrUnknownRequest)
}

func (c *OpenIDConnectExplicitHandler) PopulateTokenEndpointResponse(ctx context.Context, requester goauth2.AccessRequester, responder goauth2.AccessResponder) error {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(goauth2.ErrUnknownRequest)
	}

	authorize, err := c.OpenIDConnectRequestStorage.GetOpenIDConnectSession(ctx, requester.GetRequestForm().Get("code"), requester)
	if errors.Is(err, ErrNoSessionFound) {
		return errorsx.WithStack(goauth2.ErrUnknownRequest.WithWrap(err).WithDebug(err.Error()))
	} else if err != nil {
		return errorsx.WithStack(goauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	if !authorize.GetGrantedScopes().Has("openid") {
		return errorsx.WithStack(goauth2.ErrMisconfiguration.WithDebug("An OpenID Connect session was found but the openid scope is missing, probably due to a broken code configuration."))
	}

	if !requester.GetClient().GetGrantTypes().Has("authorization_code") {
		return errorsx.WithStack(goauth2.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use the authorization grant \"authorization_code\"."))
	}

	sess, ok := authorize.GetSession().(Session)
	if !ok {
		return errorsx.WithStack(goauth2.ErrServerError.WithDebug("Failed to generate id token because session must be of type goauth2/handler/openid.Session."))
	}

	claims := sess.IDTokenClaims()
	if claims.Subject == "" {
		return errorsx.WithStack(goauth2.ErrServerError.WithDebug("Failed to generate id token because subject is an empty string."))
	}

	claims.AccessTokenHash = c.GetAccessTokenHash(ctx, requester, responder)

	// The response type `id_token` is only required when performing the implicit or hybrid flow, see:
	// https://openid.net/specs/openid-connect-registration-1_0.html
	//
	// if !requester.GetClient().GetResponseTypes().Has("id_token") {
	// 	return errorsx.WithStack(goauth2.ErrInvalidGrant.WithDebug("The client is not allowed to use response type id_token"))
	// }

	idTokenLifespan := goauth2.GetEffectiveLifespan(requester.GetClient(), goauth2.GrantTypeAuthorizationCode, goauth2.IDToken, c.Config.GetIDTokenLifespan(ctx))
	return c.IssueExplicitIDToken(ctx, idTokenLifespan, authorize, responder)
}

func (c *OpenIDConnectExplicitHandler) CanSkipClientAuth(ctx context.Context, requester goauth2.AccessRequester) bool {
	return false
}

func (c *OpenIDConnectExplicitHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester goauth2.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne("authorization_code")
}
