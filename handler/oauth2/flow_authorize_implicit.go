// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/authelia/goauth2"
	"github.com/authelia/goauth2/internal/errorsx"
)

var _ goauth2.AuthorizeEndpointHandler = (*AuthorizeImplicitGrantTypeHandler)(nil)

// AuthorizeImplicitGrantTypeHandler is a response handler for the Authorize Code grant using the implicit grant type
// as defined in https://tools.ietf.org/html/rfc6749#section-4.2
type AuthorizeImplicitGrantTypeHandler struct {
	AccessTokenStrategy AccessTokenStrategy
	// AccessTokenStorage is used to persist session data across requests.
	AccessTokenStorage AccessTokenStorage

	Config interface {
		goauth2.AccessTokenLifespanProvider
		goauth2.ScopeStrategyProvider
		goauth2.AudienceStrategyProvider
	}
}

func (c *AuthorizeImplicitGrantTypeHandler) HandleAuthorizeEndpointRequest(ctx context.Context, ar goauth2.AuthorizeRequester, resp goauth2.AuthorizeResponder) error {
	// This let's us define multiple response types, for example open id connect's id_token
	if !ar.GetResponseTypes().ExactOne("token") {
		return nil
	}

	ar.SetDefaultResponseMode(goauth2.ResponseModeFragment)

	// Disabled because this is already handled at the authorize_request_handler
	// if !ar.GetClient().GetResponseTypes().Has("token") {
	// 	 return errorsx.WithStack(goauth2.ErrInvalidGrant.WithDebug("The client is not allowed to use response type token"))
	// }

	if !ar.GetClient().GetGrantTypes().Has("implicit") {
		return errorsx.WithStack(goauth2.ErrInvalidGrant.WithHint("The OAuth 2.0 Client is not allowed to use the authorization grant 'implicit'."))
	}

	client := ar.GetClient()
	for _, scope := range ar.GetRequestedScopes() {
		if !c.Config.GetScopeStrategy(ctx)(client.GetScopes(), scope) {
			return errorsx.WithStack(goauth2.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
	}

	if err := c.Config.GetAudienceStrategy(ctx)(client.GetAudience(), ar.GetRequestedAudience()); err != nil {
		return err
	}

	// there is no need to check for https, because implicit flow does not require https
	// https://tools.ietf.org/html/rfc6819#section-4.4.2

	return c.IssueImplicitAccessToken(ctx, ar, resp)
}

func (c *AuthorizeImplicitGrantTypeHandler) IssueImplicitAccessToken(ctx context.Context, ar goauth2.AuthorizeRequester, resp goauth2.AuthorizeResponder) error {
	// Only override expiry if none is set.
	atLifespan := goauth2.GetEffectiveLifespan(ar.GetClient(), goauth2.GrantTypeImplicit, goauth2.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	if ar.GetSession().GetExpiresAt(goauth2.AccessToken).IsZero() {
		ar.GetSession().SetExpiresAt(goauth2.AccessToken, time.Now().UTC().Add(atLifespan).Round(time.Second))
	}

	// Generate the code
	token, signature, err := c.AccessTokenStrategy.GenerateAccessToken(ctx, ar)
	if err != nil {
		return errorsx.WithStack(goauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	if err := c.AccessTokenStorage.CreateAccessTokenSession(ctx, signature, ar.Sanitize([]string{})); err != nil {
		return errorsx.WithStack(goauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}
	resp.AddParameter("access_token", token)
	resp.AddParameter("expires_in", strconv.FormatInt(int64(getExpiresIn(ar, goauth2.AccessToken, atLifespan, time.Now().UTC())/time.Second), 10))
	resp.AddParameter("token_type", "bearer")
	resp.AddParameter("state", ar.GetState())
	resp.AddParameter("scope", strings.Join(ar.GetGrantedScopes(), " "))

	ar.SetResponseTypeHandled("token")

	return nil
}
