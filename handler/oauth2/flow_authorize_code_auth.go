// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/authelia/goauth2"
	"github.com/authelia/goauth2/internal/errorsx"
)

var (
	_ goauth2.AuthorizeEndpointHandler = (*AuthorizeExplicitGrantHandler)(nil)
	_ goauth2.TokenEndpointHandler     = (*AuthorizeExplicitGrantHandler)(nil)
)

// AuthorizeExplicitGrantHandler is a response handler for the Authorize Code grant using the explicit grant type
// as defined in https://tools.ietf.org/html/rfc6749#section-4.1
type AuthorizeExplicitGrantHandler struct {
	AccessTokenStrategy    AccessTokenStrategy
	RefreshTokenStrategy   RefreshTokenStrategy
	AuthorizeCodeStrategy  AuthorizeCodeStrategy
	CoreStorage            CoreStorage
	TokenRevocationStorage TokenRevocationStorage
	Config                 interface {
		goauth2.AuthorizeCodeLifespanProvider
		goauth2.AccessTokenLifespanProvider
		goauth2.RefreshTokenLifespanProvider
		goauth2.ScopeStrategyProvider
		goauth2.AudienceStrategyProvider
		goauth2.RedirectSecureCheckerProvider
		goauth2.RefreshTokenScopesProvider
		goauth2.OmitRedirectScopeParamProvider
		goauth2.SanitationAllowedProvider
	}
}

func (c *AuthorizeExplicitGrantHandler) secureChecker(ctx context.Context) func(context.Context, *url.URL) bool {
	if c.Config.GetRedirectSecureChecker(ctx) == nil {
		return goauth2.IsRedirectURISecure
	}
	return c.Config.GetRedirectSecureChecker(ctx)
}

func (c *AuthorizeExplicitGrantHandler) HandleAuthorizeEndpointRequest(ctx context.Context, ar goauth2.AuthorizeRequester, resp goauth2.AuthorizeResponder) error {
	// This let's us define multiple response types, for example open id connect's id_token
	if !ar.GetResponseTypes().ExactOne("code") {
		return nil
	}

	ar.SetDefaultResponseMode(goauth2.ResponseModeQuery)

	// Disabled because this is already handled at the authorize_request_handler
	// if !ar.GetClient().GetResponseTypes().Has("code") {
	// 	 return errorsx.WithStack(goauth2.ErrInvalidGrant)
	// }

	if !c.secureChecker(ctx)(ctx, ar.GetRedirectURI()) {
		return errorsx.WithStack(goauth2.ErrInvalidRequest.WithHint("Redirect URL is using an insecure protocol, http is only allowed for hosts with suffix 'localhost', for example: http://myapp.localhost/."))
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

	return c.IssueAuthorizeCode(ctx, ar, resp)
}

func (c *AuthorizeExplicitGrantHandler) IssueAuthorizeCode(ctx context.Context, ar goauth2.AuthorizeRequester, resp goauth2.AuthorizeResponder) error {
	code, signature, err := c.AuthorizeCodeStrategy.GenerateAuthorizeCode(ctx, ar)
	if err != nil {
		return errorsx.WithStack(goauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	ar.GetSession().SetExpiresAt(goauth2.AuthorizeCode, time.Now().UTC().Add(c.Config.GetAuthorizeCodeLifespan(ctx)))
	if err := c.CoreStorage.CreateAuthorizeCodeSession(ctx, signature, ar.Sanitize(c.GetSanitationWhiteList(ctx))); err != nil {
		return errorsx.WithStack(goauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	resp.AddParameter("code", code)
	resp.AddParameter("state", ar.GetState())
	if !c.Config.GetOmitRedirectScopeParam(ctx) {
		resp.AddParameter("scope", strings.Join(ar.GetGrantedScopes(), " "))
	}

	ar.SetResponseTypeHandled("code")
	return nil
}

func (c *AuthorizeExplicitGrantHandler) GetSanitationWhiteList(ctx context.Context) []string {
	if allowedList := c.Config.GetSanitationWhiteList(ctx); len(allowedList) > 0 {
		return allowedList
	}

	return []string{"code", "redirect_uri"}
}
