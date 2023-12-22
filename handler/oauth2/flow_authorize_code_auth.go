// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/url"
	"strings"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/errorsx"
)

// AuthorizeExplicitGrantHandler is a response handler for the Authorize Code grant using the explicit grant type
// as defined in https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
type AuthorizeExplicitGrantHandler struct {
	AccessTokenStrategy    AccessTokenStrategy
	RefreshTokenStrategy   RefreshTokenStrategy
	AuthorizeCodeStrategy  AuthorizeCodeStrategy
	CoreStorage            CoreStorage
	TokenRevocationStorage TokenRevocationStorage
	Config                 interface {
		oauth2.AuthorizeCodeLifespanProvider
		oauth2.AccessTokenLifespanProvider
		oauth2.RefreshTokenLifespanProvider
		oauth2.ScopeStrategyProvider
		oauth2.AudienceStrategyProvider
		oauth2.RedirectSecureCheckerProvider
		oauth2.RefreshTokenScopesProvider
		oauth2.OmitRedirectScopeParamProvider
		oauth2.SanitationAllowedProvider
	}
}

var (
	_ oauth2.AuthorizeEndpointHandler = (*AuthorizeExplicitGrantHandler)(nil)
	_ oauth2.TokenEndpointHandler     = (*AuthorizeExplicitGrantHandler)(nil)
)

func (c *AuthorizeExplicitGrantHandler) secureChecker(ctx context.Context) func(context.Context, *url.URL) bool {
	if c.Config.GetRedirectSecureChecker(ctx) == nil {
		return oauth2.IsRedirectURISecure
	}
	return c.Config.GetRedirectSecureChecker(ctx)
}

func (c *AuthorizeExplicitGrantHandler) HandleAuthorizeEndpointRequest(ctx context.Context, requester oauth2.AuthorizeRequester, responder oauth2.AuthorizeResponder) error {
	// This let's us define multiple response types, for example open id connect's id_token
	if !requester.GetResponseTypes().ExactOne(consts.ResponseTypeAuthorizationCodeFlow) {
		return nil
	}

	requester.SetDefaultResponseMode(oauth2.ResponseModeQuery)

	// Disabled because this is already handled at the authorize_request_handler
	// if !requester.GetClient().GetResponseTypes().Has("code") {
	// 	 return errorsx.WithStack(oauth2.ErrInvalidGrant)
	// }

	if !c.secureChecker(ctx)(ctx, requester.GetRedirectURI()) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Redirect URL is using an insecure protocol, http is only allowed for hosts with suffix 'localhost', for example: http://myapp.localhost/."))
	}

	client := requester.GetClient()
	for _, scope := range requester.GetRequestedScopes() {
		if !c.Config.GetScopeStrategy(ctx)(client.GetScopes(), scope) {
			return errorsx.WithStack(oauth2.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
	}

	if err := c.Config.GetAudienceStrategy(ctx)(client.GetAudience(), requester.GetRequestedAudience()); err != nil {
		return err
	}

	return c.IssueAuthorizeCode(ctx, requester, responder)
}

func (c *AuthorizeExplicitGrantHandler) IssueAuthorizeCode(ctx context.Context, requester oauth2.AuthorizeRequester, responder oauth2.AuthorizeResponder) error {
	code, signature, err := c.AuthorizeCodeStrategy.GenerateAuthorizeCode(ctx, requester)
	if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	requester.GetSession().SetExpiresAt(oauth2.AuthorizeCode, time.Now().UTC().Add(c.Config.GetAuthorizeCodeLifespan(ctx)))

	if err = c.CoreStorage.CreateAuthorizeCodeSession(ctx, signature, requester.Sanitize(c.GetSanitationWhiteList(ctx))); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	responder.AddParameter(consts.FormParameterAuthorizationCode, code)
	responder.AddParameter(consts.FormParameterState, requester.GetState())
	if !c.Config.GetOmitRedirectScopeParam(ctx) {
		responder.AddParameter(consts.FormParameterScope, strings.Join(requester.GetGrantedScopes(), " "))
	}

	requester.SetResponseTypeHandled(consts.ResponseTypeAuthorizationCodeFlow)

	return nil
}

func (c *AuthorizeExplicitGrantHandler) GetSanitationWhiteList(ctx context.Context) []string {
	if allowedList := c.Config.GetSanitationWhiteList(ctx); len(allowedList) > 0 {
		return allowedList
	}

	return []string{consts.FormParameterScope, consts.FormParameterRedirectURI}
}
