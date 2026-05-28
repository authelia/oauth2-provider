// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/url"
	"strings"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
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
		oauth2.ResourceStrategyProvider
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

func (c *AuthorizeExplicitGrantHandler) GetRedirectSecureChecker(ctx context.Context) (checker func(context.Context, *url.URL) bool) {
	if checker = c.Config.GetRedirectSecureChecker(ctx); checker != nil {
		return checker
	}

	return oauth2.IsRedirectURISecure
}

func (c *AuthorizeExplicitGrantHandler) HandleAuthorizeEndpointRequest(ctx context.Context, request oauth2.AuthorizeRequester, response oauth2.AuthorizeResponder) error {
	// This let's us define multiple response types, for example open id connect's id_token
	if !request.GetResponseTypes().ExactOne(consts.ResponseTypeAuthorizationCodeFlow) {
		return nil
	}

	request.SetDefaultResponseMode(oauth2.ResponseModeQuery)

	client := request.GetClient()
	strategy := oauth2.GetScopeStrategy(ctx, c.Config, client)

	if client.IsPublic() && !c.GetRedirectSecureChecker(ctx)(ctx, request.GetRedirectURI()) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Redirect URL is using an insecure protocol, http is only allowed for confidential clients or hosts with suffix 'localhost', for example: http://myapp.localhost/."))
	}

	for _, scope := range request.GetRequestedScopes() {
		if !strategy(client.GetScopes(), scope) {
			return errorsx.WithStack(oauth2.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
	}

	if err := oauth2.GetAudienceStrategy(ctx, c.Config, client)(client.GetAudience(), request.GetRequestedAudience()); err != nil {
		return err
	}

	if err := oauth2.GetResourceStrategy(ctx, c.Config, client)(client.GetAudience(), request.GetRequestedResource()); err != nil {
		return err
	}

	return c.IssueAuthorizeCode(ctx, request, response)
}

func (c *AuthorizeExplicitGrantHandler) IssueAuthorizeCode(ctx context.Context, request oauth2.AuthorizeRequester, response oauth2.AuthorizeResponder) (err error) {
	code, signature, err := c.AuthorizeCodeStrategy.GenerateAuthorizeCode(ctx, request)
	if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	request.GetSession().SetExpiresAt(oauth2.AuthorizeCode, time.Now().UTC().Add(c.Config.GetAuthorizeCodeLifespan(ctx)))

	if err = c.CoreStorage.CreateAuthorizeCodeSession(ctx, signature, request.Sanitize(c.GetSanitationWhiteList(ctx))); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	response.AddParameter(consts.FormParameterAuthorizationCode, code)
	response.AddParameter(consts.FormParameterState, request.GetState())

	if !c.Config.GetOmitRedirectScopeParam(ctx) {
		response.AddParameter(consts.FormParameterScope, strings.Join(request.GetGrantedScopes(), " "))
	}

	request.SetResponseTypeHandled(consts.ResponseTypeAuthorizationCodeFlow)

	return nil
}

func (c *AuthorizeExplicitGrantHandler) GetSanitationWhiteList(ctx context.Context) []string {
	if allowedList := c.Config.GetSanitationWhiteList(ctx); len(allowedList) > 0 {
		return allowedList
	}

	return []string{consts.FormParameterScope, consts.FormParameterRedirectURI}
}
