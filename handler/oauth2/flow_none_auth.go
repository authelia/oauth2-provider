// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/url"
	"strings"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// NoneResponseTypeHandler is a response handler for when the None response type is requested
// as defined in https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#none
type NoneResponseTypeHandler struct {
	Config interface {
		oauth2.ScopeStrategyProvider
		oauth2.AudienceStrategyProvider
		oauth2.ResourceStrategyProvider
		oauth2.RedirectSecureCheckerProvider
		oauth2.OmitRedirectScopeParamProvider
	}
}

var (
	_ oauth2.AuthorizeEndpointHandler = (*NoneResponseTypeHandler)(nil)
)

func (c *NoneResponseTypeHandler) HandleAuthorizeEndpointRequest(ctx context.Context, request oauth2.AuthorizeRequester, response oauth2.AuthorizeResponder) (err error) {
	if !request.GetResponseTypes().ExactOne(consts.ResponseTypeNone) {
		return nil
	}

	request.SetDefaultResponseMode(oauth2.ResponseModeQuery)

	if !c.GetRedirectSecureChecker(ctx)(ctx, request.GetRedirectURI()) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Redirect URL is using an insecure protocol, http is only allowed for hosts with suffix 'localhost', for example: http://myapp.localhost/."))
	}

	client := request.GetClient()
	strategy := oauth2.GetScopeStrategy(ctx, c.Config, client)

	for _, scope := range request.GetRequestedScopes() {
		if !strategy(client.GetScopes(), scope) {
			return errorsx.WithStack(oauth2.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
	}

	if err = oauth2.GetAudienceStrategy(ctx, c.Config, client)(client.GetAudience(), request.GetRequestedAudience()); err != nil {
		return err
	}

	if err = oauth2.GetResourceStrategy(ctx, c.Config, client)(client.GetAudience(), request.GetRequestedResource()); err != nil {
		return err
	}

	response.AddParameter(consts.FormParameterState, request.GetState())

	if !c.Config.GetOmitRedirectScopeParam(ctx) {
		response.AddParameter(consts.FormParameterScope, strings.Join(request.GetGrantedScopes(), " "))
	}

	request.SetResponseTypeHandled(consts.ResponseTypeNone)

	return nil
}

func (c *NoneResponseTypeHandler) GetRedirectSecureChecker(ctx context.Context) func(context.Context, *url.URL) bool {
	if c.Config.GetRedirectSecureChecker(ctx) == nil {
		return oauth2.IsRedirectURISecure
	}

	return c.Config.GetRedirectSecureChecker(ctx)
}
