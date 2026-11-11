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
		oauth2.AllowInsecureRedirectURIForPublicClientsProvider
		oauth2.OmitRedirectScopeParamProvider
	}
}

// HandleAuthorizeEndpointRequest handles an authorize request whose 'response_type' is exactly 'none'. It rejects an
// insecure redirect URI, validates the requested scopes, audience and resources against the client, and adds the
// 'state' and, unless omitted by configuration, 'scope' parameters to the response. No code or token is issued.
func (c *NoneResponseTypeHandler) HandleAuthorizeEndpointRequest(ctx context.Context, request oauth2.AuthorizeRequester, response oauth2.AuthorizeResponder) (err error) {
	if !request.GetResponseTypes().ExactOne(consts.ResponseTypeNone) {
		return nil
	}

	request.SetDefaultResponseMode(oauth2.ResponseModeQuery)

	client := request.GetClient()

	if err = oauth2.ValidateRedirectURISecurity(ctx, c.Config, client, request.GetRedirectURI()); err != nil {
		return err
	}

	strategy := oauth2.GetScopeStrategy(ctx, c.Config, client)

	for _, scope := range request.GetRequestedScopes() {
		if !strategy(client.GetScopes(), scope) {
			return errorsx.WithStack(oauth2.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
	}

	if err = oauth2.GetAudienceStrategy(ctx, c.Config, client)(client.GetAudience(), request.GetRequestedAudience()); err != nil {
		return err
	}

	if err = oauth2.GetResourceStrategy(ctx, c.Config, client)(client.GetResource(), request.GetRequestedResource()); err != nil {
		return err
	}

	if state := request.GetState(); len(state) != 0 {
		response.AddParameter(consts.FormParameterState, state)
	}

	if !c.Config.GetOmitRedirectScopeParam(ctx) {
		response.AddParameter(consts.FormParameterScope, strings.Join(request.GetGrantedScopes(), " "))
	}

	request.SetResponseTypeHandled(consts.ResponseTypeNone)

	return nil
}

// GetRedirectSecureChecker returns the configured redirect URI security checker, or oauth2.IsRedirectURISecure when
// none is configured.
func (c *NoneResponseTypeHandler) GetRedirectSecureChecker(ctx context.Context) func(context.Context, *url.URL) (secure bool) {
	if c.Config.GetRedirectSecureChecker(ctx) == nil {
		return oauth2.IsRedirectURISecure
	}

	return c.Config.GetRedirectSecureChecker(ctx)
}

// ResponseTypesSupported returns the response types this handler serves.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
func (c *NoneResponseTypeHandler) ResponseTypesSupported(ctx context.Context) (types []string) {
	return []string{consts.ResponseTypeNone}
}

// GrantTypesSupported returns nil because the 'none' response type serves no grant.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
func (c *NoneResponseTypeHandler) GrantTypesSupported(ctx context.Context) (types []string) {
	return nil
}

// CodeChallengeMethodsSupported returns nil because the handler does not enforce PKCE.
//
// See: https://datatracker.ietf.org/doc/html/rfc7636#section-4.3
func (c *NoneResponseTypeHandler) CodeChallengeMethodsSupported(ctx context.Context) (methods []string) {
	return nil
}

// IDTokenSigningAlgValuesSupported returns nil because the handler does not issue ID Tokens.
//
// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
func (c *NoneResponseTypeHandler) IDTokenSigningAlgValuesSupported(ctx context.Context) (algs []string) {
	return nil
}

var (
	_ oauth2.AuthorizeEndpointHandler = (*NoneResponseTypeHandler)(nil)
)
