// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/url"
	"slices"
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
		oauth2.AllowInsecureRedirectURIForPublicClientsProvider
		oauth2.RefreshTokenScopesProvider
		oauth2.OmitRedirectScopeParamProvider
		oauth2.SanitationAllowedProvider
	}
}

// GetRedirectSecureChecker returns the configured redirect URI security checker, or oauth2.IsRedirectURISecure when
// none is configured.
func (c *AuthorizeExplicitGrantHandler) GetRedirectSecureChecker(ctx context.Context) (checker func(context.Context, *url.URL) (secure bool)) {
	if checker = c.Config.GetRedirectSecureChecker(ctx); checker != nil {
		return checker
	}

	return oauth2.IsRedirectURISecure
}

// HandleAuthorizeEndpointRequest handles an authorize request whose 'response_type' is exactly 'code'. It rejects an
// insecure redirect URI, validates the requested scopes, audience and resources against the client,
// and then issues the authorization code.
func (c *AuthorizeExplicitGrantHandler) HandleAuthorizeEndpointRequest(ctx context.Context, request oauth2.AuthorizeRequester, response oauth2.AuthorizeResponder) (err error) {
	// This let's us define multiple response types, for example open id connect's id_token
	if !request.GetResponseTypes().ExactOne(consts.ResponseTypeAuthorizationCodeFlow) {
		return nil
	}

	request.SetDefaultResponseMode(oauth2.ResponseModeQuery)

	client := request.GetClient()
	strategy := oauth2.GetScopeStrategy(ctx, c.Config, client)

	if err = oauth2.ValidateRedirectURISecurity(ctx, c.Config, client, request.GetRedirectURI()); err != nil {
		return err
	}

	for _, scope := range request.GetRequestedScopes() {
		if !strategy(client.GetScopes(), scope) {
			return errorsx.WithStack(oauth2.ErrInvalidScope.WithHint("The OAuth 2.0 Client is not allowed to request one or more of the values of the 'scope' parameter.").WithDebugf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
	}

	if err = oauth2.GetAudienceStrategy(ctx, c.Config, client)(client.GetAudience(), request.GetRequestedAudience()); err != nil {
		return err
	}

	if err = oauth2.GetResourceStrategy(ctx, c.Config, client)(client.GetResource(), request.GetRequestedResource()); err != nil {
		return err
	}

	return c.IssueAuthorizeCode(ctx, request, response)
}

// IssueAuthorizeCode generates an authorization code, persists the sanitized authorize request under its signature, and
// adds the 'code', 'state' and, unless omitted by configuration, 'scope' parameters to the response.
func (c *AuthorizeExplicitGrantHandler) IssueAuthorizeCode(ctx context.Context, request oauth2.AuthorizeRequester, response oauth2.AuthorizeResponder) (err error) {
	code, signature, err := c.AuthorizeCodeStrategy.GenerateAuthorizeCode(ctx, request)
	if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	request.GetSession().SetExpiresAt(oauth2.AuthorizeCode, time.Now().UTC().Add(oauth2.GetAuthorizeCodeLifespan(ctx, c.Config, request.GetClient())))

	if err = c.CoreStorage.CreateAuthorizeCodeSession(ctx, signature, request.Sanitize(c.GetAuthorizeCodeSessionParameters(ctx))); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	response.AddParameter(consts.FormParameterAuthorizationCode, code)
	if state := request.GetState(); len(state) != 0 {
		response.AddParameter(consts.FormParameterState, state)
	}

	if !c.Config.GetOmitRedirectScopeParam(ctx) {
		response.AddParameter(consts.FormParameterScope, strings.Join(request.GetGrantedScopes(), " "))
	}

	request.SetResponseTypeHandled(consts.ResponseTypeAuthorizationCodeFlow)

	return nil
}

// GetSanitationWhiteList returns the form parameters retained when the authorize request is sanitized for storage:
// 'scope' and 'redirect_uri', which the token endpoint always requires, followed by any configured parameters.
//
// See: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
func (c *AuthorizeExplicitGrantHandler) GetSanitationWhiteList(ctx context.Context) (whitelist []string) {
	whitelist = []string{consts.FormParameterScope, consts.FormParameterRedirectURI}

	for _, parameter := range c.Config.GetSanitationWhiteList(ctx) {
		if !slices.Contains(whitelist, parameter) {
			whitelist = append(whitelist, parameter)
		}
	}

	return whitelist
}

// GetAuthorizeCodeSessionParameters returns the form parameters retained when the authorize request is stored as the
// authorization code session: the sanitation whitelist, and the 'code_challenge' and 'code_challenge_method' when a
// registered handler verifies PKCE, so a replayed code only revokes the grant for the matching 'code_verifier'.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-7.5.3
func (c *AuthorizeExplicitGrantHandler) GetAuthorizeCodeSessionParameters(ctx context.Context) (parameters []string) {
	parameters = c.GetSanitationWhiteList(ctx)

	if c.isPKCEVerified(ctx) {
		return slices.Concat(parameters, pkceParameters)
	}

	return parameters
}

func (c *AuthorizeExplicitGrantHandler) isPKCEVerified(ctx context.Context) bool {
	config, ok := c.Config.(oauth2.Configurator)

	return ok && len(oauth2.SupportedCodeChallengeMethods(ctx, config)) != 0
}

// ResponseTypesSupported returns the response types this handler serves.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
func (c *AuthorizeExplicitGrantHandler) ResponseTypesSupported(ctx context.Context) (types []string) {
	return []string{consts.ResponseTypeAuthorizationCodeFlow}
}

// GrantTypesSupported returns the grant types this handler serves.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
func (c *AuthorizeExplicitGrantHandler) GrantTypesSupported(ctx context.Context) (types []string) {
	return []string{consts.GrantTypeAuthorizationCode}
}

// CodeChallengeMethodsSupported returns nil because the handler does not enforce PKCE.
//
// See: https://datatracker.ietf.org/doc/html/rfc7636#section-4.3
func (c *AuthorizeExplicitGrantHandler) CodeChallengeMethodsSupported(ctx context.Context) (methods []string) {
	return nil
}

// IDTokenSigningAlgValuesSupported returns nil because the handler does not issue ID Tokens.
//
// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
func (c *AuthorizeExplicitGrantHandler) IDTokenSigningAlgValuesSupported(ctx context.Context) (algs []string) {
	return nil
}

// RFC8693TokenTypesSupported returns nil because the handler does not issue RFC 8693 tokens.
//
// See: https://datatracker.ietf.org/doc/html/rfc8693#section-3
func (c *AuthorizeExplicitGrantHandler) RFC8693TokenTypesSupported(ctx context.Context) (types []string) {
	return nil
}

var (
	_ oauth2.AuthorizeEndpointHandler                 = (*AuthorizeExplicitGrantHandler)(nil)
	_ oauth2.TokenEndpointHandler                     = (*AuthorizeExplicitGrantHandler)(nil)
	_ oauth2.AuthorizationDetailsTokenEndpointHandler = (*AuthorizeExplicitGrantHandler)(nil)
)
