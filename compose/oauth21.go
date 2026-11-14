// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/handler/pkce"
	"authelia.com/provider/oauth2/handler/rfc7591"
	"authelia.com/provider/oauth2/internal/consts"
)

const (
	oauth21SectionCommunicationSecurity = "1.5"
	oauth21SectionClientAuthentication  = "2.4"
	oauth21SectionClientSecret          = "2.4.1"
	oauth21SectionAuthorizationRequest  = "4.1.1"
	oauth21SectionAuthorizationResponse = "4.1.2"
	oauth21SectionAuthorizationError    = "4.1.2.1"
	oauth21SectionPKCEPlain             = "7.5.2"
	oauth21SectionCredentialsGuessing   = "7.7"
	oauth21SectionBrowserRefreshTokens  = "9.3.2"
	oauth21SectionDifferences           = "10"
	oauth21SectionImplicitGrant         = "10.1"

	oauth21MaximumAuthorizeCodeLifespan   = 10 * time.Minute
	oauth21DefaultRefreshTokenMaxLifespan = 30 * 24 * time.Hour
	oauth21MinimumTokenEntropy            = 22
)

// ApplyOAuth21Profile sets the options of config which The OAuth 2.1 Authorization Framework requires of an
// authorization server: PKCE enforced for every client with S256 only, the redirect URI security check applied to
// public clients, the RFC 9207 'iss' parameter, the issuer as the sole client assertion audience, 'client_secret_post'
// wherever another client secret method is accepted at the token endpoint, an authorization code lifetime of at most 10
// minutes, and a TokenEntropy of at least 22 alphanumeric characters for generated client secrets. A value already
// within the profile is kept.
//
// It also sets RefreshTokenMaximumLifespan when it is unset or negative, so a rotated refresh token never outlives the
// first refresh token of its grant, as Section 9.3.2 requires for browser-based applications, which the authorization
// server cannot tell apart from other public clients. The maximum is RefreshTokenLifespan, the lifetime of that first
// refresh token, or its 30 day default when RefreshTokenLifespan is unset or never expires. The sessions must then
// implement oauth2.ExpiryDeadlineSetterSession, as the default sessions do.
//
// It does not set Issuer or register or remove handlers, so ValidateOAuth21Profile must still be called once the
// provider is composed.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-17
func ApplyOAuth21Profile(config *oauth2.Config) {
	config.EnforcePKCE = true
	config.AllowPublicClientsWithoutPKCE = false
	config.EnablePKCEPlainChallengeMethod = false
	config.AllowInsecureRedirectURIForPublicClients = false
	config.DisableAuthorizationServerIdentification = false
	config.DisableClientAssertionIssuerAudience = false

	if config.AuthorizeCodeLifespan > oauth21MaximumAuthorizeCodeLifespan {
		config.AuthorizeCodeLifespan = oauth21MaximumAuthorizeCodeLifespan
	}

	if config.TokenEntropy < oauth21MinimumTokenEntropy {
		config.TokenEntropy = 0
	}

	if config.RefreshTokenMaximumLifespan <= 0 {
		if config.RefreshTokenLifespan > 0 {
			config.RefreshTokenMaximumLifespan = config.RefreshTokenLifespan
		} else {
			config.RefreshTokenMaximumLifespan = oauth21DefaultRefreshTokenMaxLifespan
		}
	}

	if oauth21AcceptsClientSecretWithoutPost(config.TokenEndpointAuthMethods) {
		config.TokenEndpointAuthMethods = append(config.TokenEndpointAuthMethods, consts.ClientAuthMethodClientSecretPost)
	}
}

// ValidateOAuth21Profile returns an error joining every way the configuration and the handlers registered with it fail
// the authorization server requirements of The OAuth 2.1 Authorization Framework which the configuration determines,
// or nil when it meets them. Call it once the provider is composed. Of the authorize endpoint handlers it recognizes
// only those of this library which can issue an access token in the authorization response, being the implicit grant
// and the OpenID Connect implicit and hybrid flows, not a custom handler doing so. PKCE support is required when the
// authorization code grant handler is registered, the refresh token maximum lifespan when the refresh token grant
// handler is, and the TokenEntropy of generated client secrets when the client registration handler is.
//
// It does not check the clients, including their redirect URI comparison strategy, which must be exact string
// matching, their own lifespans and PKCE and refresh token policies, and whether they are browser-based applications.
// Nor does it check a custom RedirectSecureChecker, bearer access tokens in the query string, or the 'redirect_uri'
// token request parameter of OAuth 2.0 clients.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-17
func ValidateOAuth21Profile(ctx context.Context, config oauth2.Configurator) (err error) {
	v := &fapi2Violations{document: "OAuth 2.1"}

	v.oauth21Grants(ctx, config)
	v.oauth21ClientAuthentication(ctx, config)
	v.oauth21AuthorizationCode(ctx, config)
	v.oauth21RefreshTokens(ctx, config)

	return errors.Join(v.errs...)
}

func (v *fapi2Violations) oauth21Grants(ctx context.Context, config oauth2.Configurator) {
	for _, h := range config.GetTokenEndpointHandlers(ctx) {
		if _, ok := h.(*hoauth2.ResourceOwnerPasswordCredentialsGrantHandler); ok { //nolint:staticcheck
			v.fail(oauth21SectionDifferences, "the resource owner password credentials grant handler must not be registered, as RFC 9700 Section 2.4 forbids the grant")
		}
	}

	for _, h := range config.GetAuthorizeEndpointHandlers(ctx) {
		switch h.(type) {
		case *hoauth2.AuthorizeImplicitGrantTypeHandler, *openid.OpenIDConnectImplicitHandler, *openid.OpenIDConnectHybridHandler:
			v.fail(oauth21SectionImplicitGrant, "access tokens must not be issued in the authorization response, but the '%T' authorize endpoint handler is registered", h)
		}
	}
}

func (v *fapi2Violations) oauth21ClientAuthentication(ctx context.Context, config oauth2.Configurator) {
	if methods := oauth2.SupportedEndpointAuthMethods(ctx, config, oauth2.ClientAuthEndpointToken); oauth21AcceptsClientSecretWithoutPost(methods) {
		v.fail(oauth21SectionClientSecret, "the token endpoint accepts the client authentication methods '%s', but not '%s'", strings.Join(methods, "', '"), consts.ClientAuthMethodClientSecretPost)
	}

	if config.GetDisableClientAssertionIssuerAudience(ctx) {
		v.fail(oauth21SectionClientAuthentication, "the issuer must be the sole client assertion audience, but DisableClientAssertionIssuerAudience is set")
	}

	if !fapi2Registered[*rfc7591.ClientRegistrationHandler](config.GetRFC7591ClientRegistrationEndpointHandlers(ctx)) {
		return
	}

	if entropy := config.GetTokenEntropy(ctx); entropy < oauth21MinimumTokenEntropy {
		v.fail(oauth21SectionCredentialsGuessing, "the client secrets the client registration handler generates must have a guessing probability of at most 2^-128, which needs a TokenEntropy of at least %d, but it is %d", oauth21MinimumTokenEntropy, entropy)
	}
}

func (v *fapi2Violations) oauth21AuthorizationCode(ctx context.Context, config oauth2.Configurator) {
	if fapi2Registered[*hoauth2.AuthorizeExplicitGrantHandler](config.GetAuthorizeEndpointHandlers(ctx)) && !fapi2Registered[*pkce.Handler](config.GetAuthorizeEndpointHandlers(ctx)) {
		v.fail(oauth21SectionAuthorizationRequest, "PKCE must be supported, but the PKCE handler is not registered")
	}

	if !config.GetEnforcePKCE(ctx) {
		v.fail(oauth21SectionAuthorizationRequest, "PKCE must be enforced, but EnforcePKCE is not set")
	}

	if config.GetAllowPublicClientsWithoutPKCE(ctx) {
		v.fail(oauth21SectionAuthorizationError, "requests from public clients without 'code_challenge' must be rejected, but AllowPublicClientsWithoutPKCE is set")
	}

	if config.GetEnablePKCEPlainChallengeMethod(ctx) {
		v.fail(oauth21SectionPKCEPlain, "the 'plain' code challenge method is forbidden, but EnablePKCEPlainChallengeMethod is set")
	}

	if config.GetAllowInsecureRedirectURIForPublicClients(ctx) {
		v.fail(oauth21SectionCommunicationSecurity, "redirect URIs other than loopback interface ones must use 'https', but AllowInsecureRedirectURIForPublicClients is set")
	}

	if lifespan := config.GetAuthorizeCodeLifespan(ctx); lifespan > oauth21MaximumAuthorizeCodeLifespan {
		v.fail(oauth21SectionAuthorizationResponse, "the authorization code lifetime must be at most %s, but is %s", oauth21MaximumAuthorizeCodeLifespan, lifespan)
	}

	if config.GetIssuer(ctx) == "" {
		v.fail(oauth21SectionAuthorizationResponse, "the 'iss' authorization response parameter must be returned, but Issuer is not set")
	}

	if !config.GetAuthorizationServerIdentificationEnabled(ctx) {
		v.fail(oauth21SectionAuthorizationResponse, "the 'iss' authorization response parameter must be returned, but DisableAuthorizationServerIdentification is set")
	}

	if p, ok := config.(oauth2.ResponseModeParameterHandlerProvider); !ok || !fapi2Registered[*oauth2.RFC9207ResponseModeParameterHandler](p.GetResponseModeParameterHandlers(ctx)) {
		v.fail(oauth21SectionAuthorizationResponse, "the 'iss' authorization response parameter must be returned, but the RFC 9207 response mode parameter handler is not registered")
	}
}

func (v *fapi2Violations) oauth21RefreshTokens(ctx context.Context, config oauth2.Configurator) {
	if !fapi2Registered[*hoauth2.RefreshTokenGrantHandler](config.GetTokenEndpointHandlers(ctx)) {
		return
	}

	if config.GetRefreshTokenMaximumLifespan(ctx) <= 0 {
		v.fail(oauth21SectionBrowserRefreshTokens, "rotated refresh tokens must not outlive the first refresh token of the grant, but RefreshTokenMaximumLifespan is not set")
	}
}

func oauth21AcceptsClientSecretWithoutPost(methods []string) bool {
	return !slices.Contains(methods, consts.ClientAuthMethodClientSecretPost) && slices.ContainsFunc(methods, func(method string) bool {
		return method == consts.ClientAuthMethodClientSecretBasic || method == consts.ClientAuthMethodClientSecretJWT
	})
}
