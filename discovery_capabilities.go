// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"slices"
	"strings"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

// SupportedResponseTypes returns the sorted union of the response types reported by the registered authorize endpoint
// handlers, or nil when none report any.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
func SupportedResponseTypes(ctx context.Context, config Configurator) []string {
	return sortedUnique(capabilities(config.GetAuthorizeEndpointHandlers(ctx), func(h AuthorizeEndpointHandler) []string {
		return h.ResponseTypesSupported(ctx)
	}))
}

// SupportedGrantTypes returns the sorted union of the grant types reported by the registered handlers, or nil when none
// report any.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
func SupportedGrantTypes(ctx context.Context, config Configurator) []string {
	return sortedUnique(slices.Concat(
		capabilities(config.GetAuthorizeEndpointHandlers(ctx), func(h AuthorizeEndpointHandler) []string {
			return h.GrantTypesSupported(ctx)
		}),
		capabilities(config.GetTokenEndpointHandlers(ctx), func(h TokenEndpointHandler) []string {
			return h.GrantTypesSupported(ctx)
		}),
	))
}

// SupportedCodeChallengeMethods returns the sorted union of the code challenge methods reported by the registered
// handlers, or nil when none report any.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
func SupportedCodeChallengeMethods(ctx context.Context, config Configurator) []string {
	return sortedUnique(slices.Concat(
		capabilities(config.GetAuthorizeEndpointHandlers(ctx), func(h AuthorizeEndpointHandler) []string {
			return h.CodeChallengeMethodsSupported(ctx)
		}),
		capabilities(config.GetTokenEndpointHandlers(ctx), func(h TokenEndpointHandler) []string {
			return h.CodeChallengeMethodsSupported(ctx)
		}),
	))
}

// SupportedRFC8693TokenTypes returns the sorted union of the RFC 8693 token types reported by the registered token
// endpoint handlers, or nil when none report any.
//
// See: https://datatracker.ietf.org/doc/html/rfc8693#section-3
func SupportedRFC8693TokenTypes(ctx context.Context, config Configurator) []string {
	return sortedUnique(capabilities(config.GetTokenEndpointHandlers(ctx), func(h TokenEndpointHandler) []string {
		return h.RFC8693TokenTypesSupported(ctx)
	}))
}

// SupportedPromptValues returns the configured 'prompt' values, or 'login', 'none', 'consent' and 'select_account'
// when none are configured.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
// See: https://openid.net/specs/openid-connect-prompt-create-1_0.html#section-4
func SupportedPromptValues(ctx context.Context, config AllowedPromptsProvider) []string {
	if prompts := config.GetAllowedPrompts(ctx); len(prompts) != 0 {
		return prompts
	}

	return []string{consts.PromptTypeLogin, consts.PromptTypeNone, consts.PromptTypeConsent, consts.PromptTypeSelectAccount}
}

// SupportedIDTokenSigningAlgValues returns the sorted union of the ID Token signing algorithms reported by the registered
// handlers. When no handler reports any it falls back to the algorithms of the JWTStrategy, or nil when it has none.
//
// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
func SupportedIDTokenSigningAlgValues(ctx context.Context, config Configurator) []string {
	if algs := sortedUnique(slices.Concat(
		capabilities(config.GetAuthorizeEndpointHandlers(ctx), func(h AuthorizeEndpointHandler) []string {
			return h.IDTokenSigningAlgValuesSupported(ctx)
		}),
		capabilities(config.GetTokenEndpointHandlers(ctx), func(h TokenEndpointHandler) []string {
			return h.IDTokenSigningAlgValuesSupported(ctx)
		}),
	)); len(algs) != 0 {
		return algs
	}

	if strategy := config.GetJWTStrategy(ctx); strategy != nil {
		return sortedUnique(strategy.SigningAlgValues(ctx))
	}

	return nil
}

// SupportedResponseModes returns the sorted union of the response modes accepted by the registered response mode
// handlers, excluding the implicit default mode, or nil when there are none.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
func SupportedResponseModes(ctx context.Context, config Configurator) (modes []string) {
	for _, h := range config.GetResponseModeHandlers(ctx) {
		for _, mode := range h.ResponseModesSupported(ctx) {
			if mode == ResponseModeDefault {
				continue
			}

			modes = append(modes, string(mode))
		}
	}

	return sortedUnique(modes)
}

func capabilities[H any](handlers []H, get func(h H) []string) (values []string) {
	for _, h := range handlers {
		values = append(values, get(h)...)
	}

	return values
}

// ClientAuthEndpoint identifies an endpoint which authenticates clients. Its values are the EndpointClientAuthStrategy
// names.
type ClientAuthEndpoint string

const (
	ClientAuthEndpointToken         ClientAuthEndpoint = "token"
	ClientAuthEndpointRevocation    ClientAuthEndpoint = "revocation"
	ClientAuthEndpointIntrospection ClientAuthEndpoint = "introspection"
)

// SupportedTokenEndpointAuthMethods returns the configured token endpoint client authentication methods, otherwise the
// methods reported by the ClientAuthenticationStrategy.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
func SupportedTokenEndpointAuthMethods(ctx context.Context, config Configurator) []string {
	return SupportedEndpointAuthMethods(ctx, config, ClientAuthEndpointToken)
}

// SupportedEndpointAuthMethods returns the client authentication methods the endpoint accepts: the configured methods
// which the ClientAuthenticationStrategy supports, otherwise every method it supports. A configured access token type
// is kept for the introspection endpoint, the only endpoint whose list may hold one.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
func SupportedEndpointAuthMethods(ctx context.Context, config Configurator, endpoint ClientAuthEndpoint) []string {
	strategy := config.GetClientAuthenticationStrategy(ctx)
	if strategy == nil {
		strategy = &DefaultClientAuthenticationStrategy{Config: config}
	}

	supported := strategy.AuthMethodsSupported(ctx)

	configured := configuredEndpointAuthMethods(ctx, config, endpoint)
	if len(configured) == 0 {
		return supported
	}

	return slices.DeleteFunc(slices.Clone(configured), func(method string) bool {
		return !slices.Contains(supported, method) && (endpoint != ClientAuthEndpointIntrospection || !IsAccessTokenTypeAuthMethod(method))
	})
}

// unsupportedEndpointAuthMethods returns the configured methods of the endpoint which SupportedEndpointAuthMethods
// drops, as the ClientAuthenticationStrategy cannot authenticate a client with them.
func unsupportedEndpointAuthMethods(ctx context.Context, config Configurator, endpoint ClientAuthEndpoint) (methods []string) {
	supported := SupportedEndpointAuthMethods(ctx, config, endpoint)

	for _, method := range configuredEndpointAuthMethods(ctx, config, endpoint) {
		if !slices.Contains(supported, method) {
			methods = append(methods, method)
		}
	}

	return methods
}

// IsAccessTokenTypeAuthMethod reports whether an endpoint authentication method value is an access token type, such as
// 'Bearer' or 'DPoP', rather than a client authentication method. Only the introspection endpoint list may hold one.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-7.2
func IsAccessTokenTypeAuthMethod(method string) bool {
	return method == consts.AuthSchemeBearer || method == consts.AuthSchemeDPoP
}

// EndpointAuthSigningAlgValuesConfig is the configuration SupportedEndpointAuthSigningAlgValues reads.
type EndpointAuthSigningAlgValuesConfig interface {
	ClientAssertionAlgorithmsProvider
	ClientAuthMethodsProvider
}

// SupportedEndpointAuthSigningAlgValues returns the JWS algorithms the endpoint accepts for a client assertion: the
// algorithms configured for the revocation or introspection endpoint, otherwise the client assertion algorithms.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
func SupportedEndpointAuthSigningAlgValues(ctx context.Context, config EndpointAuthSigningAlgValuesConfig, endpoint ClientAuthEndpoint) []string {
	if algs := configuredEndpointAuthSigningAlgValues(ctx, config, endpoint); len(algs) != 0 {
		return algs
	}

	return config.GetClientAssertionSigningAlgValues(ctx)
}

func configuredEndpointAuthMethods(ctx context.Context, config ClientAuthMethodsProvider, endpoint ClientAuthEndpoint) []string {
	switch endpoint {
	case ClientAuthEndpointToken:
		return config.GetTokenEndpointAuthMethods(ctx)
	case ClientAuthEndpointRevocation:
		return config.GetRevocationEndpointAuthMethods(ctx)
	case ClientAuthEndpointIntrospection:
		return config.GetIntrospectionEndpointAuthMethods(ctx)
	default:
		return nil
	}
}

func configuredEndpointAuthSigningAlgValues(ctx context.Context, config ClientAuthMethodsProvider, endpoint ClientAuthEndpoint) []string {
	switch endpoint {
	case ClientAuthEndpointRevocation:
		return config.GetRevocationEndpointAuthSigningAlgValues(ctx)
	case ClientAuthEndpointIntrospection:
		return config.GetIntrospectionEndpointAuthSigningAlgValues(ctx)
	default:
		return nil
	}
}

type openIDConnectMarker interface {
	IsOpenIDConnectHandler()
}

type openIDConnectKeyBindingMarker interface {
	IsOpenIDConnectKeyBindingHandler()
}

type verifiableCredentialsMarker interface {
	IsVerifiableCredentialsHandler()
}

// IsOpenIDConnectRegistered returns true when the response types include an 'id_token' type or an OpenID Connect
// authorization flow handler is registered.
//
// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
func IsOpenIDConnectRegistered(ctx context.Context, config Configurator) bool {
	return isOpenIDConnectRegistered(ctx, config, SupportedResponseTypes(ctx, config))
}

func isOpenIDConnectRegistered(ctx context.Context, config Configurator, responseTypes []string) bool {
	for _, rt := range responseTypes {
		if containsField(rt, consts.ResponseTypeImplicitFlowIDToken) {
			return true
		}
	}

	return anyHandler(ctx, config, func(h any) bool {
		_, ok := h.(openIDConnectMarker)

		return ok
	})
}

// SupportedScopes returns the sorted union of the configured scopes and the scopes implied by the registered handlers
// and configuration.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
func SupportedScopes(ctx context.Context, config Configurator) []string {
	return supportedScopes(ctx, config, newDiscoveryCapabilities(ctx, config))
}

func supportedScopes(ctx context.Context, config Configurator, capabilities *discoveryCapabilities) []string {
	scopes := append([]string(nil), config.GetScopesSupported(ctx)...)

	if capabilities.openIDConnect {
		scopes = append(scopes, consts.ScopeOpenID)
	}

	for _, gt := range capabilities.grantTypes {
		if gt == consts.GrantTypeRefreshToken {
			scopes = append(scopes, config.GetRefreshTokenScopes(ctx)...)

			break
		}
	}

	if config.GetOIDCKeyBindingEnabled(ctx) && config.GetDPoPEnabled(ctx) && anyHandler(ctx, config, func(h any) bool {
		_, ok := h.(openIDConnectKeyBindingMarker)

		return ok
	}) {
		scopes = append(scopes, consts.ScopeBoundKey)
	}

	if anyHandler(ctx, config, func(h any) bool {
		_, ok := h.(verifiableCredentialsMarker)

		return ok
	}) {
		scopes = append(scopes, consts.ScopeUserinfoCredentialDraft00)
	}

	// See: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html#section-2.7.3
	if config.GetSSFConfig(ctx) != nil {
		scopes = append(scopes, consts.ScopeSSFRead, consts.ScopeSSFManage)
	}

	return sortedUnique(scopes)
}

// SupportedClaims returns the sorted union of the configured claims and, when OpenID Connect is registered, the claims
// the server always issues.
//
// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
func SupportedClaims(ctx context.Context, config Configurator) []string {
	return supportedClaims(ctx, config, IsOpenIDConnectRegistered(ctx, config))
}

func supportedClaims(ctx context.Context, config Configurator, openIDConnect bool) []string {
	claims := append([]string(nil), config.GetClaimsSupported(ctx)...)

	if openIDConnect {
		claims = append(claims,
			consts.ClaimIssuer, consts.ClaimSubject, consts.ClaimAudience, consts.ClaimExpirationTime,
			consts.ClaimIssuedAt, consts.ClaimAuthenticationTime, consts.ClaimNonce,
			consts.ClaimAuthenticationContextClassReference, consts.ClaimAuthenticationMethodsReference,
			consts.ClaimAuthorizedParty, consts.ClaimAccessTokenHash, consts.ClaimCodeHash, consts.ClaimSessionID,
		)
	}

	return sortedUnique(claims)
}

// discoveryCapabilities holds the handler-derived values several metadata members depend on, so one build walks the
// handler lists for them once.
type discoveryCapabilities struct {
	responseTypes []string
	grantTypes    []string
	openIDConnect bool
}

func newDiscoveryCapabilities(ctx context.Context, config Configurator) *discoveryCapabilities {
	responseTypes := SupportedResponseTypes(ctx, config)

	return &discoveryCapabilities{
		responseTypes: responseTypes,
		grantTypes:    SupportedGrantTypes(ctx, config),
		openIDConnect: isOpenIDConnectRegistered(ctx, config, responseTypes),
	}
}

func anyHandler(ctx context.Context, config Configurator, match func(h any) bool) bool {
	for _, h := range config.GetAuthorizeEndpointHandlers(ctx) {
		if match(h) {
			return true
		}
	}

	for _, h := range config.GetTokenEndpointHandlers(ctx) {
		if match(h) {
			return true
		}
	}

	for _, h := range config.GetAuthorizeEndpointBindingHandlers(ctx) {
		if match(h) {
			return true
		}
	}

	for _, h := range config.GetTokenEndpointBindingHandlers(ctx) {
		if match(h) {
			return true
		}
	}

	for _, h := range config.GetRFC8628DeviceAuthorizeEndpointBindingHandlers(ctx) {
		if match(h) {
			return true
		}
	}

	return false
}

func containsField(value, field string) bool {
	return slices.Contains(strings.Fields(value), field)
}

func sortedUnique(values []string) []string {
	return slices.Compact(slices.Sorted(slices.Values(values)))
}

// SupportedRequestObjectSigningAlgValues returns the configured Request Object signing algorithms, excluding 'none'
// when signed Request Objects are required.
//
// See: https://datatracker.ietf.org/doc/html/rfc9101#section-10.5
func SupportedRequestObjectSigningAlgValues(ctx context.Context, config Configurator) []string {
	algs := config.GetRequestObjectSigningAlgValues(ctx)
	if config.GetRequireSignedRequestObject(ctx) {
		return withoutNone(algs)
	}

	return algs
}

// SupportedIDTokenSignedResponseAlgValues returns the 'id_token_signed_response_alg' values the server can produce:
// SupportedIDTokenSigningAlgValues plus the client secret HMAC algorithms, or nil when the ID Token issuer has no
// signing algorithms.
//
// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
func SupportedIDTokenSignedResponseAlgValues(ctx context.Context, config Configurator) []string {
	algs := SupportedIDTokenSigningAlgValues(ctx, config)
	if len(algs) == 0 {
		return nil
	}

	return sortedUnique(clientSecretSigningAlgValues(algs))
}

// SupportedUserinfoSignedResponseAlgValues returns the 'userinfo_signed_response_alg' values the server can produce:
// the JWTStrategy algorithms plus the client secret HMAC algorithms and 'none', or only 'none' when there is no
// JWTStrategy.
//
// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
func SupportedUserinfoSignedResponseAlgValues(ctx context.Context, config Configurator) []string {
	return strategySignedResponseAlgValues(ctx, config.GetJWTStrategy(ctx), true)
}

// SupportedAuthorizationSignedResponseAlgValues returns the 'authorization_signed_response_alg' values the server can
// produce: the JARM strategy algorithms plus the client secret HMAC algorithms, or nil when there is no JARM strategy.
//
// See: https://openid.net/specs/oauth-v2-jarm.html#section-4
func SupportedAuthorizationSignedResponseAlgValues(ctx context.Context, config Configurator) []string {
	return strategySignedResponseAlgValues(ctx, config.GetJWTSecuredAuthorizeResponseModeStrategy(ctx), false)
}

// SupportedIntrospectionSignedResponseAlgValues returns the 'introspection_signed_response_alg' values the server can
// produce: the JWT introspection response strategy algorithms plus the client secret HMAC algorithms, or nil when there
// is no such strategy. 'none' is excluded because the introspection response JWT is cryptographically secured.
//
// See: https://datatracker.ietf.org/doc/html/rfc9701#section-5
// See: https://datatracker.ietf.org/doc/html/rfc9701#section-7
func SupportedIntrospectionSignedResponseAlgValues(ctx context.Context, config Configurator) []string {
	return strategySignedResponseAlgValues(ctx, config.GetIntrospectionJWTResponseStrategy(ctx), false)
}

// SupportedAccessTokenSignedResponseAlgValues returns the 'access_token_signed_response_alg' values the server can
// produce: the JWTStrategy algorithms plus the client secret HMAC algorithms, or nil when there is no JWTStrategy.
//
// See: https://datatracker.ietf.org/doc/html/rfc9068#section-2.1
func SupportedAccessTokenSignedResponseAlgValues(ctx context.Context, config Configurator) []string {
	return strategySignedResponseAlgValues(ctx, config.GetJWTStrategy(ctx), false)
}

func strategySignedResponseAlgValues(ctx context.Context, strategy jwt.Strategy, none bool) []string {
	var algs []string

	if strategy != nil {
		algs = clientSecretSigningAlgValues(strategy.SigningAlgValues(ctx))
	}

	if none {
		algs = append(algs, consts.JSONWebTokenAlgNone)
	}

	return sortedUnique(algs)
}
