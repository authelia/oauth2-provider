// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"reflect"
)

const MinParameterEntropy = 8

// ResponseModeHandlers is a list of ResponseModeHandler.
type ResponseModeHandlers []ResponseModeHandler

// Append adds an ResponseModeHandler to this list. Ignores duplicates based on reflect.TypeOf.
func (a *ResponseModeHandlers) Append(h ResponseModeHandler) {
	for _, this := range *a {
		if reflect.TypeOf(this) == reflect.TypeOf(h) {
			return
		}
	}

	*a = append(*a, h)
}

// ResponseModeParameterHandlers is a list of ResponseModeParameterHandler.
type ResponseModeParameterHandlers []ResponseModeParameterHandler

// Append adds an ResponseModeParameterHandler to this list. Ignores duplicates based on reflect.TypeOf.
func (a *ResponseModeParameterHandlers) Append(h ResponseModeParameterHandler) {
	for _, this := range *a {
		if reflect.TypeOf(this) == reflect.TypeOf(h) {
			return
		}
	}

	*a = append(*a, h)
}

// AuthorizeEndpointHandlers is a list of AuthorizeEndpointHandler
type AuthorizeEndpointHandlers []AuthorizeEndpointHandler

// Append adds an AuthorizeEndpointHandler to this list. Ignores duplicates based on reflect.TypeOf.
func (a *AuthorizeEndpointHandlers) Append(h AuthorizeEndpointHandler) {
	for _, this := range *a {
		if reflect.TypeOf(this) == reflect.TypeOf(h) {
			return
		}
	}

	*a = append(*a, h)
}

// TokenEndpointHandlers is a list of TokenEndpointHandler
type TokenEndpointHandlers []TokenEndpointHandler

// Append adds an TokenEndpointHandler to this list. Ignores duplicates based on reflect.TypeOf.
func (t *TokenEndpointHandlers) Append(h TokenEndpointHandler) {
	for _, this := range *t {
		if reflect.TypeOf(this) == reflect.TypeOf(h) {
			return
		}
	}

	*t = append(*t, h)
}

// TokenIntrospectionHandlers is a list of TokenValidator
type TokenIntrospectionHandlers []TokenIntrospector

// Append adds an AccessTokenValidator to this list. Ignores duplicates based on reflect.TypeOf.
func (t *TokenIntrospectionHandlers) Append(h TokenIntrospector) {
	for _, this := range *t {
		if reflect.TypeOf(this) == reflect.TypeOf(h) {
			return
		}
	}

	*t = append(*t, h)
}

// RevocationHandlers is a list of RevocationHandler
type RevocationHandlers []RevocationHandler

// Append adds an RevocationHandler to this list. Ignores duplicates based on reflect.TypeOf.
func (t *RevocationHandlers) Append(h RevocationHandler) {
	for _, this := range *t {
		if reflect.TypeOf(this) == reflect.TypeOf(h) {
			return
		}
	}

	*t = append(*t, h)
}

// PushedAuthorizeEndpointHandlers is a list of PushedAuthorizeEndpointHandler
type PushedAuthorizeEndpointHandlers []PushedAuthorizeEndpointHandler

// Append adds an AuthorizeEndpointHandler to this list. Ignores duplicates based on reflect.TypeOf.
func (a *PushedAuthorizeEndpointHandlers) Append(h PushedAuthorizeEndpointHandler) {
	for _, this := range *a {
		if reflect.TypeOf(this) == reflect.TypeOf(h) {
			return
		}
	}

	*a = append(*a, h)
}

// RFC8628DeviceAuthorizeEndpointHandlers is a list of RFC8628DeviceAuthorizeEndpointHandler
type RFC8628DeviceAuthorizeEndpointHandlers []RFC8628DeviceAuthorizeEndpointHandler

// Append adds an RFC8628DeviceAuthorizeEndpointHandler to this list. Ignores duplicates based on reflect.TypeOf.
func (a *RFC8628DeviceAuthorizeEndpointHandlers) Append(h RFC8628DeviceAuthorizeEndpointHandler) {
	for _, this := range *a {
		if reflect.TypeOf(this) == reflect.TypeOf(h) {
			return
		}
	}

	*a = append(*a, h)
}

// RFC8628UserAuthorizeEndpointHandlers is a list of RFC8628UserAuthorizeEndpointHandler
type RFC8628UserAuthorizeEndpointHandlers []RFC8628UserAuthorizeEndpointHandler

// Append adds an RFC8628UserAuthorizeEndpointHandler to this list. Ignores duplicates based on reflect.TypeOf.
func (a *RFC8628UserAuthorizeEndpointHandlers) Append(h RFC8628UserAuthorizeEndpointHandler) {
	for _, this := range *a {
		if reflect.TypeOf(this) == reflect.TypeOf(h) {
			return
		}
	}

	*a = append(*a, h)
}

type Configurator interface {
	IDTokenIssuerProvider
	IDTokenLifespanProvider
	AuthorizationServerIssuerIdentificationProvider
	AllowedPromptsProvider
	EnforcePKCEProvider
	EnforcePKCEForPublicClientsProvider
	EnablePKCEPlainChallengeMethodProvider
	GrantTypeJWTBearerCanSkipClientAuthProvider
	GrantTypeJWTBearerIDOptionalProvider
	GrantTypeJWTBearerIssuedDateOptionalProvider
	GetJWTMaxDurationProvider
	ScopeStrategyProvider
	AudienceStrategyProvider
	ClientCredentialsImplicitProvider
	RedirectSecureCheckerProvider
	OmitRedirectScopeParamProvider
	SanitationAllowedProvider
	JWTScopeFieldProvider
	JWTSecuredAuthorizeResponseModeIssuerProvider
	JWTSecuredAuthorizeResponseModeSignerProvider
	JWTSecuredAuthorizeResponseModeLifespanProvider
	JWTProfileAccessTokensProvider
	AccessTokenIssuerProvider
	DisableRefreshTokenValidationProvider
	RefreshTokenScopesProvider
	AccessTokenLifespanProvider
	RefreshTokenLifespanProvider
	VerifiableCredentialsNonceLifespanProvider
	AuthorizeCodeLifespanProvider
	TokenEntropyProvider
	RotatedGlobalSecretsProvider
	GlobalSecretProvider
	JWKSFetcherStrategyProvider
	HTTPClientProvider
	ScopeStrategyProvider
	AudienceStrategyProvider
	MinParameterEntropyProvider
	HMACHashingProvider
	ClientAuthenticationStrategyProvider
	ResponseModeHandlerProvider
	SendDebugMessagesToClientsProvider
	RevokeRefreshTokensExplicitlyProvider
	JWKSFetcherStrategyProvider
	ClientAuthenticationStrategyProvider
	MessageCatalogProvider
	FormPostHTMLTemplateProvider
	FormPostResponseProvider
	TokenURLProvider
	AuthorizeEndpointHandlersProvider
	TokenEndpointHandlersProvider
	TokenIntrospectionHandlersProvider
	RevocationHandlersProvider
	PushedAuthorizeRequestHandlersProvider
	PushedAuthorizeRequestConfigProvider
	RFC8693ConfigProvider
	RFC8628DeviceAuthorizeEndpointHandlersProvider
	RFC8628UserAuthorizeEndpointHandlersProvider
	RFC9628DeviceAuthorizeConfigProvider
	UseLegacyErrorFormatProvider
}

func New(store Storage, config Configurator) *Fosite {
	return &Fosite{Store: store, Config: config}
}

// Fosite implements Provider.
type Fosite struct {
	Store Storage

	Config Configurator

	defaultClientAuthenticationStrategy ClientAuthenticationStrategy
}

// GetMinParameterEntropy returns MinParameterEntropy if set. Defaults to oauth2.MinParameterEntropy.
func (f *Fosite) GetMinParameterEntropy(ctx context.Context) int {
	if mp := f.Config.GetMinParameterEntropy(ctx); mp > 0 {
		return mp
	}

	return MinParameterEntropy
}

// ResponseModeHandlers returns the configured ResponseModeHandler implementations for this instance.
func (f *Fosite) ResponseModeHandlers(ctx context.Context) []ResponseModeHandler {
	return f.Config.GetResponseModeHandlers(ctx)
}

var (
	_ Provider = (*Fosite)(nil)
)
