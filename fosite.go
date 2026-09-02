// SPDX-FileCopyrightText: 2026 Authelia
//
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

// AuthorizeEndpointBindingHandlers is a list of AuthorizeEndpointBindingHandler
type AuthorizeEndpointBindingHandlers []AuthorizeEndpointBindingHandler

// Append adds an AuthorizeEndpointBindingHandler to this list. Ignores duplicates based on reflect.TypeOf.
func (a *AuthorizeEndpointBindingHandlers) Append(h AuthorizeEndpointBindingHandler) {
	for _, this := range *a {
		if reflect.TypeOf(this) == reflect.TypeOf(h) {
			return
		}
	}

	*a = append(*a, h)
}

// TokenEndpointBindingHandlers is a list of TokenEndpointBindingHandler
type TokenEndpointBindingHandlers []TokenEndpointBindingHandler

// Append adds a TokenEndpointBindingHandler to this list. Ignores duplicates based on reflect.TypeOf.
func (t *TokenEndpointBindingHandlers) Append(h TokenEndpointBindingHandler) {
	for _, this := range *t {
		if reflect.TypeOf(this) == reflect.TypeOf(h) {
			return
		}
	}

	*t = append(*t, h)
}

// RFC8628DeviceAuthorizeEndpointBindingHandlers is a list of RFC8628DeviceAuthorizeEndpointBindingHandler
type RFC8628DeviceAuthorizeEndpointBindingHandlers []RFC8628DeviceAuthorizeEndpointBindingHandler

// Append adds an RFC8628DeviceAuthorizeEndpointBindingHandler to this list. Ignores duplicates based on reflect.TypeOf.
func (a *RFC8628DeviceAuthorizeEndpointBindingHandlers) Append(h RFC8628DeviceAuthorizeEndpointBindingHandler) {
	for _, this := range *a {
		if reflect.TypeOf(this) == reflect.TypeOf(h) {
			return
		}
	}

	*a = append(*a, h)
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

// RFC7591ClientRegistrationEndpointHandlers is a list of RFC7591ClientRegistrationEndpointHandler
type RFC7591ClientRegistrationEndpointHandlers []RFC7591ClientRegistrationEndpointHandler

// Append adds an RFC7591ClientRegistrationEndpointHandler to this list. Ignores duplicates based on reflect.TypeOf.
func (a *RFC7591ClientRegistrationEndpointHandlers) Append(h RFC7591ClientRegistrationEndpointHandler) {
	for _, this := range *a {
		if reflect.TypeOf(this) == reflect.TypeOf(h) {
			return
		}
	}

	*a = append(*a, h)
}

// RFC7592ClientConfigurationEndpointHandlers is a list of RFC7592ClientConfigurationEndpointHandler
type RFC7592ClientConfigurationEndpointHandlers []RFC7592ClientConfigurationEndpointHandler

// Append adds an RFC7592ClientConfigurationEndpointHandler to this list. Ignores duplicates based on reflect.TypeOf.
func (a *RFC7592ClientConfigurationEndpointHandlers) Append(h RFC7592ClientConfigurationEndpointHandler) {
	for _, this := range *a {
		if reflect.TypeOf(this) == reflect.TypeOf(h) {
			return
		}
	}

	*a = append(*a, h)
}

// Configurator is the full configuration surface a Provider requires.
type Configurator interface {
	IDTokenIssuerProvider
	IDTokenValidationStrategyProvider
	BackChannelLogoutTokenStrategyProvider
	BackChannelLogoutLifespanProvider
	BackChannelLogoutConcurrencyProvider
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
	JWTSecuredAuthorizeResponseModeStrategyProvider
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
	AllowedJWTAssertionAudiencesProvider
	AllowedIntrospectionAudiencesProvider
	AllowedIntrospectionScopesProvider
	AuthorizeEndpointHandlersProvider
	TokenEndpointHandlersProvider
	AuthorizeEndpointBindingHandlersProvider
	TokenEndpointBindingHandlersProvider
	RFC8628DeviceAuthorizeEndpointBindingHandlersProvider
	TokenIntrospectionHandlersProvider
	RevocationHandlersProvider
	PushedAuthorizeRequestHandlersProvider
	PushedAuthorizeRequestConfigProvider
	JWTSecuredAuthorizationRequestConfigProvider
	RFC8693ConfigProvider
	RFC8628DeviceAuthorizeEndpointHandlersProvider
	RFC8628UserAuthorizeEndpointHandlersProvider
	RFC8628DeviceAuthorizeConfigProvider
	IntrospectionIssuerProvider
	IntrospectionJWTResponseStrategyProvider
	JWTStrategyProvider
	AuthorizeErrorFieldResponseStrategyProvider
	UseLegacyErrorFormatProvider
	ResourceStrategyProvider
	TokenEndpointClientAuthStrategyProvider
	RevocationEndpointClientAuthStrategyProvider
	IntrospectionEndpointClientAuthStrategyProvider
	IntrospectionEndpointClientAuthDisabledProvider
	DPoPConfigProvider
	MTLSConfigProvider
	OIDCKeyBindingConfigProvider
	RFC7591ClientRegistrationConfigProvider
	RFC7591ClientRegistrationEndpointHandlersProvider
	RFC7592ClientConfigurationEndpointHandlersProvider
}

// New returns a Fosite Provider backed by the given Storage and Configurator. For most consumers the compose package
// offers higher-level constructors that wire up the appropriate handlers and strategies.
func New(store Storage, config Configurator) *Fosite {
	return &Fosite{
		Store:  store,
		Config: config,
	}
}

// Fosite implements Provider.
type Fosite struct {
	Store  Storage
	Config Configurator
}

// GetMinParameterEntropy returns MinParameterEntropy if set. Defaults to oauth2.MinParameterEntropy.
func (f *Fosite) GetMinParameterEntropy(ctx context.Context) int {
	switch value := f.Config.GetMinParameterEntropy(ctx); {
	case value == -1, value > 0:
		return value
	default:
		return MinParameterEntropy
	}
}

var (
	_ Provider = (*Fosite)(nil)
)
