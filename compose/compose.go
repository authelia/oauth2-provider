// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

// Package compose provides functions to build a Provider from a configuration, a storage, and a set of handler factories.
package compose

import (
	"context"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/token/jwt"
)

// Factory is the signature of the functions that build a handler from a configurator, a storage, and a strategy.
type Factory func(config oauth2.Configurator, storage any, strategy any) any

// Compose takes a config, a storage, a strategy and handlers to instantiate an Provider:
//
//	 import "authelia.com/provider/oauth2/compose"
//
//	 // var storage = new(MyFositeStorage)
//	 var config = Config {
//	 	AccessTokenLifespan: time.Minute * 30,
//			// check Config for further configuration options
//	 }
//
//	 var strategy = NewOAuth2HMACStrategy(config)
//
//	 var oauth2Provider = Compose(
//	 	config,
//			storage,
//			strategy,
//			NewOAuth2AuthorizeExplicitHandler,
//			OAuth2ClientCredentialsGrantFactory,
//			// for a complete list refer to the docs of this package
//	 )
//
// Compose makes use of any types in order to be able to handle a all types of stores, strategies and handlers.
//
// Compose also registers the RFC9207ResponseModeParameterHandler, so the 'iss' authorization response parameter is
// returned whenever Issuer is set and DisableAuthorizationServerIdentification is not.
func Compose(config *oauth2.Config, storage any, strategy any, factories ...Factory) oauth2.Provider {
	f := oauth2.New(storage.(oauth2.Storage), config)
	for _, factory := range factories {
		handler := factory(config, storage, strategy)
		register(&config.AuthorizeEndpointHandlers, handler)
		register(&config.AuthorizeEndpointBindingHandlers, handler)
		register(&config.TokenEndpointHandlers, handler)
		register(&config.TokenEndpointBindingHandlers, handler)
		register(&config.TokenIntrospectionHandlers, handler)
		register(&config.RevocationHandlers, handler)
		register(&config.PushedAuthorizeEndpointHandlers, handler)
		register(&config.RFC8628DeviceAuthorizeEndpointHandlers, handler)
		register(&config.RFC8628DeviceAuthorizeEndpointBindingHandlers, handler)
		register(&config.BackChannelAuthenticationEndpointHandlers, handler)
		register(&config.BackChannelAuthenticationEndpointBindingHandlers, handler)
		register(&config.BackChannelAuthenticationDecisionHandlers, handler)
		register(&config.RFC8628UserAuthorizeEndpointHandlers, handler)
		register(&config.RFC7591ClientRegistrationEndpointHandlers, handler)
		register(&config.RFC7592ClientConfigurationEndpointHandlers, handler)
	}

	// The 'iss' authorization response parameter is returned by default as a mix-up attack defense; it is omitted when
	// Issuer is empty or DisableAuthorizationServerIdentification is set.
	// See: https://www.rfc-editor.org/rfc/rfc9700#section-4.4.2.1 and https://www.rfc-editor.org/rfc/rfc9207#section-2
	config.ResponseModeParameterHandlers.Append(&oauth2.RFC9207ResponseModeParameterHandler{Config: config})

	if err := ValidateHandlerOrder(config); err != nil {
		panic(err)
	}

	if err := ValidateJWTSecuredAuthorizeResponseMode(config); err != nil {
		panic(err)
	}

	return f
}

func register[H any](list interface{ Append(H) }, handler any) {
	if h, ok := handler.(H); ok {
		list.Append(h)
	}
}

// ComposeAllEnabled returns a oauth2 instance with all OAuth2 and OpenID Connect handlers enabled, except the resource
// owner password credentials grant, which must not be used, and the implicit and hybrid flows, which return tokens in
// the authorization response and should not be used. Compose OAuth2ResourceOwnerPasswordCredentialsFactory,
// OAuth2AuthorizeImplicitFactory, OpenIDConnectImplicitFactory or OpenIDConnectHybridFactory explicitly with Compose to
// enable them.
//
// See: https://www.rfc-editor.org/rfc/rfc9700#section-2.4, https://www.rfc-editor.org/rfc/rfc9700#section-2.1.2,
// https://www.rfc-editor.org/rfc/rfc10017#section-7.2 and
// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-17#section-10.1
func ComposeAllEnabled(config *oauth2.Config, storage any, key any) oauth2.Provider {
	keyGetter := func(context.Context) (any, error) {
		return key, nil
	}

	strategy := &jwt.DefaultStrategy{
		Config: config,
		Issuer: jwt.NewDefaultIssuerRS256Unverified(key),
	}

	return Compose(
		config,
		storage,
		&CommonStrategy{
			CoreStrategy:               NewOAuth2HMACStrategy(config),
			OpenIDConnectTokenStrategy: NewOpenIDConnectStrategy(keyGetter, strategy, config),
			Strategy:                   strategy,
		},
		OAuth2AuthorizeExplicitFactory,
		OAuth2AuthorizeNoneFactory,
		OAuth2ClientCredentialsGrantFactory,
		OAuth2RefreshTokenGrantFactory,
		RFC8628DeviceAuthorizeFactory,
		RFC8628DeviceAuthorizeTokenFactory,

		RFC7523AssertionGrantFactory,

		RFC8693TokenExchangeGrantFactory,
		RFC8693AccessTokenTypeFactory,
		RFC8693RefreshTokenTypeFactory,
		RFC8693IDTokenTypeFactory,
		RFC8693CustomJWTTypeFactory,
		IDJAGIssueFactory,
		RFC8693ActorTokenValidationFactory,

		OpenIDConnectExplicitFactory,
		OpenIDConnectRefreshFactory,
		OpenIDConnectDeviceAuthorizeFactory,
		RFC8628UserAuthorizeFactory,

		OAuth2TokenIntrospectionFactory,
		OAuth2TokenRevocationFactory,

		OAuth2PKCEFactory,
		PushedAuthorizeHandlerFactory,

		RFC7591ClientRegistrationFactory,
		RFC7592ClientConfigurationFactory,

		DPoPAuthorizeFactory,
		DPoPDeviceAuthorizeFactory,
		DPoPTokenFactory,
		IDJAGRedeemFactory,
		RFC8705Factory,
	)
}
