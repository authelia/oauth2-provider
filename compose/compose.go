// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/token/jwt"
)

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
func Compose(config *oauth2.Config, storage any, strategy any, factories ...Factory) oauth2.Provider {
	f := oauth2.New(storage.(oauth2.Storage), config)
	for _, factory := range factories {
		res := factory(config, storage, strategy)
		if ah, ok := res.(oauth2.AuthorizeEndpointHandler); ok {
			config.AuthorizeEndpointHandlers.Append(ah)
		}
		if th, ok := res.(oauth2.TokenEndpointHandler); ok {
			config.TokenEndpointHandlers.Append(th)
		}
		if tv, ok := res.(oauth2.TokenIntrospector); ok {
			config.TokenIntrospectionHandlers.Append(tv)
		}
		if rh, ok := res.(oauth2.RevocationHandler); ok {
			config.RevocationHandlers.Append(rh)
		}
		if ph, ok := res.(oauth2.PushedAuthorizeEndpointHandler); ok {
			config.PushedAuthorizeEndpointHandlers.Append(ph)
		}
		if dh, ok := res.(oauth2.RFC8628DeviceAuthorizeEndpointHandler); ok {
			config.RFC8628DeviceAuthorizeEndpointHandlers.Append(dh)
		}
		if uh, ok := res.(oauth2.RFC8628UserAuthorizeEndpointHandler); ok {
			config.RFC8628UserAuthorizeEndpointHandlers.Append(uh)
		}
	}

	return f
}

// ComposeAllEnabled returns a oauth2 instance with all OAuth2 and OpenID Connect handlers enabled.
func ComposeAllEnabled(config *oauth2.Config, storage any, key any) oauth2.Provider {
	keyGetter := func(context.Context, jwt.Mapper) (any, error) {
		return key, nil
	}
	return Compose(
		config,
		storage,
		&CommonStrategy{
			CoreStrategy:               NewOAuth2HMACStrategy(config),
			OpenIDConnectTokenStrategy: NewOpenIDConnectStrategy(keyGetter, config),
			Signer:                     &jwt.DefaultSigner{GetPrivateKey: keyGetter},
		},
		OAuth2AuthorizeExplicitFactory,
		OAuth2AuthorizeImplicitFactory,
		OAuth2AuthorizeNoneFactory,
		OAuth2ClientCredentialsGrantFactory,
		OAuth2RefreshTokenGrantFactory,
		RFC8628DeviceAuthorizeFactory,
		RFC8628UserAuthorizeFactory,
		RFC8628DeviceAuthorizeTokenFactory,

		OAuth2ResourceOwnerPasswordCredentialsFactory,
		RFC7523AssertionGrantFactory,

		OpenIDConnectExplicitFactory,
		OpenIDConnectImplicitFactory,
		OpenIDConnectHybridFactory,
		OpenIDConnectRefreshFactory,
		OpenIDConnectDeviceAuthorizeFactory,

		OAuth2TokenIntrospectionFactory,
		OAuth2TokenRevocationFactory,

		OAuth2PKCEFactory,
		PushedAuthorizeHandlerFactory,
	)
}
