// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"

	"github.com/authelia/goauth2"
	"github.com/authelia/goauth2/token/jwt"
)

type Factory func(config goauth2.Configurator, storage interface{}, strategy interface{}) interface{}

// Compose takes a config, a storage, a strategy and handlers to instantiate an OAuth2Provider:
//
//	 import "github.com/authelia/goauth2/compose"
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
// Compose makes use of interface{} types in order to be able to handle a all types of stores, strategies and handlers.
func Compose(config *goauth2.Config, storage interface{}, strategy interface{}, factories ...Factory) goauth2.OAuth2Provider {
	f := goauth2.NewOAuth2Provider(storage.(goauth2.Storage), config)
	for _, factory := range factories {
		res := factory(config, storage, strategy)
		if ah, ok := res.(goauth2.AuthorizeEndpointHandler); ok {
			config.AuthorizeEndpointHandlers.Append(ah)
		}
		if th, ok := res.(goauth2.TokenEndpointHandler); ok {
			config.TokenEndpointHandlers.Append(th)
		}
		if tv, ok := res.(goauth2.TokenIntrospector); ok {
			config.TokenIntrospectionHandlers.Append(tv)
		}
		if rh, ok := res.(goauth2.RevocationHandler); ok {
			config.RevocationHandlers.Append(rh)
		}
		if ph, ok := res.(goauth2.PushedAuthorizeEndpointHandler); ok {
			config.PushedAuthorizeEndpointHandlers.Append(ph)
		}
	}

	return f
}

// ComposeAllEnabled returns a goauth2 instance with all OAuth2 and OpenID Connect handlers enabled.
func ComposeAllEnabled(config *goauth2.Config, storage interface{}, key interface{}) goauth2.OAuth2Provider {
	keyGetter := func(context.Context) (interface{}, error) {
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
		OAuth2ClientCredentialsGrantFactory,
		OAuth2RefreshTokenGrantFactory,
		OAuth2ResourceOwnerPasswordCredentialsFactory,
		RFC7523AssertionGrantFactory,

		OpenIDConnectExplicitFactory,
		OpenIDConnectImplicitFactory,
		OpenIDConnectHybridFactory,
		OpenIDConnectRefreshFactory,

		OAuth2TokenIntrospectionFactory,
		OAuth2TokenRevocationFactory,

		OAuth2PKCEFactory,
		PushedAuthorizeHandlerFactory,
	)
}
