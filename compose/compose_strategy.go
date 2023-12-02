// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"

	"github.com/authelia/goauth2"
	"github.com/authelia/goauth2/handler/oauth2"
	"github.com/authelia/goauth2/handler/openid"
	"github.com/authelia/goauth2/token/hmac"
	"github.com/authelia/goauth2/token/jwt"
)

type CommonStrategy struct {
	oauth2.CoreStrategy
	openid.OpenIDConnectTokenStrategy
	jwt.Signer
}

type HMACSHAStrategyConfigurator interface {
	goauth2.AccessTokenLifespanProvider
	goauth2.RefreshTokenLifespanProvider
	goauth2.AuthorizeCodeLifespanProvider
	goauth2.TokenEntropyProvider
	goauth2.GlobalSecretProvider
	goauth2.RotatedGlobalSecretsProvider
	goauth2.HMACHashingProvider
}

func NewOAuth2HMACStrategy(config HMACSHAStrategyConfigurator) *oauth2.HMACSHAStrategy {
	return &oauth2.HMACSHAStrategy{
		Enigma: &hmac.HMACStrategy{Config: config},
		Config: config,
	}
}

func NewOAuth2JWTStrategy(keyGetter func(context.Context) (interface{}, error), strategy *oauth2.HMACSHAStrategy, config goauth2.Configurator) *oauth2.DefaultJWTStrategy {
	return &oauth2.DefaultJWTStrategy{
		Signer:          &jwt.DefaultSigner{GetPrivateKey: keyGetter},
		HMACSHAStrategy: strategy,
		Config:          config,
	}
}

func NewOpenIDConnectStrategy(keyGetter func(context.Context) (interface{}, error), config goauth2.Configurator) *openid.DefaultStrategy {
	return &openid.DefaultStrategy{
		Signer: &jwt.DefaultSigner{GetPrivateKey: keyGetter},
		Config: config,
	}
}
