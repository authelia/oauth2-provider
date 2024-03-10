// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/handler/rfc8628"
	"authelia.com/provider/oauth2/token/hmac"
	"authelia.com/provider/oauth2/token/jwt"
)

type CommonStrategy struct {
	hoauth2.CoreStrategy
	rfc8628.RFC8628CodeStrategy
	openid.OpenIDConnectTokenStrategy
	jwt.Signer
}

type HMACSHAStrategyConfigurator interface {
	oauth2.AccessTokenLifespanProvider
	oauth2.RefreshTokenLifespanProvider
	oauth2.AuthorizeCodeLifespanProvider
	oauth2.TokenEntropyProvider
	oauth2.GlobalSecretProvider
	oauth2.RotatedGlobalSecretsProvider
	oauth2.HMACHashingProvider
	oauth2.RFC9628DeviceAuthorizeConfigProvider
}

func NewOAuth2HMACStrategy(config HMACSHAStrategyConfigurator) *hoauth2.HMACSHAStrategy {
	return &hoauth2.HMACSHAStrategy{
		Enigma: &hmac.HMACStrategy{Config: config},
		Config: config,
	}
}

func NewOAuth2JWTStrategy(keyGetter func(context.Context) (any, error), strategy *hoauth2.HMACSHAStrategy, config oauth2.Configurator) *hoauth2.DefaultJWTStrategy {
	return &hoauth2.DefaultJWTStrategy{
		Signer:          &jwt.DefaultSigner{GetPrivateKey: keyGetter},
		HMACSHAStrategy: strategy,
		Config:          config,
	}
}

func NewOpenIDConnectStrategy(keyGetter func(context.Context) (any, error), config oauth2.Configurator) *openid.DefaultStrategy {
	return &openid.DefaultStrategy{
		Signer: &jwt.DefaultSigner{GetPrivateKey: keyGetter},
		Config: config,
	}
}

func NewDeviceStrategy(config oauth2.Configurator) *rfc8628.RFC8628HMACSHAStrategy {
	return &rfc8628.RFC8628HMACSHAStrategy{
		Enigma: &hmac.HMACStrategy{Config: config},
		Config: config,
	}
}
