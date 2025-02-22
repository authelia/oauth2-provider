// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/token/hmac"
	"authelia.com/provider/oauth2/token/jwt"
)

type CommonStrategy struct {
	hoauth2.CoreStrategy
	openid.OpenIDConnectTokenStrategy
	jwt.Strategy
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

func NewOAuth2HMACStrategy(config HMACSHAStrategyConfigurator) *hoauth2.HMACCoreStrategy {
	return &hoauth2.HMACCoreStrategy{
		Enigma: &hmac.HMACStrategy{Config: config},
		Config: config,
	}
}

func NewOAuth2JWTStrategy(strategy jwt.Strategy, strategyHMAC *hoauth2.HMACCoreStrategy, config oauth2.Configurator) *hoauth2.JWTProfileCoreStrategy {
	return &hoauth2.JWTProfileCoreStrategy{
		Strategy:         strategy,
		HMACCoreStrategy: strategyHMAC,
		Config:           config,
	}
}

func NewOpenIDConnectStrategy(keyGetter func(context.Context) (any, error), strategy jwt.Strategy, config oauth2.Configurator) *openid.DefaultStrategy {
	return &openid.DefaultStrategy{
		Strategy: strategy,
		Config:   config,
	}
}
