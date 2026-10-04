// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"
	"fmt"
	"strings"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/handler/rfc7591"
	"authelia.com/provider/oauth2/token/jwt"
)

// CommonStrategy does not itself implement rfc7591.ClientRegistrationTokenStrategy, as the embedded
// hoauth2.CoreStrategy interface does not declare its methods. RFC7591ClientRegistrationFactory and
// RFC7592ClientConfigurationFactory resolve the CoreStrategy via mustClientRegistrationTokenStrategy, which panics at
// compose time when it does not implement the interface.
type CommonStrategy struct {
	hoauth2.CoreStrategy
	openid.OpenIDConnectTokenStrategy
	jwt.Strategy
}

// clientRegistrationTokenSignatureMethod, generateClientRegistrationTokenMethod and
// validateClientRegistrationTokenMethod each isolate one method of rfc7591.ClientRegistrationTokenStrategy so
// clientRegistrationTokenStrategy can name exactly which ones a misconfigured CoreStrategy is missing, rather than
// only being able to report that the assertion against the whole interface failed.
type clientRegistrationTokenSignatureMethod interface {
	ClientRegistrationTokenSignature(ctx context.Context, tokenString string) (signature string)
}

type generateClientRegistrationTokenMethod interface {
	GenerateClientRegistrationToken(ctx context.Context, requester oauth2.Requester) (tokenString string, signature string, err error)
}

type validateClientRegistrationTokenMethod interface {
	ValidateClientRegistrationToken(ctx context.Context, requester oauth2.Requester, tokenString string) (err error)
}

// clientRegistrationTokenStrategy resolves s.CoreStrategy as an rfc7591.ClientRegistrationTokenStrategy, or returns
// an error naming the CoreStrategy field and the specific methods it lacks. See the CommonStrategy doc comment for
// why CoreStrategy, not CommonStrategy itself, is what must satisfy the interface.
func (s CommonStrategy) clientRegistrationTokenStrategy() (strategy rfc7591.ClientRegistrationTokenStrategy, err error) {
	if resolved, ok := s.CoreStrategy.(rfc7591.ClientRegistrationTokenStrategy); ok {
		return resolved, nil
	}

	var missing []string

	if _, ok := s.CoreStrategy.(clientRegistrationTokenSignatureMethod); !ok {
		missing = append(missing, "ClientRegistrationTokenSignature")
	}

	if _, ok := s.CoreStrategy.(generateClientRegistrationTokenMethod); !ok {
		missing = append(missing, "GenerateClientRegistrationToken")
	}

	if _, ok := s.CoreStrategy.(validateClientRegistrationTokenMethod); !ok {
		missing = append(missing, "ValidateClientRegistrationToken")
	}

	return nil, fmt.Errorf(
		"compose: CommonStrategy.CoreStrategy (%T) does not implement rfc7591.ClientRegistrationTokenStrategy: missing %s; use *hoauth2.HMACCoreStrategy, *hoauth2.JWTProfileCoreStrategy, or implement these methods on your CoreStrategy",
		s.CoreStrategy, strings.Join(missing, ", "),
	)
}

// mustClientRegistrationTokenStrategy resolves strategy to an rfc7591.ClientRegistrationTokenStrategy, or panics at
// compose time. A CommonStrategy, by value or by pointer, is resolved through its CoreStrategy; any other type is
// asserted against the interface directly.
func mustClientRegistrationTokenStrategy(strategy any) (resolved rfc7591.ClientRegistrationTokenStrategy) {
	var (
		cs  CommonStrategy
		err error
	)

	switch v := strategy.(type) {
	case *CommonStrategy:
		cs = *v
	case CommonStrategy:
		cs = v
	default:
		return strategy.(rfc7591.ClientRegistrationTokenStrategy)
	}

	if resolved, err = cs.clientRegistrationTokenStrategy(); err != nil {
		panic(err)
	}

	return resolved
}

type HMACSHAStrategyConfigurator interface {
	oauth2.AccessTokenLifespanProvider
	oauth2.RefreshTokenLifespanProvider
	oauth2.AuthorizeCodeLifespanProvider
	oauth2.TokenEntropyProvider
	oauth2.GlobalSecretProvider
	oauth2.RotatedGlobalSecretsProvider
	oauth2.HMACHashingProvider
	oauth2.RFC8628DeviceAuthorizeConfigProvider
	oauth2.RFC7591ClientRegistrationTokenSecretProvider
}

// NewOAuth2HMACStrategy returns a hoauth2.HMACCoreStrategy built through hoauth2.NewHMACCoreStrategy, so its client
// registration token methods sign and verify with their own secret.
func NewOAuth2HMACStrategy(config HMACSHAStrategyConfigurator) *hoauth2.HMACCoreStrategy {
	return hoauth2.NewHMACCoreStrategy(config, "")
}

// NewOAuth2JWTStrategy returns a hoauth2.JWTProfileCoreStrategy which issues JWT Profile access tokens using the given
// jwt.Strategy and delegates every other token kind to the given HMAC strategy.
func NewOAuth2JWTStrategy(strategy jwt.Strategy, strategyHMAC *hoauth2.HMACCoreStrategy, config oauth2.Configurator) *hoauth2.JWTProfileCoreStrategy {
	return &hoauth2.JWTProfileCoreStrategy{
		Strategy:         strategy,
		HMACCoreStrategy: strategyHMAC,
		Config:           config,
	}
}

// NewOpenIDConnectStrategy returns an openid.DefaultStrategy which issues ID Tokens using the given jwt.Strategy. The
// 'keyGetter' argument is not used.
func NewOpenIDConnectStrategy(keyGetter func(context.Context) (any, error), strategy jwt.Strategy, config oauth2.Configurator) *openid.DefaultStrategy {
	return &openid.DefaultStrategy{
		Strategy: strategy,
		Config:   config,
	}
}
