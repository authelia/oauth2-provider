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

// CommonStrategy does not itself implement rfc7591.ClientRegistrationTokenStrategy, by design. CoreStrategy is
// declared as the hoauth2.CoreStrategy interface, so embedding it here promotes only the methods that interface
// declares; the client registration token methods live only on the concrete *hoauth2.HMACCoreStrategy or
// *hoauth2.JWTProfileCoreStrategy CommonStrategy is ordinarily constructed with (see NewOAuth2HMACStrategy,
// NewOAuth2JWTStrategy), and are invisible through CommonStrategy regardless of whether it is held by value or by
// pointer. RFC7591ClientRegistrationFactory and RFC7592ClientConfigurationFactory therefore resolve the underlying
// CoreStrategy directly, via mustClientRegistrationTokenStrategy, rather than requiring CommonStrategy itself to
// satisfy the interface. A CoreStrategy that does not implement it fails there, at compose time, with a message
// naming this field and the methods it lacks.
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

// mustClientRegistrationTokenStrategy resolves strategy to an rfc7591.ClientRegistrationTokenStrategy, or panics
// with a message naming what is wrong.
//
// It special-cases CommonStrategy, by value and by pointer, because CommonStrategy never satisfies the interface
// through method promotion alone (see its doc comment), so its CoreStrategy is resolved directly. Any other strategy
// type is asserted against the interface, exactly as every other compose factory asserts its strategy parameter.
//
// RFC7591ClientRegistrationFactory and RFC7592ClientConfigurationFactory call this from inside the Factory Compose
// invokes synchronously while assembling the Provider, so a misconfigured CoreStrategy fails at compose time rather
// than as an interface-conversion panic on the first request reaching one of those endpoints.
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

// NewOAuth2HMACStrategy builds the CoreStrategy through hoauth2.NewHMACCoreStrategy, not a struct literal, so its
// client registration token methods sign and verify with their own secret instead of being left unconfigured -
// which would otherwise make every client registration token mint or validation fail the first time
// compose.ComposeAllEnabled's RFC 7591 handlers use one, since ComposeAllEnabled builds its strategy through this
// constructor.
func NewOAuth2HMACStrategy(config HMACSHAStrategyConfigurator) *hoauth2.HMACCoreStrategy {
	return hoauth2.NewHMACCoreStrategy(config, "")
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
