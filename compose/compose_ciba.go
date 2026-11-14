// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"fmt"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/ciba"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/token/jwt"
)

// The OpenID Connect CIBA factories are not part of ComposeAllEnabled, as each requires a storage implementing
// ciba.Storage. CIBAFactories returns them in an order ValidateHandlerOrder accepts: CIBADecisionFactory and
// CIBATokenFactory, in either order, then OpenIDConnectCIBAFactory, then CIBAEndpointFactory.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html

// CIBAFactories returns the OpenID Connect CIBA factories in an order ValidateHandlerOrder accepts.
func CIBAFactories() []Factory {
	return []Factory{
		CIBADecisionFactory,
		CIBATokenFactory,
		OpenIDConnectCIBAFactory,
		CIBAEndpointFactory,
	}
}

// CIBAEndpointFactory creates the OpenID Connect CIBA backchannel authentication endpoint handler, which issues and
// persists the 'auth_req_id'. It must be composed after OpenIDConnectCIBAFactory.
func CIBAEndpointFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &ciba.EndpointHandler{
		Strategy: mustCIBAAuthRequestIDStrategy(strategy),
		Storage:  storage.(ciba.Storage),
		Config:   config,
	}
}

// CIBADecisionFactory creates the OpenID Connect CIBA decision handler, which records the end user's decision. It must
// be composed before OpenIDConnectCIBAFactory.
func CIBADecisionFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &ciba.DecisionHandler{
		Storage:  storage.(ciba.Storage),
		Strategy: mustCIBAAuthRequestIDStrategy(strategy),
		Config:   config,
	}
}

// CIBATokenFactory creates the token endpoint handler for the 'urn:openid:params:grant-type:ciba' grant type, which
// redeems the 'auth_req_id' of a poll or ping client. It must be composed before OpenIDConnectCIBAFactory.
func CIBATokenFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &ciba.TokenEndpointHandler{
		GenericCodeTokenEndpointHandler: hoauth2.GenericCodeTokenEndpointHandler{
			CodeTokenEndpointHandler: newCIBATokenHandler(config, storage, strategy),
			AccessTokenStrategy:      strategy.(hoauth2.AccessTokenStrategy),
			RefreshTokenStrategy:     strategy.(hoauth2.RefreshTokenStrategy),
			CoreStorage:              storage.(hoauth2.CoreStorage),
			TokenRevocationStorage:   storage.(hoauth2.TokenRevocationStorage),
			Config:                   config,
		},
	}
}

// OpenIDConnectCIBAFactory creates the OpenID Connect 1.0 handler for the 'urn:openid:params:grant-type:ciba' grant
// type, which records the 'nonce' at the backchannel authentication endpoint, writes the OpenID Connect session when
// the request is approved, and issues the ID Token when the 'auth_req_id' is redeemed. It must be composed after
// CIBADecisionFactory and CIBATokenFactory, and before CIBAEndpointFactory.
func OpenIDConnectCIBAFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &openid.OpenIDConnectCIBAHandler{
		OpenIDConnectRequestStorage:   storage.(openid.OpenIDConnectRequestStorage),
		OpenIDConnectRequestValidator: openid.NewOpenIDConnectRequestValidator(strategy.(jwt.Strategy), config),
		CodeTokenEndpointHandler:      newCIBATokenHandler(config, storage, strategy),
		Config:                        config,
		IDTokenHandleHelper: &openid.IDTokenHandleHelper{
			IDTokenStrategy: strategy.(openid.OpenIDConnectTokenStrategy),
		},
	}
}

func newCIBATokenHandler(config oauth2.Configurator, storage any, strategy any) *ciba.TokenHandler {
	return &ciba.TokenHandler{
		Storage:  storage.(ciba.Storage),
		Strategy: mustCIBAAuthRequestIDStrategy(strategy),
		Config:   config,
	}
}

// mustCIBAAuthRequestIDStrategy resolves strategy to a ciba.AuthRequestIDStrategy, or panics at compose time. A
// CommonStrategy, by value or by pointer, is resolved through its CoreStrategy, as the embedded hoauth2.CoreStrategy
// interface does not declare its methods.
func mustCIBAAuthRequestIDStrategy(strategy any) (resolved ciba.AuthRequestIDStrategy) {
	var ok bool

	if resolved, ok = strategy.(ciba.AuthRequestIDStrategy); ok {
		return resolved
	}

	switch v := strategy.(type) {
	case *CommonStrategy:
		resolved, ok = v.CoreStrategy.(ciba.AuthRequestIDStrategy)
	case CommonStrategy:
		resolved, ok = v.CoreStrategy.(ciba.AuthRequestIDStrategy)
	}

	if !ok {
		panic(fmt.Errorf("compose: the strategy (%T) does not implement ciba.AuthRequestIDStrategy; use *hoauth2.HMACCoreStrategy or *hoauth2.JWTProfileCoreStrategy as the CoreStrategy, or implement it on your strategy", strategy))
	}

	return resolved
}
