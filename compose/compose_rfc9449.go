// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/rfc9449"
)

// DPoPAuthorizeFactory creates the RFC 9449 DPoP authorize endpoint handler, which records the 'dpop_jkt' parameter on
// the session.
//
// It MUST be ordered ahead of every factory whose handler issues an authorization code, because those handlers persist
// the session as they run and would otherwise store it without the binding. DPoPFactory carries the opposite
// constraint and must be ordered last, so the two are deliberately separate factories.
func DPoPAuthorizeFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &rfc9449.AuthorizeHandler{
		Config: config.(*oauth2.Config),
	}
}

// DPoPFactory creates the RFC 9449 DPoP token endpoint handler and, when necessary, the default DPoP strategy.
//
// It MUST be ordered after every factory whose handler restores a session at the token endpoint, so that the binding
// recorded by DPoPAuthorizeFactory's handler is present on the session by the time the proof is checked against it,
// and so that the DPoP token type is not overwritten by the grant handler that populates the response.
func DPoPFactory(config oauth2.Configurator, storage any, strategy any) any {
	c := config.(*oauth2.Config)

	if c.DPoPStrategy == nil {
		store, ok := storage.(rfc9449.Storage)
		if !ok {
			panic("oauth2: DPoPFactory requires either a preconfigured Config.DPoPStrategy or a storage implementing rfc9449.Storage, but neither was provided")
		}

		c.DPoPStrategy = rfc9449.NewDefaultStrategy(c, store)
	}

	return &rfc9449.Handler{
		Config:   c,
		Strategy: c.DPoPStrategy,
	}
}
