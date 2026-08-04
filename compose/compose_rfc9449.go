// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/rfc9449"
)

// DPoPAuthorizeFactory creates the RFC 9449 DPoP authorize endpoint binding handler, which records the 'dpop_jkt'
// parameter on the session.
//
// It is dispatched in the authorize binding phase, which runs ahead of every authorize endpoint handler, so its
// position in the factory list does not matter.
func DPoPAuthorizeFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &rfc9449.AuthorizeHandler{
		Config: config.(*oauth2.Config),
	}
}

// DPoPFactory creates the RFC 9449 DPoP token endpoint handler and, when necessary, the default DPoP strategy.
//
// It is dispatched in the token binding phase, which runs after every grant handler has restored its session and
// populated the response, so its position in the factory list does not matter.
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
