// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/rfc9449"
)

// DPoPFactory creates the RFC 9449 DPoP handler and, when necessary, the default DPoP strategy.
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
