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
		Config: config,
	}
}

// DPoPTokenFactory creates the RFC 9449 DPoP token endpoint handler and, when necessary, the default DPoP strategy.
//
// It is dispatched in the token binding phase, which runs after every grant handler has restored its session and
// populated the response, so its position in the factory list does not matter, EXCEPT relative to
// OpenIDConnectKeyBindingFactory: when that factory is used, this one must precede it, see its doc comment.
func DPoPTokenFactory(config oauth2.Configurator, storage any, strategy any) any {
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

// DPoPDeviceAuthorizeFactory creates the RFC 9449 DPoP device authorization endpoint binding handler, which records
// the 'dpop_jkt' parameter on the session.
//
// It is dispatched in the device authorization binding phase, which runs ahead of every device authorization endpoint
// handler, so its position in the factory list does not matter.
//
// It is deliberately absent from ComposeAllEnabled, unlike DPoPAuthorizeFactory and DPoPTokenFactory. There was no
// device authorization binding phase before this handler existed, so registering it there would newly reject a
// malformed 'dpop_jkt' at that endpoint for every existing deployment composed that way; leaving it out preserves
// exactly the behaviour those deployments have today. Register it explicitly to accept 'dpop_jkt' in a device
// authorization request.
func DPoPDeviceAuthorizeFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &rfc9449.DeviceAuthorizeHandler{
		Config: config,
	}
}
