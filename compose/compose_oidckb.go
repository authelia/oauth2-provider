// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/oidckb"
)

// OpenIDConnectKeyBindingAuthorizeFactory creates the OpenID Connect Key Binding 1.0 authorize endpoint binding
// handler, which rejects an authentication request that cannot produce the key-bound ID Token it asks for.
//
// DPoPAuthorizeFactory and DPoPTokenFactory must also be registered; this handler enforces the profile's rules but
// performs no DPoP validation of its own.
func OpenIDConnectKeyBindingAuthorizeFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &oidckb.AuthorizeHandler{
		Config: config,
	}
}

// OpenIDConnectKeyBindingDeviceAuthorizeFactory creates the OpenID Connect Key Binding 1.0 device authorization
// endpoint binding handler.
//
// DPoPDeviceAuthorizeFactory must also be registered, as it is what records the 'dpop_jkt' parameter.
func OpenIDConnectKeyBindingDeviceAuthorizeFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &oidckb.DeviceAuthorizeHandler{
		Config: config,
	}
}

// OpenIDConnectKeyBindingFactory creates the OpenID Connect Key Binding 1.0 token endpoint binding handler, which
// confirms the 'c_s256' claim and records the proof key the ID Token's 'cnf' claim carries.
//
// It MUST be registered after DPoPTokenFactory: it performs no proof validation of its own and instead consumes the
// proof rfc9449.Handler publishes once every RFC 9449 Section 5 check has passed, and both run in the same
// registration-ordered token binding handler list.
func OpenIDConnectKeyBindingFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &oidckb.Handler{
		Config: config,
	}
}

// OpenIDConnectKeyBindingUserAuthorizeFactory creates the OpenID Connect Key Binding 1.0 user authorization endpoint
// handler, which records that the 'bound_key' scope was granted for a device flow.
//
// It must be registered for device flow key binding to work. The Device Authorization Flow grants its scopes at this
// endpoint rather than at the device authorization endpoint, because the end user approves the request here, so
// OpenIDConnectKeyBindingDeviceAuthorizeFactory's handler cannot record the grant itself.
//
// It MUST be registered before RFC8628UserAuthorizeFactory, whose handler persists the device code session: registered
// after it, this handler would record the grant onto a session already written, and every store that serializes on
// write would drop it. Compose panics on the wrong order.
func OpenIDConnectKeyBindingUserAuthorizeFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &oidckb.UserAuthorizeHandler{
		Config: config,
	}
}
