// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/rfc8705"
)

// RFC8705Factory creates the RFC 8705 certificate-bound access token handler.
//
// It is dispatched in the token binding phase, which runs after every grant handler has restored its session, so its
// position in the factory list does not matter.
func RFC8705Factory(config oauth2.Configurator, storage any, strategy any) any {
	return &rfc8705.Handler{
		Config: config.(oauth2.MTLSConfigProvider),
	}
}
