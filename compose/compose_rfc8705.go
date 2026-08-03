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
// It MUST be ordered after every factory whose handler restores a session at the token endpoint, so that a binding
// established when the grant was issued is present on the session by the time the handler checks it against the
// certificate presented now. Ordering it earlier leaves a refresh of a bound grant unchecked.
func RFC8705Factory(config oauth2.Configurator, storage any, strategy any) any {
	return &rfc8705.Handler{
		Config: config.(*oauth2.Config),
	}
}
