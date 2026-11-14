// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

// carrySessionBinding copies the proof-of-possession bindings recorded when a request was made onto the session that
// replaces its session when the end user decides it. A restored binding wins over one the replacement already carries,
// as it is the key the client committed to with 'dpop_jkt'.
func carrySessionBinding(restored, session Session) {
	if restored == nil || session == nil {
		return
	}

	if from, ok := restored.(DPoPBoundSession); ok {
		if to, ok := session.(DPoPBoundSession); ok {
			if jkt := from.GetDPoPJWKThumbprint(); jkt != "" {
				to.SetDPoPJWKThumbprint(jkt)
			}

			if jkt := from.GetRequestedDPoPJWKThumbprint(); jkt != "" {
				to.SetRequestedDPoPJWKThumbprint(jkt)
			}

			if jwk := from.GetDPoPPublicKeyJWK(); len(jwk) != 0 {
				to.SetDPoPPublicKeyJWK(jwk)
			}

			if from.GetOIDCKeyBindingGranted() {
				to.SetOIDCKeyBindingGranted(true)
			}
		}
	}

	if from, ok := restored.(MTLSBoundSession); ok {
		if to, ok := session.(MTLSBoundSession); ok {
			if x5t := from.GetClientCertificateSHA256Thumbprint(); x5t != "" {
				to.SetClientCertificateSHA256Thumbprint(x5t)
			}
		}
	}
}
