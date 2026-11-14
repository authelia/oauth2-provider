// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"authelia.com/provider/oauth2/x/errorsx"
)

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

// hasSessionBinding reports which proof-of-possession bindings the session carries.
func hasSessionBinding(session Session) (dpop, mtls bool) {
	if s, ok := session.(DPoPBoundSession); ok {
		dpop = s.GetDPoPJWKThumbprint() != "" || s.GetRequestedDPoPJWKThumbprint() != "" || len(s.GetDPoPPublicKeyJWK()) != 0 || s.GetOIDCKeyBindingGranted()
	}

	if s, ok := session.(MTLSBoundSession); ok {
		mtls = s.GetClientCertificateSHA256Thumbprint() != ""
	}

	return dpop, mtls
}

// validateSessionBindingCarry requires the session which replaces restored to be able to carry each
// proof-of-possession binding restored carries, so carrySessionBinding never drops one.
func validateSessionBindingCarry(restored, session Session) (err error) {
	dpop, mtls := hasSessionBinding(restored)

	if _, ok := session.(DPoPBoundSession); dpop && !ok {
		return errorsx.WithStack(ErrServerError.WithDebug("The request is DPoP bound but the replacement session cannot carry a DPoP binding."))
	}

	if _, ok := session.(MTLSBoundSession); mtls && !ok {
		return errorsx.WithStack(ErrServerError.WithDebug("The request is certificate bound but the replacement session cannot carry a certificate binding."))
	}

	return nil
}
