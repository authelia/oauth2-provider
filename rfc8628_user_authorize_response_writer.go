// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import "context"

// NewRFC8628UserAuthorizeResponse dispatches the user-facing device authorization request to each configured handler
// to populate the response with the user's authorization decision and any extension parameters.
func (f *Fosite) NewRFC8628UserAuthorizeResponse(ctx context.Context, requester DeviceAuthorizeRequester, session Session) (responder DeviceUserAuthorizeResponder, err error) {
	carryRFC8628SessionBinding(requester.GetSession(), session)

	requester.SetSession(session)
	responder = NewRFC8628UserAuthorizeResponse()

	for _, h := range f.Config.GetRFC8628UserAuthorizeEndpointHandlers(ctx) {
		if err = h.PopulateRFC8628UserAuthorizeEndpointResponse(ctx, requester, responder); err != nil {
			return nil, err
		}
	}

	return responder, nil
}

// carryRFC8628SessionBinding copies the proof-of-possession bindings the device authorization endpoint recorded onto
// the session that replaces it here, which would otherwise drop them.
//
// A restored binding wins over one the replacement already carries. It is what rfc9449.DeviceAuthorizeHandler recorded
// from 'dpop_jkt', so the client committed to that key, while this runs before SetSession and before any handler, so a
// value on the replacement can only have come from the caller constructing it. Letting the caller's win would rebind
// the device code to a key the client never asked for, which rfc9449.Handler.BindAccessRequest would then enforce at
// the token endpoint.
func carryRFC8628SessionBinding(restored, session Session) {
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
