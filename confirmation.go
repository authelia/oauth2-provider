// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"authelia.com/provider/oauth2/token/jwt"
)

// confirmationMethod is one member of the RFC 7800 'cnf' claim paired with the accessors that move it between a session
// and a set of token claims.
//
// Both directions live in a single entry deliberately. An issuing side without a matching recovery side silently drops
// the binding whenever a stateless token is introspected, because such a token's own claims are the only record of what
// it is bound to; that asymmetry is exactly how 'jkt' came to be lost. Pairing them means a confirmation method cannot
// be half-implemented.
type confirmationMethod struct {
	// name is the member name within the 'cnf' claim, for example 'jkt'.
	name string

	// get returns the binding recorded on session, or an empty string when session records none or does not support a
	// binding of this kind at all.
	get func(session Session) string

	// set records value as the binding on session, and does nothing when session does not support a binding of this
	// kind.
	set func(session Session, value string)
}

// confirmationMethods enumerates every RFC 7800 confirmation method this library understands. Adding an entry is all
// that is required for a binding to be minted into JWT profile access tokens, reported by token introspection, and
// recovered from a stateless token; the call sites iterate this table and need no change.
//
// An RFC 8705 certificate-bound access token belongs here as a jwt.ClaimConfirmationX509SHA256Thumbprint entry backed
// by a session interface shaped like DPoPBoundSession. Sourcing it from the session rather than from a session's extra
// claims is what makes it unforgeable, for the reasons given on ApplyConfirmation.
var confirmationMethods = []confirmationMethod{
	{
		name: jwt.ClaimConfirmationJWKThumbprint,
		get: func(session Session) (jkt string) {
			if bound, ok := session.(DPoPBoundSession); ok {
				return bound.GetDPoPJWKThumbprint()
			}

			return ""
		},
		set: func(session Session, value string) {
			if bound, ok := session.(DPoPBoundSession); ok {
				bound.SetDPoPJWKThumbprint(value)
			}
		},
	},
}

// ApplyConfirmation rebuilds the RFC 7800 'cnf' claim in claims from the bindings recorded on session, and is the only
// supported way to write that claim.
//
// The claim is rebuilt rather than merged into, so it asserts exactly the bindings the server established and nothing
// else. That matters because the claims a token is minted from include the session's extra claims, which are free-form:
// were the existing value merged into, a 'cnf' placed there would travel into the token, and a resource server reads
// 'cnf' as evidence that a proof-of-possession check was performed. A 'cnf' that would be left empty is removed
// entirely, since an empty confirmation asserts nothing while still suggesting the token is bound.
func ApplyConfirmation(claims map[string]any, session Session) {
	if claims == nil {
		return
	}

	cnf := map[string]any{}

	for _, method := range confirmationMethods {
		if value := method.get(session); value != "" {
			cnf[method.name] = value
		}
	}

	if len(cnf) == 0 {
		delete(claims, jwt.ClaimConfirmation)

		return
	}

	claims[jwt.ClaimConfirmation] = cnf
}

// RestoreConfirmation records on session the bindings asserted by the RFC 7800 'cnf' claim in claims. It is the inverse
// of ApplyConfirmation, for a stateless token whose own claims are the only record of what it is bound to.
//
// The claims MUST already have been validated, because this trusts them: it is the token's signature that makes 'cnf'
// evidence of a binding the server established rather than an assertion by whoever presented the token.
func RestoreConfirmation(claims map[string]any, session Session) {
	cnf := confirmationClaim(claims)

	for _, method := range confirmationMethods {
		if value, ok := cnf[method.name].(string); ok && value != "" {
			method.set(session, value)
		}
	}
}

// GetDPoPConfirmationJWKThumbprint returns the 'jkt' confirmation method of the RFC 7800 'cnf' claim in claims, or an
// empty string when the claim is absent, is not a JSON object, or carries no JWK thumbprint. It serves callers holding
// claims but no session, such as a resource server taking the bound thumbprint out of an introspection response to hand
// to the RFC 9449 ValidateResourceAccess.
func GetDPoPConfirmationJWKThumbprint(claims map[string]any) (jkt string) {
	jkt, _ = confirmationClaim(claims)[jwt.ClaimConfirmationJWKThumbprint].(string)

	return jkt
}

// confirmationClaim returns the RFC 7800 'cnf' claim from claims, or nil when it is absent or is not a JSON object.
// RFC 7800 Section 3.1 defines 'cnf' as a JSON object, so any other value asserts no confirmation method at all.
func confirmationClaim(claims map[string]any) map[string]any {
	switch value := claims[jwt.ClaimConfirmation].(type) {
	case map[string]any:
		return value
	case jwt.MapClaims:
		return value
	default:
		return nil
	}
}
