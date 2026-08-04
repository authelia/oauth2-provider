// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"

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

	// enabled reports whether the binding method this confirmation describes is turned on. A disabled method is never
	// asserted, because a session outlives a configuration change: a binding recorded while the method was enabled
	// survives on the session after it is turned off, and the handler that would verify it no longer runs. Emitting
	// the confirmation anyway would tell the resource server a proof-of-possession check was performed when none was.
	//
	// Only ApplyConfirmation consults this. RestoreConfirmation deliberately does not: it recovers what a signed token
	// already asserts, which is a statement about how the token was issued rather than about current configuration.
	enabled func(ctx context.Context, config ConfirmationConfigProvider) bool

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
var confirmationMethods = []confirmationMethod{
	{
		name: jwt.ClaimConfirmationJWKThumbprint,
		enabled: func(ctx context.Context, config ConfirmationConfigProvider) bool {
			return config.GetDPoPEnabled(ctx)
		},
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
	{
		name: jwt.ClaimConfirmationX509SHA256Thumbprint,
		enabled: func(ctx context.Context, config ConfirmationConfigProvider) bool {
			return config.GetMTLSEnabled(ctx)
		},
		get: func(session Session) (x5t string) {
			if bound, ok := session.(MTLSBoundSession); ok {
				return bound.GetClientCertificateSHA256Thumbprint()
			}

			return ""
		},
		set: func(session Session, value string) {
			if bound, ok := session.(MTLSBoundSession); ok {
				bound.SetClientCertificateSHA256Thumbprint(value)
			}
		},
	},
}

// ApplyConfirmation rebuilds the RFC 7800 'cnf' claim in claims from the bindings recorded on session whose binding
// method is currently enabled, and is the only supported way to write that claim.
//
// The claim is rebuilt rather than merged into, so it asserts exactly the bindings the server established and nothing
// else. That matters because the claims a token is minted from include the session's extra claims, which are free-form:
// were the existing value merged into, a 'cnf' placed there would travel into the token, and a resource server reads
// 'cnf' as evidence that a proof-of-possession check was performed. A 'cnf' that would be left empty is removed
// entirely, since an empty confirmation asserts nothing while still suggesting the token is bound.
//
// A binding whose method is disabled is skipped for the same reason, and is skipped rather than erased: a session
// restored from storage still carries a binding recorded while the method was enabled, but the handler that would
// verify it no longer runs, so asserting it would claim a check that did not happen. Leaving the value on the session
// keeps the binding dormant rather than lost, so re-enabling the method resumes both enforcement and this claim.
func ApplyConfirmation(ctx context.Context, config ConfirmationConfigProvider, claims map[string]any, session Session) {
	if claims == nil {
		return
	}

	cnf := map[string]any{}

	for _, method := range confirmationMethods {
		// A nil config asserts nothing, so no method is enabled. Failing closed is deliberate: the alternative
		// direction would emit a confirmation on a misconfigured server, which is the one outcome this claim must
		// never produce. Any existing 'cnf' is still stripped below.
		if config == nil || !method.enabled(ctx, config) {
			continue
		}

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

// GetMTLSConfirmationX509SHA256Thumbprint returns the 'x5t#S256' confirmation method of the RFC 7800 'cnf' claim in
// claims, or an empty string when the claim is absent, is not a JSON object, or carries no certificate thumbprint. It
// serves callers holding claims but no session, such as a resource server taking the bound thumbprint out of an
// introspection response to hand to the RFC 8705 ValidateResourceAccess.
func GetMTLSConfirmationX509SHA256Thumbprint(claims map[string]any) (x5t string) {
	x5t, _ = confirmationClaim(claims)[jwt.ClaimConfirmationX509SHA256Thumbprint].(string)

	return x5t
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
