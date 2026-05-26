// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"authelia.com/provider/oauth2"
)

// tokenRole identifies the form-parameter role of a token under validation.
// It selects which per-client issuer allow-list applies in ValidateIssuer.
type tokenRole int

const (
	tokenRoleSubject tokenRole = iota
	tokenRoleActor
)

// clientAllowedIssuers returns the per-client issuer allow-list for the given role,
// or nil if the request's client doesn't implement the rfc8693.Client interface.
func clientAllowedIssuers(client oauth2.Client, role tokenRole) []string {
	c, ok := client.(Client)
	if !ok {
		return nil
	}

	switch role {
	case tokenRoleActor:
		return c.GetSupportedActorTokenIssuers()
	default:
		return c.GetSupportedSubjectTokenIssuers()
	}
}

// ValidateIssuer enforces issuer trust for a JWT-typed token in token exchange:
//   - If the client publishes a non-empty issuer allow-list for this role, the JWT's
//     'iss' MUST be in that list.
//   - Otherwise, fall back to fallbackIssuer (typically JWTType.Issuer or the AS's
//     own issuer). An empty fallback means no issuer check.
//
// Returns the issuer that was matched (for diagnostics) and true on success.
func ValidateIssuer(iss, fallbackIssuer string, allowed []string) (matched string, ok bool) {
	if len(allowed) > 0 {
		for _, candidate := range allowed {
			if candidate == iss {
				return candidate, true
			}
		}

		return "", false
	}

	if fallbackIssuer == "" {
		return iss, true
	}

	if fallbackIssuer == iss {
		return fallbackIssuer, true
	}

	return "", false
}
