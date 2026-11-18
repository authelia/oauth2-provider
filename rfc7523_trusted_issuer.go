// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"authelia.com/provider/jose"
)

// RFC7523TrustedIssuer is the trust configuration for an issuer of RFC 7523 JWT authorization grants.
//
// See: https://datatracker.ietf.org/doc/html/rfc7523#section-3
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-chaining-17#section-2.4.2
type RFC7523TrustedIssuer struct {
	// Issuer is the issuer identifier matched against the 'iss' claim.
	Issuer string

	// JSONWebKeys is the static key set used to verify grants. It takes precedence over JSONWebKeysURI.
	JSONWebKeys *jose.JSONWebKeySet

	// JSONWebKeysURI is resolved through the configured JWKS fetcher when JSONWebKeys is nil.
	JSONWebKeysURI string

	// SigningAlgs is the set of permitted JWS algorithms, intersected with the configured RFC 7523 assertion signing
	// algorithms. RS256 only when empty. The HMAC algorithms and 'none' are never accepted.
	SigningAlgs []string

	// Subjects is the set of 'sub' claim values accepted before the subject is resolved. Any subject when empty.
	Subjects []string

	// Scopes is the maximum scope grantable from this issuer. It is matched with the configured scope strategy, while
	// the 'scope' claim of a grant is matched exactly.
	Scopes []string

	// Audience is the set of audience and resource values grantable from this issuer. None when empty.
	Audience []string

	// Clients is the set of client identifiers permitted to present grants from this issuer. Any client when empty. Any
	// other client presenting a valid grant is answered access_denied. Listing a public client identifies it but does
	// not authenticate it.
	Clients []string
}
