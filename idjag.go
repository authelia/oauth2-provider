// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"strings"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2/internal/consts"
)

// IDJAGRelationship is the IdP Authorization Server's record of a client's relationship with a Resource Authorization
// Server, used to issue an Identity Assertion JWT Authorization Grant.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-5
type IDJAGRelationship struct {
	// Issuer is the Resource Authorization Server issuer identifier, issued as the 'aud' claim.
	Issuer string

	// ClientID is the client identifier at the Resource Authorization Server, issued as the 'client_id' claim.
	ClientID string

	// Scopes is the ceiling on the scopes that may be granted.
	Scopes []string

	// Resources is the set of resource indicators that may be requested.
	Resources []string

	// SigningAlg is the JWS algorithm used to sign the grant. RS256 when empty.
	SigningAlg string
}

// IDJAGTrustedIssuer is the Resource Authorization Server's trust configuration for an issuer of Identity Assertion JWT
// Authorization Grants.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.1
type IDJAGTrustedIssuer struct {
	// Issuer is the issuer identifier matched against the 'iss' claim.
	Issuer string

	// JSONWebKeys is the static key set used to verify grants. It takes precedence over JSONWebKeysURI.
	JSONWebKeys *jose.JSONWebKeySet

	// JSONWebKeysURI is resolved through the configured JWKS fetcher when JSONWebKeys is nil.
	JSONWebKeysURI string

	// SigningAlgs is the set of permitted JWS algorithms. RS256 when empty. Symmetric algorithms and 'none' are always
	// rejected.
	SigningAlgs []string

	// Clients is the set of client identifiers permitted to present grants from this issuer. Any client when empty.
	Clients []string
}

// IsIDJAGTokenType returns true when typ is the JOSE 'typ' header value of an Identity Assertion JWT Authorization
// Grant, compared case-insensitively with or without the 'application/' prefix per RFC 8725 Section 3.11.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1
func IsIDJAGTokenType(typ string) bool {
	return strings.EqualFold(typ, consts.JSONWebTokenTypeIDJAG) || strings.EqualFold(typ, "application/"+consts.JSONWebTokenTypeIDJAG)
}
