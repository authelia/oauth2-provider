// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7523

import (
	"authelia.com/provider/jose"
	"authelia.com/provider/jose/jwt"

	"authelia.com/provider/oauth2"
)

// IsIDJAGAssertion returns true when the JOSE 'typ' header of assertion identifies an Identity Assertion JWT
// Authorization Grant, which this handler leaves to the handler for that profile.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4.1
func IsIDJAGAssertion(assertion string) bool {
	token, err := jwt.ParseSigned(assertion, assertionAlgorithms)
	if err != nil {
		return false
	}

	for _, header := range token.Headers {
		if typ, _ := header.ExtraHeaders[jose.HeaderType].(string); oauth2.IsIDJAGTokenType(typ) {
			return true
		}
	}

	return false
}
