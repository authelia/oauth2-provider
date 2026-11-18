// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7523

// Session must be implemented by the session if RFC7523 is to be supported.
type Session interface {
	// SetSubject sets the session's subject.
	SetSubject(subject string)
}

// GrantClaimsSession may be implemented by the session to receive the verified claims of the redeemed JWT
// authorization grant, 'act' included. The handler writes none of them to the access token: transcribing the claims of
// another trust domain is left to the application.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-chaining-17#section-2.5
type GrantClaimsSession interface {
	// SetRFC7523GrantClaims sets the verified claims of the redeemed JWT authorization grant.
	SetRFC7523GrantClaims(claims map[string]any)
}
