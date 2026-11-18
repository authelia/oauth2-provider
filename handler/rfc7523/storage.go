// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7523

import (
	"context"
	"time"

	"authelia.com/provider/oauth2"
)

// Storage holds the trusted issuers, subjects and used JWTs of the RFC 7523 JWT authorization grant.
type Storage interface {
	// GetRFC7523TrustedIssuer returns the trust configuration of the issuer, or an error matching oauth2.ErrNotFound
	// when the issuer is not trusted. The Issuer of the result MUST be the issuer requested.
	//
	// An error matching oauth2.ErrNotFound is answered invalid_grant. Any other error, or no trusted issuer and no
	// error, is answered server_error. Implementations MUST translate the not found error of their store, for example
	// a no rows error, to oauth2.ErrNotFound, otherwise an unknown issuer is answered server_error, which reveals which
	// issuers are trusted.
	//
	// It is called before the signature of the assertion is verified, with an issuer the caller chose. Implementations
	// SHOULD take the same time whether or not the issuer is trusted, as the handler cannot hide a difference in lookup
	// time and it reveals which issuers are trusted.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc7523#section-3
	GetRFC7523TrustedIssuer(ctx context.Context, issuer string) (trusted *oauth2.RFC7523TrustedIssuer, err error)

	// ResolveRFC7523Subject returns the local subject for the claims of an assertion. It is called after the signature,
	// claims and replay state of the assertion are validated, and after the 'sub' claim has passed the Subjects of the
	// trusted issuer. The client is nil when the request is not client authenticated, keyID is the 'kid' of the key
	// which verified the assertion, and claims is a copy.
	//
	// A subject that is not empty is the subject of the access token. An empty subject or an error matching
	// oauth2.ErrNotFound is answered invalid_grant. An error matching oauth2.ErrAccessDenied is returned as it is. Any
	// other error is answered server_error.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-chaining-17#section-2.4.2
	ResolveRFC7523Subject(ctx context.Context, client oauth2.Client, trusted *oauth2.RFC7523TrustedIssuer, keyID string, claims map[string]any) (subject string, err error)

	// IsRFC7523JWTUsed returns true if the JWT identified by (issuer, jti) has already been seen. Per
	// RFC 7519 §4.1.7 the 'jti' claim is only unique within the issuer, so the lookup MUST be
	// scoped to the issuer rather than the bare jti.
	IsRFC7523JWTUsed(ctx context.Context, issuer, jti string) (used bool, err error)

	// MarkRFC7523JWTUsedForTime marks a JWT identified by (issuer, jti) as used until 'exp'. This helps
	// ensure that JWTs are not replayed by maintaining the set of used (issuer, jti) pairs for
	// the length of time for which the JWT would be considered valid based on the applicable
	// "exp" instant. (https://datatracker.ietf.org/doc/html/rfc7523#section-3)
	//
	// The mark MUST be atomic and MUST return an error matching oauth2.ErrJTIKnown when the pair is already marked
	// and has not expired, as IsRFC7523JWTUsed alone can not prevent two concurrent requests using the same JWT.
	MarkRFC7523JWTUsedForTime(ctx context.Context, issuer, jti string, exp time.Time) (err error)
}
