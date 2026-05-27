// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7523

import (
	"context"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Storage holds information needed to validate jwt assertion in authorization grants.
type Storage interface {
	// GetRFC7523PublicKey returns public key, issued by 'issuer', and assigned for the subject. Public key is used to check
	// the signature of jwt assertion in authorization grants.
	GetRFC7523PublicKey(ctx context.Context, issuer, subject, keyId string) (key *jose.JSONWebKey, err error)

	// GetRFC7523PublicKeys returns public key, set issued by 'issuer', and assigned for the subject.
	GetRFC7523PublicKeys(ctx context.Context, issuer, subject string) (keySet *jose.JSONWebKeySet, err error)

	// GetRFC7523PublicKeyScopes returns the assigned scope for assertion, identified by public key, issued by 'issuer'.
	GetRFC7523PublicKeyScopes(ctx context.Context, issuer, subject, keyId string) (scopes []string, err error)

	// IsRFC7523JWTUsed returns true if the JWT identified by (issuer, jti) has already been seen. Per
	// RFC 7519 §4.1.7 the 'jti' claim is only unique within the issuer, so the lookup MUST be
	// scoped to the issuer rather than the bare jti.
	IsRFC7523JWTUsed(ctx context.Context, issuer, jti string) (used bool, err error)

	// MarkRFC7523JWTUsedForTime marks a JWT identified by (issuer, jti) as used until 'exp'. This helps
	// ensure that JWTs are not replayed by maintaining the set of used (issuer, jti) pairs for
	// the length of time for which the JWT would be considered valid based on the applicable
	// "exp" instant. (https://datatracker.ietf.org/doc/html/rfc7523#section-3)
	MarkRFC7523JWTUsedForTime(ctx context.Context, issuer, jti string, exp time.Time) (err error)
}
