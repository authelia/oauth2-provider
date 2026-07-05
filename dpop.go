// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"time"
)

// DPoPProof is the validated result of a RFC 9449 DPoP proof JWT.
type DPoPProof struct {
	// Thumbprint is the RFC 7638 base64url SHA-256 JWK Thumbprint (jkt) of the proof's public key.
	Thumbprint string

	// ID is the 'jti' claim.
	ID string

	// Method is the 'htm' claim (the HTTP method).
	Method string

	// URL is the 'htu' claim (the HTTP target URI without query or fragment).
	URL string

	// Nonce is the 'nonce' claim, if present.
	Nonce string

	// AccessTokenHash is the 'ath' claim, if present. Unused on the authorization-server side.
	AccessTokenHash string

	// IssuedAt is the 'iat' claim.
	IssuedAt time.Time
}

// DPoPStrategy validates DPoP proofs and manages server-provided nonces per RFC 9449.
type DPoPStrategy interface {
	// ValidateDPoPProof parses and validates the compact proof JWT against the request method and url. When
	// requireNonce is true, a valid 'nonce' claim is mandatory. It returns the validated proof or an error that wraps
	// ErrInvalidDPoPProof or ErrUseDPoPNonce.
	ValidateDPoPProof(ctx context.Context, method, url, proof string, requireNonce bool) (parsed *DPoPProof, err error)

	// NewDPoPNonce issues, persists, and returns a fresh server nonce.
	NewDPoPNonce(ctx context.Context) (nonce string, err error)

	// ValidateDPoPNonce returns nil when the nonce exists and is unexpired, otherwise an error wrapping ErrUseDPoPNonce.
	ValidateDPoPNonce(ctx context.Context, nonce string) (err error)
}

// DPoPBoundSession is implemented by sessions that can be bound to a DPoP proof-of-possession key. The binding is the
// RFC 7638 JWK SHA-256 Thumbprint (jkt) of the client's public key.
type DPoPBoundSession interface {
	// SetDPoPJWKThumbprint records the JWK thumbprint (jkt) the token is bound to.
	SetDPoPJWKThumbprint(jkt string)

	// GetDPoPJWKThumbprint returns the bound JWK thumbprint, or an empty string when the session is not DPoP bound.
	GetDPoPJWKThumbprint() (jkt string)
}
