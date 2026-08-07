// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"time"

	"authelia.com/provider/oauth2/internal/consts"
)

// DPoPJWKThumbprintLength is the length of a well-formed 'dpop_jkt' value, being the number of characters a 32 byte
// SHA-256 digest occupies when base64url encoded without padding.
const DPoPJWKThumbprintLength = 43

// IsValidDPoPJWKThumbprint reports whether jkt is a well-formed RFC 9449 Section 10.1 'dpop_jkt' value, which that
// section defines as the RFC 7638 JWK Thumbprint of the proof-of-possession public key computed with SHA-256, the same
// value used for 'jkt' in the 'cnf' claim. Only the encoding can be checked, as the thumbprint of a key the client has
// not yet presented cannot be recomputed.
//
// The client supplies this value directly, so it is validated before being recorded against a grant. An unchecked
// value is stored verbatim for the lifetime of the authorization code and can be of any length, and while a malformed
// one only ever fails to match a proof, there is no reason to carry it that far.
func IsValidDPoPJWKThumbprint(jkt string) bool {
	if len(jkt) != DPoPJWKThumbprintLength {
		return false
	}

	// Decoding covers the base64url alphabet as well as the length, as no other input of this length decodes to a
	// SHA-256 sized digest.
	decoded, err := base64.RawURLEncoding.DecodeString(jkt)

	return err == nil && len(decoded) == sha256.Size
}

// RequestURL reconstructs the RFC 9449 target URI ('htu') from the request, discarding query and fragment. When the
// request did not arrive over TLS directly it falls back to the X-Forwarded-Proto header to determine the scheme;
// deployments MUST therefore ensure that header is set (and any client-supplied value stripped) by a trusted edge
// proxy, otherwise a client could influence the reconstructed htu scheme.
//
// The path is taken in its escaped form. The decoded (*url.URL).Path would silently turn a percent-encoded delimiter
// in the request target into a real one, so a request to '/token%3Fx=1' would reconstruct as '/token?x=1' and compare
// equal to a proof bound to '/token' once the query is discarded.
func RequestURL(r *http.Request) string {
	scheme := consts.SchemeHTTPS

	if r.TLS == nil {
		if proto := r.Header.Get(consts.HeaderXForwardedProto); proto != "" {
			scheme = proto
		} else {
			scheme = consts.SchemeHTTP
		}
	}

	// A request served by net/http always carries a URL, but this is reached from authorization decisions such as the
	// DPoP 'htu' comparison and the bearer credential audience fallback, where a panic would be a worse failure mode
	// than a mismatch. A hand-constructed request with no URL therefore reconstructs to just the scheme and host,
	// which no legitimately issued audience or proof will match.
	if r.URL == nil {
		return scheme + "://" + r.Host
	}

	host := r.Host
	if host == "" {
		host = r.URL.Host
	}

	return scheme + "://" + host + r.URL.EscapedPath()
}

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

// DPoPResourceStrategy is the resource-server half of the RFC 9449 strategy, needed by an endpoint accepting an
// access token as a credential and not declared by DPoPStrategy, the type GetDPoPStrategy returns.
// *rfc9449.DefaultStrategy implements it. The assertion is made at the point of use rather than by widening
// DPoPStrategy, so a deployment supplying its own strategy is not broken by a method it has no bound tokens to serve.
type DPoPResourceStrategy interface {
	// ValidateResourceAccess performs the RFC 9449 7.1/7.2 resource-server checks for a DPoP-bound access token. It
	// verifies the token was presented under the DPoP scheme, that the proof covers this request and this token via
	// the 'ath' claim, and that the proof key is the key the token is bound to.
	ValidateResourceAccess(ctx context.Context, r *http.Request, accessToken, boundJKT string, requireNonce bool) (parsed *DPoPProof, err error)
}

// DPoPBoundSession is implemented by sessions that can be bound to a DPoP proof-of-possession key. The binding is the
// RFC 7638 JWK SHA-256 Thumbprint (jkt) of the client's public key.
type DPoPBoundSession interface {
	// SetDPoPJWKThumbprint records the JWK thumbprint (jkt) the token is bound to.
	SetDPoPJWKThumbprint(jkt string)

	// GetDPoPJWKThumbprint returns the bound JWK thumbprint, or an empty string when the session is not DPoP bound.
	GetDPoPJWKThumbprint() (jkt string)
}
