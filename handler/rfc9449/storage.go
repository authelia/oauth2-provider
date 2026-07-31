// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc9449

import (
	"context"
	"time"
)

// DPoPReplayStorage provides replay protection for DPoP proof JWTs keyed by their 'jti' claim within the context the
// 'jti' is required to be unique in.
type DPoPReplayStorage interface {
	// CheckAndSetDPoPProofUsed atomically reports whether a proof has already been used (and not yet expired) and,
	// when it has not, records it as used until exp. The check and the store MUST happen within a single critical
	// section so that concurrent requests presenting the same proof cannot both observe it as unused.
	//
	// Implementations MUST key the record on all three of thumbprint (the RFC 7638 JWK Thumbprint of the proof's
	// public key), htu (the normalized target URI) and jti, rather than on jti alone. RFC 9449 Section 4.2 only
	// requires a 'jti' to be unique "in the same context", and Section 11.1 describes tracking it "in the context of
	// the target URI", so a conforming client may reuse a 'jti' at another endpoint; keying on jti alone would reject
	// that as a replay and would additionally let one client emitting weak 'jti' values deny service to every other
	// client that happens to pick the same value.
	//
	// The narrower key does not weaken replay protection. A replayed proof is presented verbatim, so it carries the
	// same key and the same 'htu', and the strategy separately rejects any proof whose 'htu' does not match the
	// request URI. A proof cannot be re-signed under a different key without the corresponding private key.
	CheckAndSetDPoPProofUsed(ctx context.Context, thumbprint, htu, jti string, exp time.Time) (used bool, err error)
}

// DPoPNonceStorage persists server-provided DPoP nonces.
type DPoPNonceStorage interface {
	// CreateDPoPNonce persists a freshly issued nonce until exp.
	CreateDPoPNonce(ctx context.Context, nonce string, exp time.Time) (err error)

	// IsDPoPNonceValid reports whether a nonce exists and has not expired.
	IsDPoPNonceValid(ctx context.Context, nonce string) (valid bool, err error)
}

// Storage is the combined storage required by the DPoP handler and default strategy.
type Storage interface {
	DPoPReplayStorage
	DPoPNonceStorage
}
