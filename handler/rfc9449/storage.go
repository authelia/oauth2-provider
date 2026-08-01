// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc9449

import (
	"context"
	"time"
)

// DPoPReplayStorage provides replay protection for DPoP proof JWTs keyed by their 'jti' claim within the request
// context the 'jti' is required to be unique in.
type DPoPReplayStorage interface {
	// CheckAndSetDPoPProofUsed atomically reports whether a proof has already been used (and not yet expired) and,
	// when it has not, records it as used until exp. The check and the store MUST happen within a single critical
	// section so that concurrent requests presenting the same proof cannot both observe it as unused.
	//
	// Implementations MUST key the record on at least jti and htu (the normalized target URI), never on jti alone.
	// RFC 9449 Section 4.2 requires a 'jti' to be unique only "in the same context", and Section 11.1 recommends
	// tracking it "in the context of the target URI", so a conforming client may reuse a 'jti' against a different
	// endpoint and keying on jti alone would reject that as a replay.
	//
	// Implementations are additionally given jkt (the RFC 7638 JWK Thumbprint of the proof's public key), nonce (the
	// 'nonce' claim, empty when the proof carries none) and htm (the HTTP method), and MAY include any of them in the
	// key. Widening the key cannot weaken replay protection, because a replayed proof is presented verbatim and so
	// carries every one of these fields unchanged; none can be altered without the corresponding private key. It only
	// ever admits presentations that are not replays:
	//
	//   - jkt distinguishes key holders. Without it the 'jti' namespace is shared by every client, so one client
	//     emitting weak 'jti' values denies service to every other client that happens to pick the same value.
	//     Deployments serving mutually distrusting clients should prefer including it.
	//   - htm and nonce are separately validated against the actual request before this is reached, so neither can be
	//     varied to evade the check. Including nonce lets a client answer a DPoP-Nonce challenge by re-signing with
	//     the new nonce and the same 'jti'.
	//
	// ParseProof bounds both claims via JTIMaxLength and NonceMaxLength, following the Section 11.1 advice to reject
	// unnecessarily large values so that tracked records cannot exhaust memory.
	CheckAndSetDPoPProofUsed(ctx context.Context, jti, jkt, nonce, htm, htu string, exp time.Time) (used bool, err error)
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
