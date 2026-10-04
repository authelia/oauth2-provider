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
	// Implementations MUST key the record on at least jti and htu (the normalized target URI), never on jti alone, as
	// a 'jti' is unique only in the context of the target URI.
	//
	// Implementations MAY also include any of jkt (the RFC 7638 JWK Thumbprint of the proof's public key), nonce (the
	// 'nonce' claim, empty when the proof carries none) and htm (the HTTP method) in the key. Without jkt the 'jti'
	// namespace is shared by every client. ParseProof bounds jti and nonce via JTIMaxLength and NonceMaxLength.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9449#section-4.2
	// See: https://www.rfc-editor.org/rfc/rfc9449#section-11.1
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
