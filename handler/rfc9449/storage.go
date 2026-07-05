// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc9449

import (
	"context"
	"time"
)

// DPoPReplayStorage provides replay protection for DPoP proof JWTs keyed by their 'jti' claim.
type DPoPReplayStorage interface {
	// SetDPoPProofUsed records a proof 'jti' as used until exp.
	SetDPoPProofUsed(ctx context.Context, jti string, exp time.Time) (err error)

	// IsDPoPProofUsed reports whether a proof 'jti' has already been used (and not yet expired).
	IsDPoPProofUsed(ctx context.Context, jti string) (used bool, err error)
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
