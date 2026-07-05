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
	// CheckAndSetDPoPProofUsed atomically reports whether a proof 'jti' has already been used (and not yet expired)
	// and, when it has not, records it as used until exp. The check and the store MUST happen within a single critical
	// section so that concurrent requests presenting the same 'jti' cannot both observe it as unused.
	CheckAndSetDPoPProofUsed(ctx context.Context, jti string, exp time.Time) (used bool, err error)
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
