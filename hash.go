// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
)

// Hasher defines how a oauth2-compatible hasher should look like.
type Hasher interface {
	// Compare compares data with a hash and returns an error
	// if the two do not match.
	Compare(ctx context.Context, hash, data []byte) error

	// Hash creates a hash from data or returns an error.
	Hash(ctx context.Context, data []byte) ([]byte, error)
}
