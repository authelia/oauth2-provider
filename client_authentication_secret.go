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

// ClientSecret is a service interface for client secret comparisons and functionality.
type ClientSecret interface {
	// Compare is the primary function of the interface which is used to compare this ClientSecret to the form input.
	// This function SHOULD return nil if the secret input matches the expected value, otherwise it should return an
	// error.
	Compare(ctx context.Context, secret []byte) (err error)

	// IsPlainText is a utility function to determine if this secret is in a plaintext format making it usable for the
	// client_secret_jwt authentication method.
	IsPlainText() (is bool)

	// GetPlainTextValue is a utility function to return the secret in the plaintext format making it usable for the
	// client_secret_jwt authentication method.
	GetPlainTextValue() (secret []byte, err error)
}
