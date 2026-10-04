// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"crypto/subtle"
	"fmt"

	"authelia.com/provider/oauth2/x/errorsx"
)

// NewPlainTextClientSecret returns a new PlainTextClientSecret given a value.
func NewPlainTextClientSecret(value string) *PlainTextClientSecret {
	return &PlainTextClientSecret{value: []byte(value)}
}

type PlainTextClientSecret struct {
	value []byte
}

// IsPlainText returns true as the secret is held as plaintext.
func (s *PlainTextClientSecret) IsPlainText() (is bool) {
	return true
}

// GetPlainTextValue returns the plaintext secret.
func (s *PlainTextClientSecret) GetPlainTextValue() (secret []byte, err error) {
	return s.value, nil
}

// Compare returns nil if the given secret matches the plaintext secret using a constant time comparison, otherwise it
// returns an error.
func (s *PlainTextClientSecret) Compare(ctx context.Context, secret []byte) (err error) {
	if subtle.ConstantTimeCompare(s.value, secret) == 0 {
		return errorsx.WithStack(fmt.Errorf("secrets don't match"))
	}

	return nil
}

// Valid returns true if the secret is not nil and has a value.
func (s *PlainTextClientSecret) Valid() (valid bool) {
	return s != nil && len(s.value) != 0
}
