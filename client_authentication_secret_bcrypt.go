// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"authelia.com/provider/oauth2/x/errorsx"
)

const DefaultBCryptWorkFactor = 12

// NewBCryptClientSecret returns a new BCryptClientSecret given a hash.
func NewBCryptClientSecret(hash string) *BCryptClientSecret {
	return &BCryptClientSecret{value: []byte(hash)}
}

// NewBCryptClientSecretPlain returns a new BCryptClientSecret given a plaintext secret.
func NewBCryptClientSecretPlain(rawSecret string, cost int) (secret *BCryptClientSecret, err error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(rawSecret), cost)
	if err != nil {
		return nil, err
	}

	return &BCryptClientSecret{value: hashed}, nil
}

type BCryptClientSecret struct {
	value []byte
}

// IsPlainText returns false as a bcrypt digest is not usable as a plaintext secret.
func (s *BCryptClientSecret) IsPlainText() (is bool) {
	return false
}

// GetPlainTextValue always returns an error as the plaintext value can't be recovered from a bcrypt digest.
func (s *BCryptClientSecret) GetPlainTextValue() (secret []byte, err error) {
	return nil, fmt.Errorf("this secret doesn't support plaintext")
}

// Compare returns nil if the given secret matches the bcrypt digest, otherwise it returns an error.
func (s *BCryptClientSecret) Compare(ctx context.Context, secret []byte) (err error) {
	if err = bcrypt.CompareHashAndPassword(s.value, secret); err != nil {
		return errorsx.WithStack(err)
	}

	return nil
}

// Valid returns true if the secret is not nil and has a value.
func (s *BCryptClientSecret) Valid() (valid bool) {
	return s != nil && len(s.value) != 0
}
