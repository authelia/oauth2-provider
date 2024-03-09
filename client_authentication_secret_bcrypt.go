// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"authelia.com/provider/oauth2/internal/errorsx"
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

func (s *BCryptClientSecret) IsPlainText() (is bool) {
	return false
}

func (s *BCryptClientSecret) GetPlainTextValue() (secret []byte, err error) {
	return nil, fmt.Errorf("this secret doesn't support plaintext")
}

func (s *BCryptClientSecret) Compare(ctx context.Context, secret []byte) (err error) {
	if err = bcrypt.CompareHashAndPassword(s.value, secret); err != nil {
		return errorsx.WithStack(err)
	}

	return nil
}
