// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"

	"golang.org/x/crypto/bcrypt"

	"authelia.com/provider/oauth2/internal/errorsx"
)

const DefaultBCryptWorkFactor = 12

// BCrypt implements the Hasher interface by using BCrypt.
type BCrypt struct {
	Config interface {
		BCryptCostProvider
	}
}

func (b *BCrypt) Hash(ctx context.Context, data []byte) ([]byte, error) {
	wf := b.Config.GetBCryptCost(ctx)
	if wf == 0 {
		wf = DefaultBCryptWorkFactor
	}
	s, err := bcrypt.GenerateFromPassword(data, wf)
	if err != nil {
		return nil, errorsx.WithStack(err)
	}
	return s, nil
}

func (b *BCrypt) Compare(ctx context.Context, hash, data []byte) error {
	if err := bcrypt.CompareHashAndPassword(hash, data); err != nil {
		return errorsx.WithStack(err)
	}
	return nil
}
