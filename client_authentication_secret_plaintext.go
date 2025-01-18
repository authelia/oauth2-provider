// Copyright © 2023 Ory Corp
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

func (s *PlainTextClientSecret) IsPlainText() (is bool) {
	return true
}

func (s *PlainTextClientSecret) GetPlainTextValue() (secret []byte, err error) {
	return s.value, nil
}

func (s *PlainTextClientSecret) Compare(ctx context.Context, secret []byte) (err error) {
	if subtle.ConstantTimeCompare(s.value, secret) == 0 {
		return errorsx.WithStack(fmt.Errorf("secrets don't match"))
	}

	return nil
}

func (s *PlainTextClientSecret) Valid() (valid bool) {
	return s != nil && len(s.value) != 0
}
