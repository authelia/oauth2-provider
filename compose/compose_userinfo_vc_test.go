// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/verifiable"
	"authelia.com/provider/oauth2/storage"
)

func TestOIDCUserinfoVerifiableCredentialFactory(t *testing.T) {
	t.Run("ShouldPanicWithAClearMessageWithoutANonceManager", func(t *testing.T) {
		assert.PanicsWithValue(t, "oauth2: OIDCUserinfoVerifiableCredentialFactory requires a storage implementing verifiable.NonceManager, but it was not provided", func() {
			OIDCUserinfoVerifiableCredentialFactory(&oauth2.Config{}, storage.NewMemoryStore(), nil)
		})
	})

	t.Run("ShouldUseTheStorageAsTheNonceManager", func(t *testing.T) {
		store := &nonceManagingStore{MemoryStore: storage.NewMemoryStore()}

		handler, ok := OIDCUserinfoVerifiableCredentialFactory(&oauth2.Config{}, store, nil).(*verifiable.Handler)

		assert.True(t, ok)
		assert.Same(t, store, handler.NonceManager)
	})
}

type nonceManagingStore struct {
	*storage.MemoryStore
}

func (s *nonceManagingStore) NewNonce(_ context.Context, _ string, _ time.Time) (string, error) {
	return "nonce", nil
}

func (s *nonceManagingStore) IsNonceValid(_ context.Context, _, _ string) error {
	return nil
}
