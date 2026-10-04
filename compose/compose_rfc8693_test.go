// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/storage"
)

func TestRFC8693RefreshTokenTypeFactoryWiresTokenRevocationStorage(t *testing.T) {
	store := storage.NewMemoryStore()

	testCases := []struct {
		name    string
		storage any
		panics  bool
	}{
		{name: "ShouldWireTheStorageAsTokenRevocationStorage", storage: store},
		{name: "ShouldPanicWhenTheStorageCannotRevokeTokens", storage: &rfc8693OnlyStorage{}, panics: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &oauth2.Config{GlobalSecret: []byte("some-cool-secret-that-is-32bytes")}
			strategy := NewOAuth2HMACStrategy(config)

			if tc.panics {
				assert.Panics(t, func() { RFC8693RefreshTokenTypeFactory(config, tc.storage, strategy) })

				return
			}

			handler, ok := RFC8693RefreshTokenTypeFactory(config, tc.storage, strategy).(*rfc8693.RefreshTokenTypeHandler)
			require.True(t, ok)
			assert.Same(t, store, handler.TokenRevocationStorage)
		})
	}
}

func TestRFC8693TokenExchangeGrantFactoryWiresCustomJWTStorage(t *testing.T) {
	store := storage.NewMemoryStore()

	testCases := []struct {
		name     string
		storage  any
		expected rfc8693.CustomJWTStorage
	}{
		{name: "ShouldWireTheStorageAsCustomJWTStorage", storage: store, expected: store},
		{name: "ShouldLeaveTheStorageUnsetWhenItCannotMarkCustomJWTs", storage: struct{}{}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &oauth2.Config{GlobalSecret: []byte("some-cool-secret-that-is-32bytes")}

			handler, ok := RFC8693TokenExchangeGrantFactory(config, tc.storage, nil).(*rfc8693.TokenExchangeGrantHandler)
			require.True(t, ok)
			assert.Equal(t, tc.expected, handler.Storage)
		})
	}
}

type rfc8693OnlyStorage struct {
	rfc8693.Storage
}
