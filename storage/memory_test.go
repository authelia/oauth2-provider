// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
)

func TestMemoryStore_Authenticate(t *testing.T) {
	type args struct {
		in0    context.Context
		name   string
		secret string
	}

	testCases := []struct {
		name  string
		users map[string]MemoryUserRelation
		args  args
		err   string
	}{
		{
			name: "ShouldHandleInvalidPassword",
			args: args{
				name:   "peter",
				secret: "invalid",
			},
			users: map[string]MemoryUserRelation{
				"peter": {
					Username: "peter",
					Password: "secret",
				},
			},
			err: "Could not find the requested resource(s). Invalid credentials.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := &MemoryStore{
				Users:      tc.users,
				usersMutex: sync.RWMutex{},
			}

			_, err := s.Authenticate(tc.args.in0, tc.args.name, tc.args.secret)

			if len(tc.err) == 0 {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)
			}
		})
	}
}

func TestMemoryStoreDPoP(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	const htu, other = "https://as.example.com/token", "https://as.example.com/introspect"

	used, err := s.CheckAndSetDPoPProofUsed(ctx, "jkt-1", htu, "jti-1", time.Now().Add(time.Minute))
	require.NoError(t, err)
	assert.False(t, used)

	used, err = s.CheckAndSetDPoPProofUsed(ctx, "jkt-1", htu, "jti-1", time.Now().Add(time.Minute))
	require.NoError(t, err)
	assert.True(t, used)

	used, err = s.CheckAndSetDPoPProofUsed(ctx, "jkt-2", htu, "jti-1", time.Now().Add(time.Minute))
	require.NoError(t, err)
	assert.False(t, used)

	used, err = s.CheckAndSetDPoPProofUsed(ctx, "jkt-2", htu, "jti-1", time.Now().Add(time.Minute))
	require.NoError(t, err)
	assert.True(t, used)

	used, err = s.CheckAndSetDPoPProofUsed(ctx, "jkt-1", other, "jti-1", time.Now().Add(time.Minute))
	require.NoError(t, err)
	assert.False(t, used)

	_, err = s.CheckAndSetDPoPProofUsed(ctx, "jkt-1", htu, "jti-2", time.Now().Add(-time.Minute))
	require.NoError(t, err)
	used, err = s.CheckAndSetDPoPProofUsed(ctx, "jkt-1", htu, "jti-2", time.Now().Add(time.Minute))
	require.NoError(t, err)
	assert.False(t, used)

	valid, err := s.IsDPoPNonceValid(ctx, "n-1")
	require.NoError(t, err)
	assert.False(t, valid)

	require.NoError(t, s.CreateDPoPNonce(ctx, "n-1", time.Now().Add(time.Minute)))
	valid, err = s.IsDPoPNonceValid(ctx, "n-1")
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestMemoryStoreDPoPPrunesExpiredRecords(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	require.NoError(t, s.CreateDPoPNonce(ctx, "expired", time.Now().Add(-time.Minute)))
	require.NoError(t, s.CreateDPoPNonce(ctx, "live", time.Now().Add(time.Minute)))

	assert.NotContains(t, s.DPoPNonces, "expired")
	assert.Contains(t, s.DPoPNonces, "live")

	_, err := s.CheckAndSetDPoPProofUsed(ctx, "jkt-1", "https://as.example.com/token", "expired", time.Now().Add(-time.Minute))
	require.NoError(t, err)
	_, err = s.CheckAndSetDPoPProofUsed(ctx, "jkt-1", "https://as.example.com/token", "live", time.Now().Add(time.Minute))
	require.NoError(t, err)

	assert.NotContains(t, s.DPoPProofJTIs, DPoPProofMarker{Thumbprint: "jkt-1", URL: "https://as.example.com/token", JTI: "expired"})
	assert.Contains(t, s.DPoPProofJTIs, DPoPProofMarker{Thumbprint: "jkt-1", URL: "https://as.example.com/token", JTI: "live"})
}

func TestExampleStoreSupportsDPoP(t *testing.T) {
	ctx := context.Background()
	s := NewExampleStore()

	used, err := s.CheckAndSetDPoPProofUsed(ctx, "jkt-1", "https://as.example.com/token", "jti-1", time.Now().Add(time.Minute))
	require.NoError(t, err)
	assert.False(t, used)

	require.NoError(t, s.CreateDPoPNonce(ctx, "n-1", time.Now().Add(time.Minute)))

	valid, err := s.IsDPoPNonceValid(ctx, "n-1")
	require.NoError(t, err)
	assert.True(t, valid)
}
