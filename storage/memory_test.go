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

	used, err := s.CheckAndSetDPoPProofUsed(ctx, "jti-1", "jkt-1", "", "POST", htu, time.Now().Add(time.Minute))
	require.NoError(t, err)
	assert.False(t, used)

	used, err = s.CheckAndSetDPoPProofUsed(ctx, "jti-1", "jkt-1", "", "POST", htu, time.Now().Add(time.Minute))
	require.NoError(t, err)
	assert.True(t, used)

	used, err = s.CheckAndSetDPoPProofUsed(ctx, "jti-1", "jkt-1", "", "POST", other, time.Now().Add(time.Minute))
	require.NoError(t, err)
	assert.False(t, used)

	used, err = s.CheckAndSetDPoPProofUsed(ctx, "jti-1", "jkt-1", "", "POST", other, time.Now().Add(time.Minute))
	require.NoError(t, err)
	assert.True(t, used)

	used, err = s.CheckAndSetDPoPProofUsed(ctx, "jti-1", "jkt-1", "", "GET", htu, time.Now().Add(time.Minute))
	require.NoError(t, err)
	assert.False(t, used)

	used, err = s.CheckAndSetDPoPProofUsed(ctx, "jti-1", "jkt-1", "", "GET", htu, time.Now().Add(time.Minute))
	require.NoError(t, err)
	assert.True(t, used)

	used, err = s.CheckAndSetDPoPProofUsed(ctx, "jti-1", "jkt-2", "", "POST", htu, time.Now().Add(time.Minute))
	require.NoError(t, err)
	assert.True(t, used)

	used, err = s.CheckAndSetDPoPProofUsed(ctx, "jti-1", "jkt-1", "nonce-1", "POST", htu, time.Now().Add(time.Minute))
	require.NoError(t, err)
	assert.True(t, used)

	_, err = s.CheckAndSetDPoPProofUsed(ctx, "jti-2", "jkt-1", "", "POST", htu, time.Now().Add(-time.Minute))
	require.NoError(t, err)
	used, err = s.CheckAndSetDPoPProofUsed(ctx, "jti-2", "jkt-1", "", "POST", htu, time.Now().Add(time.Minute))
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

	_, err := s.CheckAndSetDPoPProofUsed(ctx, "expired", "jkt-1", "n-1", "POST", "https://as.example.com/token", time.Now().Add(-time.Minute))
	require.NoError(t, err)
	_, err = s.CheckAndSetDPoPProofUsed(ctx, "live", "jkt-1", "n-1", "POST", "https://as.example.com/token", time.Now().Add(time.Minute))
	require.NoError(t, err)

	assert.NotContains(t, s.DPoPProofJTIs, DPoPProofMarker{JTI: "expired", Method: "POST", URL: "https://as.example.com/token"})
	assert.Contains(t, s.DPoPProofJTIs, DPoPProofMarker{JTI: "live", Method: "POST", URL: "https://as.example.com/token"})
}

func TestMemoryStore_RotateRefreshToken(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	request := &oauth2.Request{ID: "req-id", Session: &oauth2.DefaultSession{}}

	require.NoError(t, s.CreateAccessTokenSession(ctx, "at-sig", request))
	require.NoError(t, s.CreateRefreshTokenSession(ctx, "rt-sig", "at-sig", request))

	assert.Equal(t, "at-sig", s.RefreshTokens["rt-sig"].accessTokenSignature)

	require.NoError(t, s.RotateRefreshToken(ctx, "req-id", "rt-sig"))

	_, err := s.GetRefreshTokenSession(ctx, "rt-sig", nil)
	assert.ErrorIs(t, err, oauth2.ErrInactiveToken)

	_, err = s.GetAccessTokenSession(ctx, "at-sig", nil)
	assert.ErrorIs(t, err, oauth2.ErrNotFound)
}

func TestMemoryStoreClientRegistrationManager(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	client := &oauth2.DefaultClient{ID: "new-client", Scopes: []string{"openid"}}

	require.NoError(t, store.CreateClient(ctx, client))

	// Creating the same id twice must fail.
	require.Error(t, store.CreateClient(ctx, client))

	got, err := store.GetClient(ctx, "new-client")
	require.NoError(t, err)
	assert.Equal(t, oauth2.Arguments{"openid"}, got.GetScopes())

	require.NoError(t, store.UpdateClient(ctx, "new-client", &oauth2.DefaultClient{ID: "new-client", Scopes: []string{"openid", "profile"}}))

	got, err = store.GetClient(ctx, "new-client")
	require.NoError(t, err)
	assert.Equal(t, oauth2.Arguments{"openid", "profile"}, got.GetScopes())

	// Updating an unknown id must fail.
	require.Error(t, store.UpdateClient(ctx, "missing", client))

	require.NoError(t, store.DeleteClient(ctx, "new-client"))

	_, err = store.GetClient(ctx, "new-client")
	require.Error(t, err)

	// Deleting an unknown id must fail.
	require.Error(t, store.DeleteClient(ctx, "new-client"))
}

func TestExampleStoreSupportsDPoP(t *testing.T) {
	ctx := context.Background()
	s := NewExampleStore()

	used, err := s.CheckAndSetDPoPProofUsed(ctx, "jti-1", "jkt-1", "", "POST", "https://as.example.com/token", time.Now().Add(time.Minute))
	require.NoError(t, err)
	assert.False(t, used)

	require.NoError(t, s.CreateDPoPNonce(ctx, "n-1", time.Now().Add(time.Minute)))

	valid, err := s.IsDPoPNonceValid(ctx, "n-1")
	require.NoError(t, err)
	assert.True(t, valid)
}
