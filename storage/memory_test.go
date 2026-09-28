// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"strconv"
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

func TestMemoryStoreRotateRefreshTokenReportsAnInactiveToken(t *testing.T) {
	store := NewMemoryStore()

	request := &oauth2.Request{ID: "rotated-request", Client: &oauth2.DefaultClient{ID: "client"}, Session: &oauth2.DefaultSession{}}

	require.NoError(t, store.CreateRefreshTokenSession(t.Context(), "rt-sig", "", request))
	require.NoError(t, store.RotateRefreshToken(t.Context(), request.ID, "rt-sig"))

	assert.ErrorIs(t, store.RotateRefreshToken(t.Context(), request.ID, "rt-sig"), oauth2.ErrInactiveToken)
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

	t.Run("ShouldRejectCreatingTheSameIdentifierTwice", func(t *testing.T) {
		assert.ErrorIs(t, store.CreateClient(ctx, client), oauth2.ErrInvalidClientMetadata)
	})

	t.Run("ShouldReadBackTheCreatedClient", func(t *testing.T) {
		got, err := store.GetClient(ctx, "new-client")
		require.NoError(t, err)

		assert.Equal(t, oauth2.Arguments{"openid"}, got.GetScopes())
	})

	t.Run("ShouldUpdateTheStoredClient", func(t *testing.T) {
		require.NoError(t, store.UpdateClient(ctx, "new-client", &oauth2.DefaultClient{ID: "new-client", Scopes: []string{"openid", "profile"}}))

		got, err := store.GetClient(ctx, "new-client")
		require.NoError(t, err)

		assert.Equal(t, oauth2.Arguments{"openid", "profile"}, got.GetScopes())
	})

	t.Run("ShouldRejectUpdatingAnUnknownIdentifier", func(t *testing.T) {
		assert.ErrorIs(t, store.UpdateClient(ctx, "missing", client), oauth2.ErrNotFound)
	})

	t.Run("ShouldRejectAnUpdateWhoseClientIdentifierDisagreesWithTheKey", func(t *testing.T) {
		assert.ErrorIs(t, store.UpdateClient(ctx, "new-client", &oauth2.DefaultClient{ID: "other-client"}), oauth2.ErrInvalidClientMetadata)

		got, err := store.GetClient(ctx, "new-client")
		require.NoError(t, err)

		assert.Equal(t, oauth2.Arguments{"openid", "profile"}, got.GetScopes())
	})

	t.Run("ShouldDeleteTheStoredClient", func(t *testing.T) {
		require.NoError(t, store.DeleteClient(ctx, "new-client"))

		_, err := store.GetClient(ctx, "new-client")
		assert.ErrorIs(t, err, oauth2.ErrNotFound)
	})

	t.Run("ShouldRejectDeletingAnUnknownIdentifier", func(t *testing.T) {
		assert.ErrorIs(t, store.DeleteClient(ctx, "new-client"), oauth2.ErrNotFound)
	})
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

func TestMemoryStoreClientRegistrationTokenSessions(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	request := &oauth2.Request{ID: "req-id", Session: &oauth2.DefaultSession{Subject: "abc"}}

	require.NoError(t, store.CreateClientRegistrationTokenSession(ctx, "cr-sig", request))

	got, err := store.GetClientRegistrationTokenSession(ctx, "cr-sig", nil)
	require.NoError(t, err)
	assert.Equal(t, "req-id", got.GetID())

	_, err = store.GetAccessTokenSession(ctx, "cr-sig", nil)
	assert.ErrorIs(t, err, oauth2.ErrNotFound)

	require.NoError(t, store.DeleteClientRegistrationTokenSession(ctx, "cr-sig"))

	_, err = store.GetClientRegistrationTokenSession(ctx, "cr-sig", nil)
	assert.ErrorIs(t, err, oauth2.ErrNotFound)
}

func TestMemoryStore_RevokeRefreshTokenSynchronisesRefreshTokens(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	const n = 64

	for i := 0; i < n; i++ {
		id := strconv.Itoa(i)
		request := &oauth2.Request{ID: "req-" + id, Session: &oauth2.DefaultSession{}}

		require.NoError(t, s.CreateAccessTokenSession(ctx, "at-"+id, request))
		require.NoError(t, s.CreateRefreshTokenSession(ctx, "rt-"+id, "at-"+id, request))
	}

	var wg sync.WaitGroup

	wg.Add(2 * n)

	for i := 0; i < n; i++ {
		id := strconv.Itoa(i)

		go func() {
			defer wg.Done()

			_ = s.RevokeRefreshToken(ctx, "req-"+id)
		}()

		go func() {
			defer wg.Done()

			_, _ = s.GetRefreshTokenSession(ctx, "rt-"+id, nil)
		}()
	}

	wg.Wait()
}

func TestMemoryStore_CreateDeviceCodeSessionRejectsDuplicateUserCode(t *testing.T) {
	store := NewMemoryStore()

	newRequest := func(deviceCodeSignature string) *oauth2.DeviceAuthorizeRequest {
		r := oauth2.NewDeviceAuthorizeRequest()
		r.SetSession(&oauth2.DefaultSession{})
		r.SetDeviceCodeSignature(deviceCodeSignature)
		r.SetUserCodeSignature("user")

		return r
	}

	require.NoError(t, store.CreateDeviceCodeSession(t.Context(), "first", newRequest("first")))
	require.ErrorIs(t, store.CreateDeviceCodeSession(t.Context(), "second", newRequest("second")), oauth2.ErrDuplicateUserCode)

	found, err := store.GetDeviceCodeSessionByUserCode(t.Context(), "user", &oauth2.DefaultSession{})
	require.NoError(t, err)
	assert.Equal(t, "first", found.GetDeviceCodeSignature())

	_, err = store.GetDeviceCodeSession(t.Context(), "second", &oauth2.DefaultSession{})
	require.ErrorIs(t, err, oauth2.ErrNotFound)
}

func TestMemoryStore_InvalidateDeviceCodeSessionKeepsTheRequester(t *testing.T) {
	store := NewMemoryStore()

	request := oauth2.NewDeviceAuthorizeRequest()
	request.SetID("request")
	request.SetSession(&oauth2.DefaultSession{})
	request.SetDeviceCodeSignature("device")
	request.SetUserCodeSignature("user")

	require.NoError(t, store.CreateDeviceCodeSession(t.Context(), "device", request))
	require.NoError(t, store.InvalidateDeviceCodeSession(t.Context(), "device"))

	found, err := store.GetDeviceCodeSession(t.Context(), "device", &oauth2.DefaultSession{})
	require.ErrorIs(t, err, oauth2.ErrInvalidatedDeviceCode)
	require.NotNil(t, found)
	assert.Equal(t, "request", found.GetID())

	found, err = store.GetDeviceCodeSessionByUserCode(t.Context(), "user", &oauth2.DefaultSession{})
	require.ErrorIs(t, err, oauth2.ErrInvalidatedDeviceCode)
	require.NotNil(t, found)
	assert.Equal(t, "request", found.GetID())

	require.ErrorIs(t, store.InvalidateDeviceCodeSession(t.Context(), "device"), oauth2.ErrInvalidatedDeviceCode)
	require.ErrorIs(t, store.CreateDeviceCodeSession(t.Context(), "other", request), oauth2.ErrDuplicateUserCode)
}

func TestMemoryStore_SetTokenLifespans(t *testing.T) {
	lifespan := time.Hour
	lifespans := &oauth2.ClientLifespanConfig{ClientCredentialsGrantAccessTokenLifespan: &lifespan}

	t.Run("ShouldReplaceTheStoredClient", func(t *testing.T) {
		store := NewExampleStore()

		before, err := store.GetClient(t.Context(), "custom-lifespan-client")
		require.NoError(t, err)

		previous := before.(*oauth2.DefaultClientWithCustomTokenLifespans).GetTokenLifespans()

		require.NoError(t, store.SetTokenLifespans("custom-lifespan-client", lifespans))

		after, err := store.GetClient(t.Context(), "custom-lifespan-client")
		require.NoError(t, err)

		assert.Equal(t, lifespans, after.(*oauth2.DefaultClientWithCustomTokenLifespans).GetTokenLifespans())
		assert.Same(t, previous, before.(*oauth2.DefaultClientWithCustomTokenLifespans).GetTokenLifespans())
		assert.Equal(t, before.GetID(), after.GetID())
	})

	t.Run("ShouldRejectUnknownClient", func(t *testing.T) {
		store := NewExampleStore()

		require.ErrorIs(t, store.SetTokenLifespans("unknown", lifespans), oauth2.ErrNotFound)
	})

	t.Run("ShouldRejectClientWithoutCustomLifespans", func(t *testing.T) {
		store := NewExampleStore()

		require.Error(t, store.SetTokenLifespans("my-client", lifespans))
	})

	t.Run("ShouldNotRaceWithReaders", func(t *testing.T) {
		store := NewExampleStore()

		var wg sync.WaitGroup

		wg.Add(2)

		go func() {
			defer wg.Done()

			for range 100 {
				client, err := store.GetClient(context.Background(), "custom-lifespan-client")
				if err != nil {
					continue
				}

				oauth2.GetEffectiveLifespan(client, oauth2.GrantTypeClientCredentials, oauth2.AccessToken, time.Minute)
			}
		}()

		go func() {
			defer wg.Done()

			for range 100 {
				_ = store.SetTokenLifespans("custom-lifespan-client", lifespans)
			}
		}()

		wg.Wait()
	})
}
