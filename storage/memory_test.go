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
	"authelia.com/provider/oauth2/internal"
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

func TestMemoryStoreDecideDeviceCodeSession(t *testing.T) {
	newRequest := func(status oauth2.DeviceAuthorizeStatus) *oauth2.DeviceAuthorizeRequest {
		request := oauth2.NewDeviceAuthorizeRequest()
		request.SetDeviceCodeSignature("device-sig")
		request.SetUserCodeSignature("user-sig")
		request.SetStatus(status)

		return request
	}

	t.Run("ShouldFailWithoutAStoredSession", func(t *testing.T) {
		store := NewMemoryStore()

		assert.ErrorIs(t, store.DecideDeviceCodeSession(t.Context(), "device-sig", newRequest(oauth2.DeviceAuthorizeStatusApproved)), oauth2.ErrNotFound)
	})

	t.Run("ShouldRecordTheFirstDecision", func(t *testing.T) {
		store := NewMemoryStore()

		require.NoError(t, store.CreateDeviceCodeSession(t.Context(), "device-sig", newRequest(oauth2.DeviceAuthorizeStatusNew)))
		require.NoError(t, store.DecideDeviceCodeSession(t.Context(), "device-sig", newRequest(oauth2.DeviceAuthorizeStatusApproved)))

		stored, err := store.GetDeviceCodeSession(t.Context(), "device-sig", nil)
		require.NoError(t, err)
		assert.Equal(t, oauth2.DeviceAuthorizeStatusApproved, stored.GetStatus())
	})

	t.Run("ShouldRefuseASecondDecision", func(t *testing.T) {
		store := NewMemoryStore()

		require.NoError(t, store.CreateDeviceCodeSession(t.Context(), "device-sig", newRequest(oauth2.DeviceAuthorizeStatusNew)))
		require.NoError(t, store.DecideDeviceCodeSession(t.Context(), "device-sig", newRequest(oauth2.DeviceAuthorizeStatusApproved)))

		assert.ErrorIs(t, store.DecideDeviceCodeSession(t.Context(), "device-sig", newRequest(oauth2.DeviceAuthorizeStatusDenied)), oauth2.ErrDeviceAuthorizeDecided)

		stored, err := store.GetDeviceCodeSession(t.Context(), "device-sig", nil)
		require.NoError(t, err)
		assert.Equal(t, oauth2.DeviceAuthorizeStatusApproved, stored.GetStatus())
	})
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

func TestExampleStoreCustomLifespanClient(t *testing.T) {
	client, err := NewExampleStore().GetClient(context.Background(), "custom-lifespan-client")
	require.NoError(t, err)

	c, ok := client.(*oauth2.DefaultClientWithCustomTokenLifespans)
	require.True(t, ok)
	assert.Equal(t, &internal.TestLifespans, c.TokenLifespans)
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

func TestMemoryStore_DeletePARSessionConsumesOnce(t *testing.T) {
	testCases := []struct {
		name  string
		store oauth2.PARStorage
	}{
		{"ShouldConsumeOnceMemoryStore", NewMemoryStore()},
		{"ShouldConsumeOnceHydratingMemoryStore", NewHydratingMemoryStore()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			request := oauth2.NewAuthorizeRequest()
			request.SetSession(&oauth2.DefaultSession{})

			require.NoError(t, tc.store.CreatePARSession(t.Context(), "urn:ietf:params:oauth:request_uri:abc", request))

			for range 2 {
				found, err := tc.store.GetPARSession(t.Context(), "urn:ietf:params:oauth:request_uri:abc")
				require.NoError(t, err)
				require.NotNil(t, found)
			}

			require.NoError(t, tc.store.DeletePARSession(t.Context(), "urn:ietf:params:oauth:request_uri:abc"))
			require.ErrorIs(t, tc.store.DeletePARSession(t.Context(), "urn:ietf:params:oauth:request_uri:abc"), oauth2.ErrNotFound)
		})
	}
}

func TestMemoryStoreScopesJTIs(t *testing.T) {
	exp := time.Now().Add(time.Minute)

	testCases := []struct {
		name  string
		check func(t *testing.T, s *MemoryStore)
	}{
		{
			name: "ShouldScopeClientAssertionJTIsToTheClient",
			check: func(t *testing.T, s *MemoryStore) {
				require.NoError(t, s.ClientAssertionJWTValid(t.Context(), "client-a", "jti"))
				require.NoError(t, s.SetClientAssertionJWT(t.Context(), "client-a", "jti", exp))

				assert.NoError(t, s.ClientAssertionJWTValid(t.Context(), "client-b", "jti"))
				assert.NoError(t, s.SetClientAssertionJWT(t.Context(), "client-b", "jti", exp))

				assert.ErrorIs(t, s.ClientAssertionJWTValid(t.Context(), "client-a", "jti"), oauth2.ErrJTIKnown)
				assert.ErrorIs(t, s.SetClientAssertionJWT(t.Context(), "client-a", "jti", exp), oauth2.ErrJTIKnown)
			},
		},
		{
			name: "ShouldScopeRFC7523JTIsToTheIssuer",
			check: func(t *testing.T, s *MemoryStore) {
				require.NoError(t, s.MarkRFC7523JWTUsedForTime(t.Context(), "a", "b\x00c", exp))

				used, err := s.IsRFC7523JWTUsed(t.Context(), "a\x00b", "c")
				require.NoError(t, err)
				assert.False(t, used)

				used, err = s.IsRFC7523JWTUsed(t.Context(), "a", "b\x00c")
				require.NoError(t, err)
				assert.True(t, used)

				assert.ErrorIs(t, s.MarkRFC7523JWTUsedForTime(t.Context(), "a", "b\x00c", exp), oauth2.ErrJTIKnown)
			},
		},
		{
			name: "ShouldScopeTokenExchangeJTIsToTheIssuer",
			check: func(t *testing.T, s *MemoryStore) {
				require.NoError(t, s.SetTokenExchangeCustomJWT(t.Context(), "https://a.example.com", "jti", exp))

				assert.NoError(t, s.SetTokenExchangeCustomJWT(t.Context(), "https://b.example.com", "jti", exp))
				assert.ErrorIs(t, s.SetTokenExchangeCustomJWT(t.Context(), "https://a.example.com", "jti", exp), oauth2.ErrJTIKnown)
			},
		},
		{
			name: "ShouldSeparateEachPurpose",
			check: func(t *testing.T, s *MemoryStore) {
				require.NoError(t, s.SetClientAssertionJWT(t.Context(), "https://a.example.com", "jti", exp))

				used, err := s.IsRFC7523JWTUsed(t.Context(), "https://a.example.com", "jti")
				require.NoError(t, err)
				assert.False(t, used)

				assert.NoError(t, s.MarkRFC7523JWTUsedForTime(t.Context(), "https://a.example.com", "jti", exp))
				assert.NoError(t, s.SetTokenExchangeCustomJWT(t.Context(), "https://a.example.com", "jti", exp))
			},
		},
		{
			name: "ShouldForgetExpiredJTIs",
			check: func(t *testing.T, s *MemoryStore) {
				require.NoError(t, s.SetClientAssertionJWT(t.Context(), "client", "jti", time.Now().Add(-time.Minute)))

				assert.NoError(t, s.ClientAssertionJWTValid(t.Context(), "client", "jti"))
				assert.NoError(t, s.SetClientAssertionJWT(t.Context(), "client", "jti", exp))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.check(t, NewMemoryStore())
		})
	}
}

func TestMemoryStoreRevokeAccessTokenRevokesEveryTokenForTheRequest(t *testing.T) {
	testCases := []struct {
		name  string
		store accessTokenStore
	}{
		{"ShouldRevokeEveryTokenMemoryStore", NewMemoryStore()},
		{"ShouldRevokeEveryTokenHydratingMemoryStore", NewHydratingMemoryStore()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			request := &oauth2.Request{ID: "hybrid", Session: &oauth2.DefaultSession{Subject: "abc"}}
			other := &oauth2.Request{ID: "other", Session: &oauth2.DefaultSession{Subject: "abc"}}

			require.NoError(t, tc.store.CreateAccessTokenSession(t.Context(), "implicit", request))
			require.NoError(t, tc.store.CreateAccessTokenSession(t.Context(), "code", request))
			require.NoError(t, tc.store.CreateAccessTokenSession(t.Context(), "unrelated", other))

			require.NoError(t, tc.store.RevokeAccessToken(t.Context(), "hybrid"))

			for _, signature := range []string{"implicit", "code"} {
				_, err := tc.store.GetAccessTokenSession(t.Context(), signature, &oauth2.DefaultSession{})
				assert.ErrorIs(t, err, oauth2.ErrNotFound, signature)
			}

			_, err := tc.store.GetAccessTokenSession(t.Context(), "unrelated", &oauth2.DefaultSession{})
			assert.NoError(t, err)
		})
	}
}

func TestMemoryStoreDeleteAccessTokenSessionUnindexesTheSignature(t *testing.T) {
	store := NewMemoryStore()

	request := &oauth2.Request{ID: "req", Session: &oauth2.DefaultSession{}}

	require.NoError(t, store.CreateAccessTokenSession(t.Context(), "a", request))
	require.NoError(t, store.CreateAccessTokenSession(t.Context(), "b", request))
	require.NoError(t, store.DeleteAccessTokenSession(t.Context(), "a"))

	assert.Equal(t, map[string]struct{}{"b": {}}, store.AccessTokenRequestIDs[request.ID])

	require.NoError(t, store.DeleteAccessTokenSession(t.Context(), "b"))

	assert.NotContains(t, store.AccessTokenRequestIDs, request.ID)
}

func TestMemoryStorePrunesExpiredEntriesAtAnInterval(t *testing.T) {
	past, future := time.Now().Add(-time.Minute), time.Now().Add(time.Minute)

	const htu, iss = "https://as.example.com/token", "https://issuer.example.com"

	testCases := []struct {
		name    string
		insert  func(t *testing.T, s *MemoryStore, key string, exp time.Time)
		contain func(s *MemoryStore, key string) bool
		rewind  func(s *MemoryStore)
	}{
		{
			name: "ShouldPruneClientAssertionJTIs",
			insert: func(t *testing.T, s *MemoryStore, key string, exp time.Time) {
				require.NoError(t, s.SetClientAssertionJWT(t.Context(), "client", key, exp))
			},
			contain: func(s *MemoryStore, key string) bool {
				_, ok := s.ClientAssertionJTIs[JTIMarker{Issuer: "client", JTI: key}]
				return ok
			},
			rewind: func(s *MemoryStore) { s.clientAssertionJTIsPruneAt = time.Time{} },
		},
		{
			name: "ShouldPruneRFC7523JTIs",
			insert: func(t *testing.T, s *MemoryStore, key string, exp time.Time) {
				require.NoError(t, s.MarkRFC7523JWTUsedForTime(t.Context(), iss, key, exp))
			},
			contain: func(s *MemoryStore, key string) bool {
				_, ok := s.RFC7523JTIs[JTIMarker{Issuer: iss, JTI: key}]
				return ok
			},
			rewind: func(s *MemoryStore) { s.rfc7523JTIsPruneAt = time.Time{} },
		},
		{
			name: "ShouldPruneTokenExchangeJTIs",
			insert: func(t *testing.T, s *MemoryStore, key string, exp time.Time) {
				require.NoError(t, s.SetTokenExchangeCustomJWT(t.Context(), iss, key, exp))
			},
			contain: func(s *MemoryStore, key string) bool {
				_, ok := s.TokenExchangeJTIs[JTIMarker{Issuer: iss, JTI: key}]
				return ok
			},
			rewind: func(s *MemoryStore) { s.tokenExchangeJTIsPruneAt = time.Time{} },
		},
		{
			name: "ShouldPruneDPoPProofJTIs",
			insert: func(t *testing.T, s *MemoryStore, key string, exp time.Time) {
				_, err := s.CheckAndSetDPoPProofUsed(t.Context(), key, "jkt", "", "POST", htu, exp)
				require.NoError(t, err)
			},
			contain: func(s *MemoryStore, key string) bool {
				_, ok := s.DPoPProofJTIs[DPoPProofMarker{JTI: key, Method: "POST", URL: htu}]
				return ok
			},
			rewind: func(s *MemoryStore) { s.dpopProofJTIsPruneAt = time.Time{} },
		},
		{
			name: "ShouldPruneDPoPNonces",
			insert: func(t *testing.T, s *MemoryStore, key string, exp time.Time) {
				require.NoError(t, s.CreateDPoPNonce(t.Context(), key, exp))
			},
			contain: func(s *MemoryStore, key string) bool {
				_, ok := s.DPoPNonces[key]
				return ok
			},
			rewind: func(s *MemoryStore) { s.dpopNoncesPruneAt = time.Time{} },
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewMemoryStore()

			tc.insert(t, s, "expired", past)
			tc.insert(t, s, "first", future)

			assert.True(t, tc.contain(s, "expired"))

			tc.rewind(s)
			tc.insert(t, s, "second", future)

			assert.False(t, tc.contain(s, "expired"))
			assert.True(t, tc.contain(s, "first"))
			assert.True(t, tc.contain(s, "second"))
		})
	}
}

func TestExampleStoreInitialisesEveryMap(t *testing.T) {
	s := NewExampleStore()

	require.NoError(t, s.CreateClientRegistrationTokenSession(t.Context(), "cr-sig", &oauth2.Request{ID: "cr-req", Session: &oauth2.DefaultSession{}}))

	request := oauth2.NewDeviceAuthorizeRequest()
	request.SetSession(&oauth2.DefaultSession{})
	request.SetDeviceCodeSignature("device")
	request.SetUserCodeSignature("user")

	require.NoError(t, s.CreateDeviceCodeSession(t.Context(), "device", request))
	require.NoError(t, s.InvalidateDeviceCodeSession(t.Context(), "device"))

	assert.Contains(t, s.Clients, "my-client")
	assert.Contains(t, s.Users, "peter")
}

type accessTokenStore interface {
	CreateAccessTokenSession(ctx context.Context, signature string, request oauth2.Requester) error
	GetAccessTokenSession(ctx context.Context, signature string, session oauth2.Session) (oauth2.Requester, error)
	RevokeAccessToken(ctx context.Context, requestID string) error
}
