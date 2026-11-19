// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
)

func TestMemoryStoreDeviceCode(t *testing.T) {
	stores := []struct {
		name string
		new  func() deviceCodeTestStore
	}{
		{"MemoryStore", func() deviceCodeTestStore { return NewMemoryStore() }},
		{"HydratingMemoryStore", func() deviceCodeTestStore { return NewHydratingMemoryStore() }},
	}

	for _, sc := range stores {
		t.Run(sc.name, func(t *testing.T) {
			ctx := t.Context()

			t.Run("ShouldWriteOnlyThePollingState", func(t *testing.T) {
				store := sc.new()

				require.NoError(t, store.CreateDeviceCodeSession(ctx, "device", newDeviceCodeTestRequest()))

				stale := getDeviceCodeTestRequest(t, store)

				decided := getDeviceCodeTestRequest(t, store)
				decided.SetStatus(oauth2.DeviceAuthorizeStatusDenied)
				decided.SetSession(&oauth2.DefaultSession{Subject: "john"})

				require.NoError(t, store.DecideDeviceCodeSession(ctx, "device", decided))

				polled := time.Now().UTC().Truncate(time.Second)

				stale.SetLastChecked(polled)
				stale.SetPollingInterval(15 * time.Second)
				stale.SetSlowDownCount(1)

				require.NoError(t, store.UpdateDeviceCodeSessionPolling(ctx, "device", stale))

				actual := getDeviceCodeTestRequest(t, store)

				assert.Equal(t, oauth2.DeviceAuthorizeStatusDenied, actual.GetStatus())
				assert.Equal(t, "john", actual.GetSession().GetSubject())
				assert.Equal(t, polled, actual.GetLastChecked())
				assert.Equal(t, 15*time.Second, actual.GetPollingInterval())
				assert.Equal(t, 1, actual.GetSlowDownCount())
			})

			t.Run("ShouldKeepThePollingStateOnDecision", func(t *testing.T) {
				store := sc.new()

				require.NoError(t, store.CreateDeviceCodeSession(ctx, "device", newDeviceCodeTestRequest()))

				decided := getDeviceCodeTestRequest(t, store)
				decided.SetStatus(oauth2.DeviceAuthorizeStatusApproved)

				polled := time.Now().UTC().Truncate(time.Second)

				poll := getDeviceCodeTestRequest(t, store)
				poll.SetLastChecked(polled)
				poll.SetPollingInterval(15 * time.Second)
				poll.SetSlowDownCount(1)

				require.NoError(t, store.UpdateDeviceCodeSessionPolling(ctx, "device", poll))
				require.NoError(t, store.DecideDeviceCodeSession(ctx, "device", decided))

				actual := getDeviceCodeTestRequest(t, store)

				assert.Equal(t, oauth2.DeviceAuthorizeStatusApproved, actual.GetStatus())
				assert.Equal(t, polled, actual.GetLastChecked())
				assert.Equal(t, 15*time.Second, actual.GetPollingInterval())
				assert.Equal(t, 1, actual.GetSlowDownCount())
			})

			t.Run("ShouldNotMutateARequestAlreadyReturned", func(t *testing.T) {
				store := sc.new()

				require.NoError(t, store.CreateDeviceCodeSession(ctx, "device", newDeviceCodeTestRequest()))

				held, err := store.GetDeviceCodeSession(ctx, "device", &oauth2.DefaultSession{})
				require.NoError(t, err)

				poll := getDeviceCodeTestRequest(t, store)
				poll.SetSlowDownCount(1)

				require.NoError(t, store.UpdateDeviceCodeSessionPolling(ctx, "device", poll))
				require.NoError(t, store.ClaimDeviceCodeSession(ctx, "device", "alice"))

				assert.Equal(t, oauth2.DeviceAuthorizeStatusNew, held.GetStatus())
				assert.Empty(t, held.(oauth2.DeviceAuthorizeClaimRequester).GetClaimSubject())
				assert.Zero(t, held.(oauth2.DeviceAuthorizePollingRequester).GetSlowDownCount())

				actual := getDeviceCodeTestRequest(t, store)

				assert.Equal(t, oauth2.DeviceAuthorizeStatusClaimed, actual.GetStatus())
				assert.Equal(t, "alice", actual.GetClaimSubject())
				assert.Equal(t, 1, actual.GetSlowDownCount())
			})

			t.Run("ShouldIgnoreAPollOfAnUnknownSession", func(t *testing.T) {
				store := sc.new()

				require.NoError(t, store.UpdateDeviceCodeSessionPolling(ctx, "device", newDeviceCodeTestRequest()))

				_, err := store.GetDeviceCodeSession(ctx, "device", &oauth2.DefaultSession{})

				assert.ErrorIs(t, err, oauth2.ErrNotFound)
			})

			t.Run("ShouldClaim", func(t *testing.T) {
				testCases := []struct {
					name     string
					setup    func(t *testing.T, store deviceCodeTestStore)
					subject  string
					expected error
					claimed  string
					status   oauth2.DeviceAuthorizeStatus
				}{
					{
						name:    "ShouldClaimAnUnclaimedSession",
						subject: "john",
						claimed: "john",
						status:  oauth2.DeviceAuthorizeStatusClaimed,
					},
					{
						name: "ShouldAcceptTheSameSubjectAgain",
						setup: func(t *testing.T, store deviceCodeTestStore) {
							require.NoError(t, store.ClaimDeviceCodeSession(t.Context(), "device", "john"))
						},
						subject: "john",
						claimed: "john",
						status:  oauth2.DeviceAuthorizeStatusClaimed,
					},
					{
						name: "ShouldRefuseAnotherSubject",
						setup: func(t *testing.T, store deviceCodeTestStore) {
							require.NoError(t, store.ClaimDeviceCodeSession(t.Context(), "device", "john"))
						},
						subject:  "jane",
						expected: oauth2.ErrUserCodeClaimed,
						claimed:  "john",
						status:   oauth2.DeviceAuthorizeStatusClaimed,
					},
					{
						name: "ShouldRefuseADecidedSession",
						setup: func(t *testing.T, store deviceCodeTestStore) {
							decided := getDeviceCodeTestRequest(t, store)
							decided.SetStatus(oauth2.DeviceAuthorizeStatusApproved)

							require.NoError(t, store.DecideDeviceCodeSession(t.Context(), "device", decided))
						},
						subject:  "john",
						expected: oauth2.ErrDeviceAuthorizeDecided,
						status:   oauth2.DeviceAuthorizeStatusApproved,
					},
				}

				for _, tc := range testCases {
					t.Run(tc.name, func(t *testing.T) {
						store := sc.new()

						require.NoError(t, store.CreateDeviceCodeSession(ctx, "device", newDeviceCodeTestRequest()))

						if tc.setup != nil {
							tc.setup(t, store)
						}

						err := store.ClaimDeviceCodeSession(ctx, "device", tc.subject)

						if tc.expected == nil {
							require.NoError(t, err)
						} else {
							require.ErrorIs(t, err, tc.expected)
						}

						actual := getDeviceCodeTestRequest(t, store)

						assert.Equal(t, tc.claimed, actual.GetClaimSubject())
						assert.Equal(t, tc.status, actual.GetStatus())
					})
				}
			})

			t.Run("ShouldRefuseToClaimAnInvalidatedSession", func(t *testing.T) {
				store := sc.new()

				require.NoError(t, store.CreateDeviceCodeSession(ctx, "device", newDeviceCodeTestRequest()))
				require.NoError(t, store.InvalidateDeviceCodeSession(ctx, "device"))

				assert.ErrorIs(t, store.ClaimDeviceCodeSession(ctx, "device", "john"), oauth2.ErrDeviceAuthorizeDecided)
			})

			t.Run("ShouldRefuseToClaimAnUnknownSession", func(t *testing.T) {
				assert.ErrorIs(t, sc.new().ClaimDeviceCodeSession(ctx, "device", "john"), oauth2.ErrNotFound)
			})
		})
	}
}

func TestHydratingMemoryStoreDeviceCode(t *testing.T) {
	ctx := t.Context()

	t.Run("ShouldDecoupleTheStoredRequestFromTheCaller", func(t *testing.T) {
		store := NewHydratingMemoryStore()
		request := newDeviceCodeTestRequest()

		require.NoError(t, store.CreateDeviceCodeSession(ctx, "device", request))

		request.SetStatus(oauth2.DeviceAuthorizeStatusApproved)
		request.GetSession().(*oauth2.DefaultSession).Subject = "mutated"

		for _, get := range []func(session oauth2.Session) (oauth2.DeviceAuthorizeRequester, error){
			func(session oauth2.Session) (oauth2.DeviceAuthorizeRequester, error) {
				return store.GetDeviceCodeSession(ctx, "device", session)
			},
			func(session oauth2.Session) (oauth2.DeviceAuthorizeRequester, error) {
				return store.GetDeviceCodeSessionByUserCode(ctx, "user", session)
			},
		} {
			session := &oauth2.DefaultSession{Subject: "caller"}

			actual, err := get(session)
			require.NoError(t, err)

			assert.Equal(t, oauth2.DeviceAuthorizeStatusNew, actual.GetStatus())
			assert.Same(t, session, actual.GetSession())
			assert.Empty(t, session.Subject)

			actual.SetStatus(oauth2.DeviceAuthorizeStatusDenied)
		}

		assert.Equal(t, oauth2.DeviceAuthorizeStatusNew, getDeviceCodeTestRequest(t, store).GetStatus())
	})

	t.Run("ShouldReplaceTheWholeSessionOnUpdate", func(t *testing.T) {
		store := NewHydratingMemoryStore()

		require.NoError(t, store.CreateDeviceCodeSession(ctx, "device", newDeviceCodeTestRequest()))

		update := getDeviceCodeTestRequest(t, store)
		update.SetStatus(oauth2.DeviceAuthorizeStatusApproved)
		update.SetSession(&oauth2.DefaultSession{Subject: "john"})

		require.NoError(t, store.UpdateDeviceCodeSession(ctx, "device", update))

		actual := getDeviceCodeTestRequest(t, store)

		assert.Equal(t, oauth2.DeviceAuthorizeStatusApproved, actual.GetStatus())
		assert.Equal(t, "john", actual.GetSession().GetSubject())
	})

	t.Run("ShouldNotStoreAnUpdateOfAnUnknownSession", func(t *testing.T) {
		store := NewHydratingMemoryStore()

		require.NoError(t, store.UpdateDeviceCodeSession(ctx, "device", newDeviceCodeTestRequest()))

		_, err := store.GetDeviceCodeSession(ctx, "device", &oauth2.DefaultSession{})

		assert.ErrorIs(t, err, oauth2.ErrNotFound)
	})

	t.Run("ShouldNotStoreTheSessionOfARefusedDecision", func(t *testing.T) {
		store := NewHydratingMemoryStore()

		require.NoError(t, store.CreateDeviceCodeSession(ctx, "device", newDeviceCodeTestRequest()))

		first := getDeviceCodeTestRequest(t, store)
		first.SetStatus(oauth2.DeviceAuthorizeStatusDenied)
		first.SetSession(&oauth2.DefaultSession{Subject: "john"})

		second := getDeviceCodeTestRequest(t, store)
		second.SetStatus(oauth2.DeviceAuthorizeStatusApproved)
		second.SetSession(&oauth2.DefaultSession{Subject: "jane"})

		require.NoError(t, store.DecideDeviceCodeSession(ctx, "device", first))
		require.ErrorIs(t, store.DecideDeviceCodeSession(ctx, "device", second), oauth2.ErrDeviceAuthorizeDecided)

		actual := getDeviceCodeTestRequest(t, store)

		assert.Equal(t, oauth2.DeviceAuthorizeStatusDenied, actual.GetStatus())
		assert.Equal(t, "john", actual.GetSession().GetSubject())
	})

	t.Run("ShouldReturnTheRequestOfAnInvalidatedSession", func(t *testing.T) {
		store := NewHydratingMemoryStore()

		require.NoError(t, store.CreateDeviceCodeSession(ctx, "device", newDeviceCodeTestRequest()))
		require.NoError(t, store.InvalidateDeviceCodeSession(ctx, "device"))

		actual, err := store.GetDeviceCodeSession(ctx, "device", &oauth2.DefaultSession{})

		require.ErrorIs(t, err, oauth2.ErrInvalidatedDeviceCode)
		assert.Equal(t, "device", actual.GetDeviceCodeSignature())
	})
}

type deviceCodeTestStore interface {
	CreateDeviceCodeSession(ctx context.Context, signature string, request oauth2.DeviceAuthorizeRequester) (err error)
	UpdateDeviceCodeSession(ctx context.Context, signature string, request oauth2.DeviceAuthorizeRequester) (err error)
	DecideDeviceCodeSession(ctx context.Context, signature string, request oauth2.DeviceAuthorizeRequester) (err error)
	UpdateDeviceCodeSessionPolling(ctx context.Context, signature string, request oauth2.DeviceAuthorizeRequester) (err error)
	ClaimDeviceCodeSession(ctx context.Context, signature string, subject string) (err error)
	GetDeviceCodeSession(ctx context.Context, signature string, session oauth2.Session) (request oauth2.DeviceAuthorizeRequester, err error)
	GetDeviceCodeSessionByUserCode(ctx context.Context, signature string, session oauth2.Session) (request oauth2.DeviceAuthorizeRequester, err error)
	InvalidateDeviceCodeSession(ctx context.Context, signature string) (err error)
}

func newDeviceCodeTestRequest() (request *oauth2.DeviceAuthorizeRequest) {
	request = oauth2.NewDeviceAuthorizeRequest()
	request.Client = &oauth2.DefaultClient{ID: "client"}
	request.SetSession(&oauth2.DefaultSession{})
	request.SetDeviceCodeSignature("device")
	request.SetUserCodeSignature("user")
	request.SetStatus(oauth2.DeviceAuthorizeStatusNew)

	return request
}

func getDeviceCodeTestRequest(t *testing.T, store deviceCodeTestStore) (request *oauth2.DeviceAuthorizeRequest) {
	t.Helper()

	stored, err := store.GetDeviceCodeSession(t.Context(), "device", &oauth2.DefaultSession{})
	require.NoError(t, err)

	request, ok := stored.(*oauth2.DeviceAuthorizeRequest)
	require.True(t, ok)

	clone := *request

	return &clone
}
