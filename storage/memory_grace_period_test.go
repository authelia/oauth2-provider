// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
)

func TestRotateRefreshTokenWithGracePeriod(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	deadline := start.Add(time.Minute)

	testCases := []struct {
		name   string
		have   func(t *testing.T, store gracePeriodStore, now *time.Time)
		active []string
		access []string
		err    error
	}{
		{
			name:   "ShouldKeepTheRefreshTokenActiveUntilTheDeadline",
			have:   func(t *testing.T, store gracePeriodStore, now *time.Time) { *now = deadline.Add(-time.Nanosecond) },
			active: []string{"rt-1", "rt-2"},
			access: []string{"at-2"},
		},
		{
			name:   "ShouldDeactivateTheRefreshTokenAtTheDeadline",
			have:   func(t *testing.T, store gracePeriodStore, now *time.Time) { *now = deadline },
			active: []string{"rt-2"},
			access: []string{"at-2"},
			err:    oauth2.ErrInactiveToken,
		},
		{
			name: "ShouldNotReplaceTheDeadline",
			have: func(t *testing.T, store gracePeriodStore, now *time.Time) {
				require.NoError(t, store.RotateRefreshTokenWithGracePeriod(t.Context(), "req-id", "rt-1", deadline.Add(time.Hour)))

				*now = deadline
			},
			active: []string{"rt-2"},
			access: []string{"at-2"},
			err:    oauth2.ErrInactiveToken,
		},
		{
			name: "ShouldDeactivateARefreshTokenRotatedWithoutAGracePeriod",
			have: func(t *testing.T, store gracePeriodStore, now *time.Time) {
				require.NoError(t, store.RotateRefreshToken(t.Context(), "req-id", "rt-1"))
			},
			active: []string{"rt-2"},
			err:    oauth2.ErrInactiveToken,
		},
		{
			name: "ShouldDeactivateEveryRefreshTokenOfARevokedRequest",
			have: func(t *testing.T, store gracePeriodStore, now *time.Time) {
				require.NoError(t, store.RevokeRefreshToken(t.Context(), "req-id"))
			},
			access: []string{"at-2"},
			err:    oauth2.ErrInactiveToken,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			forEachGracePeriodStore(t, func(t *testing.T, store gracePeriodStore, memory *MemoryStore) {
				now := start

				memory.Clock = func() time.Time { return now }

				for _, n := range []string{"1", "2"} {
					request := &oauth2.Request{ID: "req-id", Client: &oauth2.DefaultClient{ID: "foo"}, Session: &oauth2.DefaultSession{Subject: "peter"}}

					require.NoError(t, store.CreateAccessTokenSession(t.Context(), "at-"+n, request))
					require.NoError(t, store.CreateRefreshTokenSession(t.Context(), "rt-"+n, "at-"+n, request))
				}

				require.NoError(t, store.RotateRefreshTokenWithGracePeriod(t.Context(), "req-id", "rt-1", deadline))

				tc.have(t, store, &now)

				for _, signature := range []string{"rt-1", "rt-2"} {
					session := &oauth2.DefaultSession{}

					request, err := store.GetRefreshTokenSession(t.Context(), signature, session)

					if slices.Contains(tc.active, signature) {
						require.NoError(t, err)
					} else {
						require.ErrorIs(t, err, oauth2.ErrInactiveToken)
					}

					require.NotNil(t, request)
					assert.Equal(t, "req-id", request.GetID())
					assert.Equal(t, "peter", request.GetSession().GetSubject())
				}

				for _, signature := range []string{"at-1", "at-2"} {
					_, err := store.GetAccessTokenSession(t.Context(), signature, &oauth2.DefaultSession{})

					if slices.Contains(tc.access, signature) {
						assert.NoError(t, err)
					} else {
						assert.ErrorIs(t, err, oauth2.ErrNotFound)
					}
				}

				err := store.RotateRefreshTokenWithGracePeriod(t.Context(), "req-id", "rt-1", deadline.Add(time.Hour))

				if tc.err != nil {
					assert.ErrorIs(t, err, tc.err)
				} else {
					assert.NoError(t, err)
				}
			})
		})
	}
}

func TestRotateRefreshTokenWithGracePeriodReportsAMissingToken(t *testing.T) {
	forEachGracePeriodStore(t, func(t *testing.T, store gracePeriodStore, _ *MemoryStore) {
		request := &oauth2.Request{ID: "req-id", Client: &oauth2.DefaultClient{ID: "foo"}, Session: &oauth2.DefaultSession{}}

		require.NoError(t, store.CreateRefreshTokenSession(t.Context(), "rt-sig", "", request))

		assert.ErrorIs(t, store.RotateRefreshTokenWithGracePeriod(t.Context(), "req-id", "other-sig", time.Now().Add(time.Minute)), oauth2.ErrNotFound)

		_, err := store.GetRefreshTokenSession(t.Context(), "rt-sig", &oauth2.DefaultSession{})
		assert.NoError(t, err)
	})
}

func TestRotateRefreshTokenDeactivatesARefreshTokenWithinItsGracePeriod(t *testing.T) {
	forEachGracePeriodStore(t, func(t *testing.T, store gracePeriodStore, _ *MemoryStore) {
		request := &oauth2.Request{ID: "req-id", Client: &oauth2.DefaultClient{ID: "foo"}, Session: &oauth2.DefaultSession{}}

		require.NoError(t, store.CreateRefreshTokenSession(t.Context(), "rt-1", "", request))
		require.NoError(t, store.CreateRefreshTokenSession(t.Context(), "rt-2", "", request))
		require.NoError(t, store.RotateRefreshTokenWithGracePeriod(t.Context(), "req-id", "rt-1", time.Now().Add(time.Hour)))
		require.NoError(t, store.RotateRefreshToken(t.Context(), "req-id", "rt-1"))

		_, err := store.GetRefreshTokenSession(t.Context(), "rt-1", &oauth2.DefaultSession{})
		assert.ErrorIs(t, err, oauth2.ErrInactiveToken)

		_, err = store.GetRefreshTokenSession(t.Context(), "rt-2", &oauth2.DefaultSession{})
		assert.NoError(t, err)
	})
}

func TestRevokeRefreshTokenDeactivatesTheGrantWhenTheLatestRefreshTokenIsDeleted(t *testing.T) {
	forEachGracePeriodStore(t, func(t *testing.T, store gracePeriodStore, _ *MemoryStore) {
		request := &oauth2.Request{ID: "req-id", Client: &oauth2.DefaultClient{ID: "foo"}, Session: &oauth2.DefaultSession{}}

		require.NoError(t, store.CreateRefreshTokenSession(t.Context(), "rt-1", "", request))
		require.NoError(t, store.RotateRefreshTokenWithGracePeriod(t.Context(), "req-id", "rt-1", time.Now().Add(time.Hour)))
		require.NoError(t, store.CreateRefreshTokenSession(t.Context(), "rt-2", "", request))
		require.NoError(t, store.CreateRefreshTokenSession(t.Context(), "rt-3", "", request))
		require.NoError(t, store.DeleteRefreshTokenSession(t.Context(), "rt-3"))

		_, err := store.GetRefreshTokenSession(t.Context(), "rt-1", &oauth2.DefaultSession{})
		require.NoError(t, err)

		assert.ErrorIs(t, store.RevokeRefreshToken(t.Context(), "req-id"), oauth2.ErrNotFound)

		for _, signature := range []string{"rt-1", "rt-2"} {
			_, err = store.GetRefreshTokenSession(t.Context(), signature, &oauth2.DefaultSession{})
			assert.ErrorIs(t, err, oauth2.ErrInactiveToken, signature)
		}

		_, err = store.GetRefreshTokenSession(t.Context(), "rt-3", &oauth2.DefaultSession{})
		assert.ErrorIs(t, err, oauth2.ErrNotFound)
	})
}

type gracePeriodStore interface {
	CreateAccessTokenSession(ctx context.Context, signature string, request oauth2.Requester) (err error)
	GetAccessTokenSession(ctx context.Context, signature string, session oauth2.Session) (request oauth2.Requester, err error)
	CreateRefreshTokenSession(ctx context.Context, signature, accessSignature string, request oauth2.Requester) (err error)
	GetRefreshTokenSession(ctx context.Context, signature string, session oauth2.Session) (request oauth2.Requester, err error)
	RotateRefreshToken(ctx context.Context, requestID, signature string) (err error)
	RotateRefreshTokenWithGracePeriod(ctx context.Context, requestID, signature string, deadline time.Time) (err error)
	RevokeRefreshToken(ctx context.Context, requestID string) (err error)
	DeleteRefreshTokenSession(ctx context.Context, signature string) (err error)
}

func forEachGracePeriodStore(t *testing.T, test func(t *testing.T, store gracePeriodStore, memory *MemoryStore)) {
	t.Helper()

	t.Run("MemoryStore", func(t *testing.T) {
		store := NewMemoryStore()

		test(t, store, store)
	})

	t.Run("HydratingMemoryStore", func(t *testing.T) {
		store := NewHydratingMemoryStore()

		test(t, store, store.MemoryStore)
	})
}
