// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
)

func TestHydratingMemoryStoreHydratesTheSuppliedSession(t *testing.T) {
	ctx := context.Background()
	store := NewHydratingMemoryStore()

	request := &oauth2.Request{ID: "req-id", Session: &oauth2.DefaultSession{Subject: "abc"}}

	require.NoError(t, store.CreateAccessTokenSession(ctx, "at-sig", request))

	target := &oauth2.DefaultSession{}

	got, err := store.GetAccessTokenSession(ctx, "at-sig", target)
	require.NoError(t, err)

	assert.Same(t, target, got.GetSession())
	assert.Equal(t, "abc", target.Subject)

	plain := NewMemoryStore()
	require.NoError(t, plain.CreateAccessTokenSession(ctx, "at-sig", request))

	plainGot, err := plain.GetAccessTokenSession(ctx, "at-sig", &oauth2.DefaultSession{})
	require.NoError(t, err)
	assert.NotSame(t, target, plainGot.GetSession())
}

func TestHydratingMemoryStoreHydratesClientRegistrationTokenSessions(t *testing.T) {
	ctx := context.Background()
	store := NewHydratingMemoryStore()

	const sharedSignature = "shared-sig"

	atRequest := &oauth2.Request{ID: "at-req-id", Session: &oauth2.DefaultSession{Subject: "at-subject"}}
	crRequest := &oauth2.Request{ID: "cr-req-id", Session: &oauth2.DefaultSession{Subject: "cr-subject"}}

	require.NoError(t, store.CreateAccessTokenSession(ctx, sharedSignature, atRequest))
	require.NoError(t, store.CreateClientRegistrationTokenSession(ctx, sharedSignature, crRequest))

	crTarget := &oauth2.DefaultSession{}

	crGot, err := store.GetClientRegistrationTokenSession(ctx, sharedSignature, crTarget)
	require.NoError(t, err)

	assert.Same(t, crTarget, crGot.GetSession())
	assert.Equal(t, "cr-subject", crTarget.Subject)

	atTarget := &oauth2.DefaultSession{}

	atGot, err := store.GetAccessTokenSession(ctx, sharedSignature, atTarget)
	require.NoError(t, err)

	assert.Same(t, atTarget, atGot.GetSession())
	assert.Equal(t, "at-subject", atTarget.Subject)
}

func TestHydratingMemoryStoreHydratesRefreshTokenSessions(t *testing.T) {
	ctx := context.Background()
	store := NewHydratingMemoryStore()

	const issued, rebound = "issued-subject", "rebound-subject"

	stored := &oauth2.DefaultSession{Subject: issued}

	require.NoError(t, store.CreateRefreshTokenSession(ctx, "rt-sig", "at-sig", &oauth2.AccessRequest{Request: oauth2.Request{ID: "req-id", Session: stored}}))

	stored.Subject = "mutated"

	target := &oauth2.DefaultSession{}

	got, err := store.GetRefreshTokenSession(ctx, "rt-sig", target)
	require.NoError(t, err)

	assert.Same(t, target, got.GetSession())
	assert.Equal(t, issued, target.Subject)

	require.NoError(t, store.UpdateRefreshTokenSession(ctx, "rt-sig", &oauth2.Request{ID: "req-id", Session: &oauth2.DefaultSession{Subject: rebound}}))

	got, err = store.GetRefreshTokenSession(ctx, "rt-sig", &oauth2.DefaultSession{})
	require.NoError(t, err)

	assert.Equal(t, rebound, got.GetSession().(*oauth2.DefaultSession).Subject)

	require.NoError(t, store.RevokeRefreshToken(ctx, "req-id"))

	got, err = store.GetRefreshTokenSession(ctx, "rt-sig", &oauth2.DefaultSession{})
	require.ErrorIs(t, err, oauth2.ErrInactiveToken)

	assert.Equal(t, rebound, got.GetSession().(*oauth2.DefaultSession).Subject)

	_, err = store.GetRefreshTokenSession(ctx, "missing", &oauth2.DefaultSession{})
	assert.ErrorIs(t, err, oauth2.ErrNotFound)

	assert.ErrorIs(t, store.UpdateRefreshTokenSession(ctx, "missing", &oauth2.Request{ID: "req-id"}), oauth2.ErrNotFound)
}

func TestHydratingMemoryStoreHydratesAuthorizeCodeAndPKCESessions(t *testing.T) {
	ctx := context.Background()

	testCases := []struct {
		name   string
		create func(store *HydratingMemoryStore, signature string, request oauth2.Requester) error
		get    func(store *HydratingMemoryStore, signature string, session oauth2.Session) (oauth2.Requester, error)
	}{
		{
			name: "AuthorizeCode",
			create: func(store *HydratingMemoryStore, signature string, request oauth2.Requester) error {
				return store.CreateAuthorizeCodeSession(ctx, signature, request)
			},
			get: func(store *HydratingMemoryStore, signature string, session oauth2.Session) (oauth2.Requester, error) {
				return store.GetAuthorizeCodeSession(ctx, signature, session)
			},
		},
		{
			name: "PKCE",
			create: func(store *HydratingMemoryStore, signature string, request oauth2.Requester) error {
				return store.CreatePKCERequestSession(ctx, signature, request)
			},
			get: func(store *HydratingMemoryStore, signature string, session oauth2.Session) (oauth2.Requester, error) {
				return store.GetPKCERequestSession(ctx, signature, session)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("ShouldHydrateTheSuppliedSession", func(t *testing.T) {
				store := NewHydratingMemoryStore()

				require.NoError(t, tc.create(store, "sig", &oauth2.AuthorizeRequest{Request: oauth2.Request{ID: "req-id", Session: &oauth2.DefaultSession{Subject: "abc"}}}))

				target := &oauth2.DefaultSession{}

				got, err := tc.get(store, "sig", target)
				require.NoError(t, err)

				assert.Same(t, target, got.GetSession())
				assert.Equal(t, "abc", target.Subject)
			})

			t.Run("ShouldNotHydrateASessionReplacedByNone", func(t *testing.T) {
				store := NewHydratingMemoryStore()

				require.NoError(t, tc.create(store, "sig", &oauth2.Request{ID: "first", Session: &oauth2.DefaultSession{Subject: "abc"}}))
				require.NoError(t, tc.create(store, "sig", &oauth2.Request{ID: "second"}))

				target := &oauth2.DefaultSession{}

				got, err := tc.get(store, "sig", target)
				require.NoError(t, err)

				assert.Equal(t, "second", got.GetID())
				assert.Nil(t, got.GetSession())
				assert.Empty(t, target.Subject)
			})
		})
	}
}
