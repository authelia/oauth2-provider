// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
)

func TestMemoryStoreGrant(t *testing.T) {
	stores := []struct {
		name  string
		store func() oauth2.GrantManagementStorage
	}{
		{name: "MemoryStore", store: func() oauth2.GrantManagementStorage { return NewMemoryStore() }},
		{name: "HydratingMemoryStore", store: func() oauth2.GrantManagementStorage { return NewHydratingMemoryStore() }},
		{name: "ZeroValueMemoryStore", store: func() oauth2.GrantManagementStorage { return &MemoryStore{} }},
	}

	testCases := []struct {
		name  string
		check func(t *testing.T, s oauth2.GrantManagementStorage)
	}{
		{
			name: "ShouldCreateGetUpdateDelete",
			check: func(t *testing.T, s oauth2.GrantManagementStorage) {
				ctx := t.Context()

				require.NoError(t, s.CreateGrant(ctx, newTestGrant("g1")))

				got, err := s.GetGrant(ctx, "g1")
				require.NoError(t, err)
				assert.Equal(t, newTestGrant("g1"), got)

				updated := newTestGrant("g1")
				updated.Permissions = oauth2.GrantPermissions{Scopes: []oauth2.GrantScope{{Scope: "write"}}}
				updated.RequestIDs = []string{"request-2"}
				updated.UpdatedBy = "authorization_server"
				updated.ExpiresAt = time.Time{}

				require.NoError(t, s.UpdateGrant(ctx, updated))

				updated.RequestIDs = newTestGrant("g1").RequestIDs

				got, err = s.GetGrant(ctx, "g1")
				require.NoError(t, err)
				assert.Equal(t, updated, got)

				require.NoError(t, s.AppendGrantRequestID(ctx, "g1", "request-3"))

				ids, err := s.DeleteGrant(ctx, "g1")
				require.NoError(t, err)
				assert.Equal(t, append(newTestGrant("g1").RequestIDs, "request-3"), ids)

				_, err = s.GetGrant(ctx, "g1")
				assert.True(t, errors.Is(err, oauth2.ErrNotFound))

				assert.True(t, errors.Is(s.AppendGrantRequestID(ctx, "g1", "request-4"), oauth2.ErrNotFound))

				_, err = s.ReplaceGrantRequestIDs(ctx, "g1", nil)
				assert.True(t, errors.Is(err, oauth2.ErrNotFound))
			},
		},
		{
			name: "ShouldReturnNotFoundForUnknownGrant",
			check: func(t *testing.T, s oauth2.GrantManagementStorage) {
				ctx := t.Context()

				got, err := s.GetGrant(ctx, "unknown")
				assert.Nil(t, got)
				assert.True(t, errors.Is(err, oauth2.ErrNotFound))

				assert.True(t, errors.Is(s.UpdateGrant(ctx, newTestGrant("unknown")), oauth2.ErrNotFound))

				ids, err := s.DeleteGrant(ctx, "unknown")
				assert.Nil(t, ids)
				assert.True(t, errors.Is(err, oauth2.ErrNotFound))
			},
		},
		{
			name: "ShouldRejectInvalidOrDuplicateGrant",
			check: func(t *testing.T, s oauth2.GrantManagementStorage) {
				ctx := t.Context()

				assert.True(t, errors.Is(s.CreateGrant(ctx, nil), oauth2.ErrServerError))
				assert.True(t, errors.Is(s.CreateGrant(ctx, &oauth2.Grant{}), oauth2.ErrServerError))
				assert.True(t, errors.Is(s.UpdateGrant(ctx, nil), oauth2.ErrServerError))

				require.NoError(t, s.CreateGrant(ctx, newTestGrant("g1")))

				duplicate := newTestGrant("g1")
				duplicate.Subject = "mallory"

				assert.True(t, errors.Is(s.CreateGrant(ctx, duplicate), oauth2.ErrServerError))

				got, err := s.GetGrant(ctx, "g1")
				require.NoError(t, err)
				assert.Equal(t, "alice", got.Subject)
			},
		},
		{
			name: "ShouldNotAliasReturnedGrant",
			check: func(t *testing.T, s oauth2.GrantManagementStorage) {
				ctx := t.Context()

				require.NoError(t, s.CreateGrant(ctx, newTestGrant("g1")))

				got, err := s.GetGrant(ctx, "g1")
				require.NoError(t, err)

				mutateTestGrant(got)

				got, err = s.GetGrant(ctx, "g1")
				require.NoError(t, err)
				assert.Equal(t, newTestGrant("g1"), got)
			},
		},
		{
			name: "ShouldNotAliasStoredGrant",
			check: func(t *testing.T, s oauth2.GrantManagementStorage) {
				ctx := t.Context()

				created := newTestGrant("g1")

				require.NoError(t, s.CreateGrant(ctx, created))

				mutateTestGrant(created)

				got, err := s.GetGrant(ctx, "g1")
				require.NoError(t, err)
				assert.Equal(t, newTestGrant("g1"), got)

				updated := newTestGrant("g1")

				require.NoError(t, s.UpdateGrant(ctx, updated))

				mutateTestGrant(updated)

				got, err = s.GetGrant(ctx, "g1")
				require.NoError(t, err)
				assert.Equal(t, newTestGrant("g1"), got)
			},
		},
		{
			name: "ShouldAppendARequestIDOnce",
			check: func(t *testing.T, s oauth2.GrantManagementStorage) {
				ctx := t.Context()

				created := newTestGrant("g1")

				require.NoError(t, s.CreateGrant(ctx, created))

				require.NoError(t, s.AppendGrantRequestID(ctx, "g1", "appended"))
				require.NoError(t, s.AppendGrantRequestID(ctx, "g1", "appended"))
				require.NoError(t, s.AppendGrantRequestID(ctx, "g1", created.RequestIDs[0]))

				expected := newTestGrant("g1")
				expected.RequestIDs = append(expected.RequestIDs, "appended")

				got, err := s.GetGrant(ctx, "g1")
				require.NoError(t, err)
				assert.Equal(t, expected, got)
				assert.Equal(t, newTestGrant("g1"), created)
			},
		},
		{
			name: "ShouldNotAppendARequestIDToAMissingGrant",
			check: func(t *testing.T, s oauth2.GrantManagementStorage) {
				assert.ErrorIs(t, s.AppendGrantRequestID(t.Context(), "missing", "appended"), oauth2.ErrNotFound)
			},
		},
		{
			name: "ShouldReplaceRequestIDs",
			check: func(t *testing.T, s oauth2.GrantManagementStorage) {
				ctx := t.Context()

				require.NoError(t, s.CreateGrant(ctx, newTestGrant("g1")))
				require.NoError(t, s.AppendGrantRequestID(ctx, "g1", "appended"))

				replacement := []string{"replacement"}

				previous, err := s.ReplaceGrantRequestIDs(ctx, "g1", replacement)
				require.NoError(t, err)
				assert.Equal(t, append(newTestGrant("g1").RequestIDs, "appended"), previous)

				replacement[0], previous[0] = "mutated", "mutated"

				expected := newTestGrant("g1")
				expected.RequestIDs = []string{"replacement"}

				got, err := s.GetGrant(ctx, "g1")
				require.NoError(t, err)
				assert.Equal(t, expected, got)

				previous, err = s.ReplaceGrantRequestIDs(ctx, "g1", nil)
				require.NoError(t, err)
				assert.Equal(t, []string{"replacement"}, previous)
			},
		},
		{
			name: "ShouldNotReplaceTheRequestIDsOfAMissingGrant",
			check: func(t *testing.T, s oauth2.GrantManagementStorage) {
				previous, err := s.ReplaceGrantRequestIDs(t.Context(), "missing", []string{"replacement"})

				assert.ErrorIs(t, err, oauth2.ErrNotFound)
				assert.Nil(t, previous)
			},
		},
		{
			name: "ShouldRetainConcurrentlyAppendedRequestIDs",
			check: func(t *testing.T, s oauth2.GrantManagementStorage) {
				ctx := t.Context()

				created := newTestGrant("g1")

				require.NoError(t, s.CreateGrant(ctx, created))

				expected := slices.Clone(created.RequestIDs)

				var wg sync.WaitGroup

				for i := range 64 {
					id := fmt.Sprintf("concurrent-%d", i)
					expected = append(expected, id)

					wg.Go(func() {
						assert.NoError(t, s.AppendGrantRequestID(ctx, "g1", id))
					})
				}

				wg.Wait()

				got, err := s.GetGrant(ctx, "g1")
				require.NoError(t, err)
				assert.ElementsMatch(t, expected, got.RequestIDs)
			},
		},
	}

	for _, store := range stores {
		t.Run(store.name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					tc.check(t, store.store())
				})
			}
		})
	}
}

func newTestGrant(id string) *oauth2.Grant {
	return &oauth2.Grant{
		ID:       id,
		ClientID: "client-1",
		Subject:  "alice",
		Permissions: oauth2.GrantPermissions{
			Scopes:               []oauth2.GrantScope{{Scope: "read", Resource: []string{"https://rs1"}}},
			Audience:             []string{"https://rs1"},
			Claims:               []string{"email"},
			AuthorizationDetails: oauth2.AuthorizationDetails{{Type: "account_information", Actions: []string{"read"}}},
		},
		CreatedAt:  time.Unix(1700000000, 0).UTC(),
		UpdatedAt:  time.Unix(1700000100, 0).UTC(),
		ExpiresAt:  time.Unix(1700003600, 0).UTC(),
		UpdatedBy:  "client",
		RequestIDs: []string{"request-1"},
	}
}

func mutateTestGrant(grant *oauth2.Grant) {
	grant.Subject = "mallory"
	grant.RequestIDs[0] = "mutated"
	grant.Permissions.Scopes[0].Scope = "mutated"
	grant.Permissions.Scopes[0].Resource[0] = "https://mutated"
	grant.Permissions.Audience[0] = "https://mutated"
	grant.Permissions.Claims[0] = "mutated"
	grant.Permissions.AuthorizationDetails[0].Actions[0] = "mutated"
}
