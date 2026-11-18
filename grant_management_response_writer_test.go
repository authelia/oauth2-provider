// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestRevokeGrant(t *testing.T) {
	for _, sc := range grantManagementAPIStores {
		t.Run(sc.name, func(t *testing.T) {
			t.Run("ShouldRevokeTheTokensAndDeleteTheGrant", func(t *testing.T) {
				h := newGrantManagementAPIHarness(t, sc.new)

				id, issued := h.grant()

				other, kept := h.grant()

				refreshed, err := h.refresh(grantManagementAPIRefreshToken(t, issued))
				require.NoError(t, ErrorToDebugRFC6749Error(err))

				require.NoError(t, h.provider.RevokeGrant(h.ctx, id))

				_, err = h.memory.GetGrant(h.ctx, id)
				require.ErrorIs(t, err, ErrNotFound)

				assert.False(t, h.active(issued.GetAccessToken()))
				assert.False(t, h.active(refreshed.GetAccessToken()))

				_, err = h.refresh(grantManagementAPIRefreshToken(t, refreshed))
				require.ErrorIs(t, err, ErrInvalidGrant)

				token := h.token(grantManagementAPIClientA, grantManagementAPIIssuer, consts.ScopeGrantManagementQuery)

				assert.Equal(t, http.StatusNotFound, h.call(http.MethodGet, id, token).Code)
				assert.Equal(t, http.StatusOK, h.call(http.MethodGet, other, token).Code)
				assert.True(t, h.active(kept.GetAccessToken()))

				require.ErrorIs(t, h.provider.RevokeGrant(h.ctx, id), ErrNotFound)
			})

			t.Run("ShouldRevokeAnExpiredGrant", func(t *testing.T) {
				h := newGrantManagementAPIHarness(t, sc.new)

				id, issued := h.grant()

				h.expire(id)

				require.NoError(t, h.provider.RevokeGrant(h.ctx, id))

				_, err := h.memory.GetGrant(h.ctx, id)
				require.ErrorIs(t, err, ErrNotFound)

				assert.False(t, h.active(issued.GetAccessToken()))

				_, err = h.refresh(grantManagementAPIRefreshToken(t, issued))
				require.ErrorIs(t, err, ErrInvalidGrant)
			})
		})
	}

	t.Run("ShouldRevokeWithoutTheHandlerRegistered", func(t *testing.T) {
		h := newGrantManagementAPIHarness(t, grantManagementAPIStores[0].new)

		id, issued := h.grant()

		h.config.AuthorizeEndpointBindingHandlers = nil

		require.NoError(t, h.provider.RevokeGrant(h.ctx, id))

		assert.False(t, h.active(issued.GetAccessToken()))
	})

	t.Run("ShouldFailWhenGrantManagementIsNotConfigured", func(t *testing.T) {
		h := newGrantManagementAPIHarness(t, grantManagementAPIStores[0].new)

		id, issued := h.grant()

		h.config.GrantManagement = nil

		err := h.provider.RevokeGrant(h.ctx, id)

		require.ErrorIs(t, err, ErrServerError)
		assert.Equal(t, "Grant management is not configured.", ErrorToRFC6749Error(err).DebugField)

		_, err = h.memory.GetGrant(h.ctx, id)
		require.NoError(t, err)

		assert.True(t, h.active(issued.GetAccessToken()))
	})

	t.Run("ShouldFailWhenTheStorageDoesNotPersistGrants", func(t *testing.T) {
		h := newGrantManagementAPIHarness(t, grantManagementAPIStores[0].new)

		id, _ := h.grant()

		h.provider.Store = struct{ ClientManager }{h.memory}

		require.ErrorIs(t, h.provider.RevokeGrant(h.ctx, id), ErrServerError)
	})

	t.Run("ShouldIgnoreTokensWhichAreAlreadyGone", func(t *testing.T) {
		store := &grantManagementAPIRevokingStore{MemoryStore: storage.NewMemoryStore(), refresh: ErrNotFound, access: ErrInactiveToken}

		provider := &Fosite{Config: &Config{GrantManagement: &GrantManagementConfig{}}, Store: store}

		require.NoError(t, store.CreateGrant(t.Context(), &Grant{ID: "one", ClientID: "a", RequestIDs: []string{"first", "second"}}))

		require.NoError(t, provider.RevokeGrant(t.Context(), "one"))

		assert.Equal(t, []string{"refresh:first", "access:first", "refresh:second", "access:second"}, store.calls)

		_, err := store.GetGrant(t.Context(), "one")
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("ShouldKeepTheGrantWhenATokenIsNotRevoked", func(t *testing.T) {
		store := &grantManagementAPIRevokingStore{MemoryStore: storage.NewMemoryStore(), access: errors.New("the database is gone")}

		provider := &Fosite{Config: &Config{GrantManagement: &GrantManagementConfig{}}, Store: store}

		require.NoError(t, store.CreateGrant(t.Context(), &Grant{ID: "one", ClientID: "a", RequestIDs: []string{"first", "second"}}))

		require.ErrorIs(t, provider.RevokeGrant(t.Context(), "one"), ErrServerError)

		assert.Equal(t, []string{"refresh:first", "access:first"}, store.calls)

		grant, err := store.GetGrant(t.Context(), "one")
		require.NoError(t, err)

		assert.ElementsMatch(t, []string{"first", "second"}, grant.RequestIDs)
	})

	t.Run("ShouldRevokeTheTokensOfARequestAppendedWhileRevoking", func(t *testing.T) {
		store := &grantManagementAPIRevokingStore{MemoryStore: storage.NewMemoryStore()}

		provider := &Fosite{Config: &Config{GrantManagement: &GrantManagementConfig{}}, Store: store}

		require.NoError(t, store.CreateGrant(t.Context(), &Grant{ID: "one", ClientID: "a", RequestIDs: []string{"first", "second"}}))

		store.hook = func(call string) {
			if call == "access:first" {
				require.NoError(t, store.AppendGrantRequestID(t.Context(), "one", "late"))
			}
		}

		require.NoError(t, provider.RevokeGrant(t.Context(), "one"))

		assert.Equal(t, []string{"refresh:first", "access:first", "refresh:second", "access:second", "refresh:late", "access:late"}, store.calls)

		_, err := store.GetGrant(t.Context(), "one")
		require.ErrorIs(t, err, ErrNotFound)

		require.ErrorIs(t, store.AppendGrantRequestID(t.Context(), "one", "later"), ErrNotFound)
	})

	t.Run("ShouldRevokeEveryTokenWhenTheContextIsCancelledWhileRevoking", func(t *testing.T) {
		store := &grantManagementAPIRevokingStore{MemoryStore: storage.NewMemoryStore()}

		provider := &Fosite{Config: &Config{GrantManagement: &GrantManagementConfig{}}, Store: store}

		require.NoError(t, store.CreateGrant(t.Context(), &Grant{ID: "one", ClientID: "a", RequestIDs: []string{"first", "second"}}))

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		store.hook = func(string) { cancel() }

		require.NoError(t, provider.RevokeGrant(ctx, "one"))

		assert.Equal(t, []string{"refresh:first", "access:first", "refresh:second", "access:second"}, store.calls)

		_, err := store.GetGrant(t.Context(), "one")
		require.ErrorIs(t, err, ErrNotFound)
	})
}

func TestNewGrantManagementResponse(t *testing.T) {
	t.Run("ShouldRejectAMethodTheRequestHandlerWouldNotAdmit", func(t *testing.T) {
		h := newGrantManagementAPIHarness(t, grantManagementAPIStores[0].new)

		id, _ := h.grant()

		client := h.memory.Clients[grantManagementAPIClientA]

		_, err := h.provider.NewGrantManagementResponse(h.ctx, &GrantManagementRequest{Method: http.MethodPost, Client: client, GrantID: id})

		assert.Equal(t, "invalid_request", ErrorToRFC6749Error(err).ErrorField)
		assert.Equal(t, http.StatusMethodNotAllowed, ErrorToRFC6749Error(err).CodeField)

		h.config.GrantManagement.Actions = []GrantManagementAction{GrantManagementActionQuery}

		_, err = h.provider.NewGrantManagementResponse(h.ctx, &GrantManagementRequest{Method: http.MethodDelete, Client: client, GrantID: id})

		assert.Equal(t, http.StatusMethodNotAllowed, ErrorToRFC6749Error(err).CodeField)

		_, err = h.memory.GetGrant(h.ctx, id)
		require.NoError(t, err)
	})

	t.Run("ShouldAnswerNotFoundWithoutAClient", func(t *testing.T) {
		h := newGrantManagementAPIHarness(t, grantManagementAPIStores[0].new)

		require.NoError(t, h.memory.CreateGrant(h.ctx, &Grant{ID: "ownerless"}))

		_, err := h.provider.NewGrantManagementResponse(h.ctx, &GrantManagementRequest{Method: http.MethodDelete, GrantID: "ownerless"})
		require.ErrorIs(t, err, ErrNotFound)

		_, err = h.provider.NewGrantManagementResponse(h.ctx, &GrantManagementRequest{Method: http.MethodDelete, Client: &DefaultClient{}, GrantID: "ownerless"})
		require.ErrorIs(t, err, ErrNotFound)

		_, err = h.memory.GetGrant(h.ctx, "ownerless")
		require.NoError(t, err)
	})
}

type grantManagementAPIRevokingStore struct {
	*storage.MemoryStore

	refresh error
	access  error
	calls   []string
	hook    func(call string)
}

func (s *grantManagementAPIRevokingStore) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return s.revoke(ctx, "refresh:"+requestID, s.refresh)
}

func (s *grantManagementAPIRevokingStore) RevokeAccessToken(ctx context.Context, requestID string) error {
	return s.revoke(ctx, "access:"+requestID, s.access)
}

func (s *grantManagementAPIRevokingStore) revoke(ctx context.Context, call string, result error) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.calls = append(s.calls, call)

	if s.hook != nil {
		s.hook(call)
	}

	return result
}
