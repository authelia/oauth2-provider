// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestRefreshTokenPastTheExpiryDeadline(t *testing.T) {
	stores := []struct {
		name string
		new  func() (deadlineStore, *storage.MemoryStore)
	}{
		{"MemoryStore", func() (deadlineStore, *storage.MemoryStore) {
			store := storage.NewMemoryStore()

			return store, store
		}},
		{"HydratingMemoryStore", func() (deadlineStore, *storage.MemoryStore) {
			store := storage.NewHydratingMemoryStore()

			return store, store.MemoryStore
		}},
	}

	owner := &oauth2.DefaultClient{
		ID:           "foo",
		ClientSecret: oauth2.NewPlainTextClientSecret("foobarfoobarfoobarfoobarfoobar12"),
		GrantTypes:   oauth2.Arguments{consts.GrantTypeRefreshToken},
		Scopes:       []string{"foo", consts.ScopeOffline},
	}

	for _, s := range stores {
		t.Run(s.name+"/ShouldReportTheTokenInactiveAtIntrospection", func(t *testing.T) {
			store, memory := s.new()
			memory.Clients[owner.ID] = owner

			token := newPastDeadlineRefreshToken(t, store, owner)

			config := &oauth2.Config{
				GlobalSecret:  []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar"),
				ScopeStrategy: oauth2.HierarchicScopeStrategy,
			}

			config.TokenIntrospectionHandlers = oauth2.TokenIntrospectionHandlers{
				&CoreValidator{CoreStrategy: &hmacshaStrategy, CoreStorage: store, Config: config},
			}

			provider := &oauth2.Fosite{Store: store, Config: config}

			r := httptest.NewRequest(http.MethodPost, "https://auth.example.com/introspect", strings.NewReader(url.Values{consts.FormParameterToken: {token}}.Encode()))
			r.Header.Set(consts.HeaderContentType, "application/x-www-form-urlencoded")
			r.SetBasicAuth(owner.ID, "foobarfoobarfoobarfoobarfoobar12")

			response, err := provider.NewIntrospectionRequest(t.Context(), r, &oauth2.DefaultSession{})

			require.ErrorIs(t, err, oauth2.ErrInactiveToken)
			assert.ErrorIs(t, err, oauth2.ErrTokenExpired)
			assert.False(t, response.IsActive())
		})

		t.Run(s.name+"/ShouldRejectTheRefreshGrantWithoutRotation", func(t *testing.T) {
			store, _ := s.new()

			token := newPastDeadlineRefreshToken(t, store, owner)

			handler := &RefreshTokenGrantHandler{
				TokenRevocationStorage: store,
				RefreshTokenStrategy:   &hmacshaStrategy,
				AccessTokenStrategy:    &hmacshaStrategy,
				Config: &oauth2.Config{
					AccessTokenLifespan:         time.Hour,
					RefreshTokenLifespan:        time.Hour,
					ScopeStrategy:               oauth2.HierarchicScopeStrategy,
					AudienceStrategy:            oauth2.DefaultAudienceStrategy,
					RefreshTokenScopes:          []string{consts.ScopeOffline},
					DisableRefreshTokenRotation: true,
				},
			}

			requester := oauth2.NewAccessRequest(&oauth2.DefaultSession{})
			requester.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
			requester.Client = owner
			requester.Form = url.Values{consts.FormParameterRefreshToken: {token}}

			err := handler.HandleTokenEndpointRequest(t.Context(), requester)

			require.ErrorIs(t, err, oauth2.ErrInvalidGrant)
			assert.ErrorIs(t, err, oauth2.ErrTokenExpired)
		})

		t.Run(s.name+"/ShouldRevokeTheToken", func(t *testing.T) {
			store, _ := s.new()

			token := newPastDeadlineRefreshToken(t, store, owner)

			handler := &TokenRevocationHandler{
				TokenRevocationStorage: store,
				RefreshTokenStrategy:   &hmacshaStrategy,
				AccessTokenStrategy:    &hmacshaStrategy,
				Config:                 &oauth2.Config{},
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.RevokeToken(t.Context(), token, oauth2.RefreshToken, owner)))

			_, err := store.GetRefreshTokenSession(t.Context(), hmacshaStrategy.RefreshTokenSignature(t.Context(), token), &oauth2.DefaultSession{})
			assert.ErrorIs(t, err, oauth2.ErrInactiveToken)
		})
	}
}

type deadlineStore interface {
	oauth2.Storage
	CoreStorage
	TokenRevocationStorage
}

func newPastDeadlineRefreshToken(t *testing.T, store deadlineStore, client oauth2.Client) (token string) {
	t.Helper()

	now := time.Now().UTC()

	original := &oauth2.Request{
		ID:             "req-id",
		Client:         client,
		RequestedAt:    now,
		GrantedScope:   oauth2.Arguments{"foo", consts.ScopeOffline},
		RequestedScope: oauth2.Arguments{"foo", consts.ScopeOffline},
		Session: &oauth2.DefaultSession{
			Subject:        "peter",
			ExpiresAt:      map[oauth2.TokenType]time.Time{oauth2.RefreshToken: now.Add(time.Hour)},
			ExpiryDeadline: now.Add(-time.Second),
		},
		Form: url.Values{},
	}

	token, signature, err := hmacshaStrategy.GenerateRefreshToken(t.Context(), nil)
	require.NoError(t, err)

	_, accessSignature, err := hmacshaStrategy.GenerateAccessToken(t.Context(), nil)
	require.NoError(t, err)

	require.NoError(t, store.CreateAccessTokenSession(t.Context(), accessSignature, original))
	require.NoError(t, store.CreateRefreshTokenSession(t.Context(), signature, accessSignature, original))

	return token
}
