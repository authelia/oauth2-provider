// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
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

func TestRevokeRotatedRefreshToken(t *testing.T) {
	stores := []struct {
		name string
		new  func() TokenRevocationStorage
	}{
		{"MemoryStore", func() TokenRevocationStorage { return storage.NewMemoryStore() }},
		{"HydratingMemoryStore", func() TokenRevocationStorage { return storage.NewHydratingMemoryStore() }},
	}

	owner := &oauth2.DefaultClient{ID: "foo", GrantTypes: oauth2.Arguments{consts.GrantTypeRefreshToken}, Scopes: []string{"foo", consts.ScopeOffline}}

	testCases := []struct {
		name     string
		hint     oauth2.TokenType
		client   oauth2.Client
		token    func(token string) string
		revoked  bool
		expected error
	}{
		{name: "ShouldRevokeTheGrantWithARefreshTokenHint", hint: oauth2.RefreshToken, client: owner, revoked: true},
		{name: "ShouldRevokeTheGrantWithAnAccessTokenHint", hint: oauth2.AccessToken, client: owner, revoked: true},
		{name: "ShouldRevokeTheGrantWithoutAHint", client: owner, revoked: true},
		{name: "ShouldRefuseAnotherClient", hint: oauth2.RefreshToken, client: &oauth2.DefaultClient{ID: "bar"}, expected: oauth2.ErrUnauthorizedClient},
		{
			name:   "ShouldIgnoreATokenWithAnInvalidKey",
			hint:   oauth2.RefreshToken,
			client: owner,
			token: func(token string) string {
				_, signature, _ := strings.Cut(token, ".")

				return "authelia_rt_v9E8WquYRq3WmL5xeME65ftCh2SezhVBI9JL7z7NPbM." + signature
			},
		},
		{
			name:   "ShouldIgnoreATokenWithACorruptKey",
			hint:   oauth2.RefreshToken,
			client: owner,
			token: func(token string) string {
				_, signature, _ := strings.Cut(token, ".")

				return "authelia_rt_!!!." + signature
			},
		},
	}

	for _, s := range stores {
		for _, tc := range testCases {
			t.Run(s.name+"/"+tc.name, func(t *testing.T) {
				store := s.new()

				rotated, access, refresh := newRotatedRefreshToken(t, store, owner)

				handler := &TokenRevocationHandler{
					TokenRevocationStorage: store,
					RefreshTokenStrategy:   &hmacshaStrategy,
					AccessTokenStrategy:    &hmacshaStrategy,
					Config:                 &oauth2.Config{},
				}

				token := rotated
				if tc.token != nil {
					token = tc.token(rotated)
				}

				err := handler.RevokeToken(t.Context(), token, tc.hint, tc.client)

				if tc.expected != nil {
					require.ErrorIs(t, err, tc.expected)
				} else {
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
				}

				_, errAccess := store.GetAccessTokenSession(t.Context(), hmacshaStrategy.AccessTokenSignature(t.Context(), access), &oauth2.DefaultSession{})
				_, errRefresh := store.GetRefreshTokenSession(t.Context(), hmacshaStrategy.RefreshTokenSignature(t.Context(), refresh), &oauth2.DefaultSession{})

				if tc.revoked {
					assert.Error(t, errAccess)
					assert.ErrorIs(t, errRefresh, oauth2.ErrInactiveToken)

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.RevokeToken(t.Context(), token, tc.hint, tc.client)))
				} else {
					assert.NoError(t, errAccess)
					assert.NoError(t, errRefresh)
				}
			})
		}
	}
}

func TestRevokeRotatedRefreshTokenWithoutAHydratedSession(t *testing.T) {
	owner := &oauth2.DefaultClient{ID: "foo", GrantTypes: oauth2.Arguments{consts.GrantTypeRefreshToken}, Scopes: []string{"foo", consts.ScopeOffline}}
	store := storage.NewMemoryStore()

	rotated, _, refresh := newRotatedRefreshToken(t, store, owner)

	handler := &TokenRevocationHandler{
		TokenRevocationStorage: &sessionlessRevocationStore{TokenRevocationStorage: store},
		RefreshTokenStrategy:   &hmacshaStrategy,
		AccessTokenStrategy:    &hmacshaStrategy,
		Config:                 &oauth2.Config{},
	}

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.RevokeToken(t.Context(), rotated, oauth2.RefreshToken, owner)))

	_, err := store.GetRefreshTokenSession(t.Context(), hmacshaStrategy.RefreshTokenSignature(t.Context(), refresh), nil)
	assert.ErrorIs(t, err, oauth2.ErrInactiveToken)
}

func TestRevokeRotatedRefreshTokenWithoutARequesterRevokesNothing(t *testing.T) {
	owner := &oauth2.DefaultClient{ID: "foo", GrantTypes: oauth2.Arguments{consts.GrantTypeRefreshToken}, Scopes: []string{"foo", consts.ScopeOffline}}
	store := storage.NewMemoryStore()

	rotated, _, refresh := newRotatedRefreshToken(t, store, owner)

	handler := &TokenRevocationHandler{
		TokenRevocationStorage: &sessionlessRevocationStore{TokenRevocationStorage: store, omitRequester: true},
		RefreshTokenStrategy:   &hmacshaStrategy,
		AccessTokenStrategy:    &hmacshaStrategy,
		Config:                 &oauth2.Config{},
	}

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.RevokeToken(t.Context(), rotated, oauth2.RefreshToken, owner)))

	_, err := store.GetRefreshTokenSession(t.Context(), hmacshaStrategy.RefreshTokenSignature(t.Context(), refresh), nil)
	assert.NoError(t, err)
}

type sessionlessRevocationStore struct {
	TokenRevocationStorage

	omitRequester bool
}

func (s *sessionlessRevocationStore) GetRefreshTokenSession(ctx context.Context, signature string, session oauth2.Session) (oauth2.Requester, error) {
	request, err := s.TokenRevocationStorage.GetRefreshTokenSession(ctx, signature, session)
	if s.omitRequester {
		return nil, err
	}

	if request == nil {
		return nil, err
	}

	return &oauth2.Request{ID: request.GetID(), Client: request.GetClient()}, err
}

func newRotatedRefreshToken(t *testing.T, store TokenRevocationStorage, client oauth2.Client) (rotated, access, refresh string) {
	t.Helper()

	expires := time.Now().UTC().Add(time.Hour)

	original := &oauth2.Request{
		ID:             "req-id",
		Client:         client,
		RequestedAt:    time.Now().UTC(),
		GrantedScope:   oauth2.Arguments{"foo", consts.ScopeOffline},
		RequestedScope: oauth2.Arguments{"foo", consts.ScopeOffline},
		Session:        &oauth2.DefaultSession{Subject: "peter", ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.RefreshToken: expires}},
		Form:           url.Values{},
	}

	rotated, signature, err := hmacshaStrategy.GenerateRefreshToken(t.Context(), nil)
	require.NoError(t, err)

	_, accessSignature, err := hmacshaStrategy.GenerateAccessToken(t.Context(), nil)
	require.NoError(t, err)

	require.NoError(t, store.CreateAccessTokenSession(t.Context(), accessSignature, original))
	require.NoError(t, store.CreateRefreshTokenSession(t.Context(), signature, accessSignature, original))

	handler := &RefreshTokenGrantHandler{
		TokenRevocationStorage: store,
		RefreshTokenStrategy:   &hmacshaStrategy,
		AccessTokenStrategy:    &hmacshaStrategy,
		Config: &oauth2.Config{
			AccessTokenLifespan:  time.Hour,
			RefreshTokenLifespan: time.Hour,
			ScopeStrategy:        oauth2.HierarchicScopeStrategy,
			AudienceStrategy:     oauth2.DefaultAudienceStrategy,
			RefreshTokenScopes:   []string{consts.ScopeOffline},
		},
	}

	request := oauth2.NewAccessRequest(&oauth2.DefaultSession{})
	request.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
	request.Client = client
	request.Form = url.Values{consts.FormParameterRefreshToken: {rotated}}

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.HandleTokenEndpointRequest(t.Context(), request)))

	response := oauth2.NewAccessResponse()

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(t.Context(), request, response)))

	refresh, _ = response.GetExtra(consts.AccessResponseRefreshToken).(string)

	require.NotEmpty(t, refresh)

	return rotated, response.GetAccessToken(), refresh
}
