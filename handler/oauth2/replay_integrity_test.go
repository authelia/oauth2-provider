// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
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

func TestRefreshTokenReplayRequiresAnIntactToken(t *testing.T) {
	testCases := []struct {
		name    string
		forge   bool
		expired bool
		revoked bool
	}{
		{name: "ShouldRevokeTheGrantForAGenuineReplay", revoked: true},
		{name: "ShouldRevokeTheGrantForAGenuineExpiredReplay", expired: true, revoked: true},
		{name: "ShouldNotRevokeTheGrantForAForgedToken", forge: true},
		{name: "ShouldNotRevokeTheGrantForAForgedExpiredToken", forge: true, expired: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := storage.NewMemoryStore()
			strategy := &hmacshaStrategy

			client := &oauth2.DefaultClient{ID: "refresh-client", GrantTypes: oauth2.Arguments{consts.GrantTypeRefreshToken}}

			original := &oauth2.Request{
				ID:           "refresh-grant",
				Client:       client,
				GrantedScope: oauth2.Arguments{consts.ScopeOffline},
				Session:      &oauth2.DefaultSession{ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.RefreshToken: time.Now().UTC().Add(time.Hour)}},
				RequestedAt:  time.Now().UTC(),
			}

			if tc.expired {
				original.Session.SetExpiresAt(oauth2.RefreshToken, time.Now().UTC().Add(-time.Minute))
			}

			token, signature, err := strategy.GenerateRefreshToken(t.Context(), nil)
			require.NoError(t, err)
			require.NoError(t, store.CreateRefreshTokenSession(t.Context(), signature, "", original))
			require.NoError(t, store.RevokeRefreshToken(t.Context(), original.ID))

			_, accessSignature, err := strategy.GenerateAccessToken(t.Context(), nil)
			require.NoError(t, err)
			require.NoError(t, store.CreateAccessTokenSession(t.Context(), accessSignature, original))

			if tc.forge {
				token = forgeHMACToken(token)
			}

			request := oauth2.NewAccessRequest(&oauth2.DefaultSession{})
			request.Client = client
			request.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
			request.Form = url.Values{consts.FormParameterRefreshToken: {token}}

			handler := &RefreshTokenGrantHandler{
				TokenRevocationStorage: store,
				RefreshTokenStrategy:   strategy,
				Config:                 &oauth2.Config{RefreshTokenScopes: []string{consts.ScopeOffline}},
			}

			err = handler.HandleTokenEndpointRequest(t.Context(), request)
			require.ErrorIs(t, err, oauth2.ErrInvalidGrant)

			_, err = store.GetAccessTokenSession(t.Context(), accessSignature, nil)
			assert.Equal(t, tc.revoked, err != nil)
		})
	}
}

func TestAuthorizeCodeReplayRequiresAnIntactCode(t *testing.T) {
	testCases := []struct {
		name    string
		forge   bool
		expired bool
		revoked bool
	}{
		{name: "ShouldRevokeTheGrantForAGenuineCodeReplay", revoked: true},
		{name: "ShouldRevokeTheGrantForAGenuineExpiredCodeReplay", expired: true, revoked: true},
		{name: "ShouldNotRevokeTheGrantForAForgedCode", forge: true},
		{name: "ShouldNotRevokeTheGrantForAForgedExpiredCode", forge: true, expired: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := storage.NewMemoryStore()
			strategy := &hmacshaStrategy

			client := &oauth2.DefaultClient{ID: "code-client", GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode}}

			original := &oauth2.Request{
				ID:          "code-grant",
				Client:      client,
				Session:     &oauth2.DefaultSession{},
				RequestedAt: time.Now().UTC(),
			}

			if tc.expired {
				original.Session.SetExpiresAt(oauth2.AuthorizeCode, time.Now().UTC().Add(-time.Minute))
			}

			code, signature, err := strategy.GenerateAuthorizeCode(t.Context(), nil)
			require.NoError(t, err)
			require.NoError(t, store.CreateAuthorizeCodeSession(t.Context(), signature, original))
			require.NoError(t, store.InvalidateAuthorizeCodeSession(t.Context(), signature))

			_, accessSignature, err := strategy.GenerateAccessToken(t.Context(), nil)
			require.NoError(t, err)
			require.NoError(t, store.CreateAccessTokenSession(t.Context(), accessSignature, original))

			if tc.forge {
				code = forgeHMACToken(code)
			}

			request := oauth2.NewAccessRequest(&oauth2.DefaultSession{})
			request.Client = client
			request.GrantTypes = oauth2.Arguments{consts.GrantTypeAuthorizationCode}
			request.Form = url.Values{consts.FormParameterAuthorizationCode: {code}}

			handler := &AuthorizeExplicitGrantHandler{
				AuthorizeCodeStrategy:  strategy,
				CoreStorage:            store,
				TokenRevocationStorage: store,
				Config:                 &oauth2.Config{AuthorizeCodeLifespan: time.Hour},
			}

			err = handler.HandleTokenEndpointRequest(t.Context(), request)
			require.ErrorIs(t, err, oauth2.ErrInvalidGrant)

			_, err = store.GetAccessTokenSession(t.Context(), accessSignature, nil)
			assert.Equal(t, tc.revoked, err != nil)
		})
	}
}

func forgeHMACToken(token string) string {
	i := strings.LastIndex(token, ".") - 10

	replacement := "A"
	if token[i] == 'A' {
		replacement = "B"
	}

	return token[:i] + replacement + token[i+1:]
}
