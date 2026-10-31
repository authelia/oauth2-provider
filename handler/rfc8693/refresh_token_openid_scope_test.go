// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestTokenExchangeRequiresOpenIDScopeForAnIDTokenFromARefreshToken(t *testing.T) {
	testCases := []struct {
		name      string
		scopes    oauth2.Arguments
		requested string
		expected  string
	}{
		{
			name:      "ShouldIssueAnIDTokenWhenOpenIDWasGranted",
			scopes:    oauth2.Arguments{consts.ScopeOpenID, consts.ScopeOffline},
			requested: consts.TokenTypeRFC8693IDToken,
		},
		{
			name:      "ShouldRefuseAnIDTokenWhenOpenIDWasNotGranted",
			scopes:    oauth2.Arguments{consts.ScopeOffline},
			requested: consts.TokenTypeRFC8693IDToken,
			expected:  "An ID Token can only be issued from a refresh token that was granted the 'openid' scope.",
		},
		{
			name:      "ShouldIssueAnAccessTokenWhenOpenIDWasNotGranted",
			scopes:    oauth2.Arguments{consts.ScopeOffline},
			requested: consts.TokenTypeRFC8693AccessToken,
		},
	}

	for _, sc := range bindingExchangeStores() {
		for _, tc := range testCases {
			t.Run(sc.name+"/"+tc.name, func(t *testing.T) {
				store := sc.newStore()
				config, strategy := newBindingExchangeConfig()
				token := mintScopedRefreshToken(t.Context(), strategy, store, store.GetClients()["my-client"], tc.scopes)

				err := newLifetimeRefreshTokenHandler(config, strategy, store).HandleTokenEndpointRequest(t.Context(), newLifetimeExchangeRequest(store, consts.TokenTypeRFC8693RefreshToken, token, tc.requested))

				if tc.expected == "" {
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

					return
				}

				assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
				assert.ErrorContains(t, oauth2.ErrorToDebugRFC6749Error(err), tc.expected)
			})
		}
	}
}

func mintScopedRefreshToken(ctx context.Context, strategy hoauth2.CoreStrategy, store rfc8693ExchangeStore, client oauth2.Client, scopes oauth2.Arguments) string {
	session := NewDefaultSession()
	session.SetSubject("peter")
	session.SetExpiresAt(oauth2.RefreshToken, time.Now().UTC().Add(time.Hour))

	request := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
		Request:    oauth2.Request{ID: uuid.New().String(), GrantedScope: scopes, Session: session, Client: client},
	}

	token, signature, err := strategy.GenerateRefreshToken(ctx, request)
	if err != nil {
		panic(err.Error())
	}

	if err = store.(hoauth2.TokenRevocationStorage).CreateRefreshTokenSession(ctx, signature, "", request.Sanitize([]string{})); err != nil {
		panic(err.Error())
	}

	return token
}
