// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestRefreshKeepsTheDelegationClaims(t *testing.T) {
	act := map[string]any{consts.ClaimSubject: "actor", consts.ClaimClientIdentifier: "my-client"}
	mayAct := map[string]any{consts.ClaimSubject: "actor"}

	for _, tc := range bindingExchangeStores() {
		t.Run(tc.name, func(t *testing.T) {
			config, coreStrategy := newBindingExchangeConfig()
			config.AccessTokenLifespan = time.Hour
			config.RefreshTokenLifespan = time.Hour

			store := tc.newStore()

			revocation, ok := store.(hoauth2.TokenRevocationStorage)
			require.True(t, ok)

			client := store.GetClients()["my-client"]

			session := NewDefaultSession()
			session.Subject = "peter"
			session.Claims.Subject = "peter"
			session.SetClaimActor(act)
			session.Extra[consts.ClaimAuthorizedActor] = mayAct

			original := oauth2.NewAccessRequest(session)
			original.ID = "original"
			original.Client = client
			original.GrantedScope = oauth2.Arguments{consts.ScopeOffline}

			token, signature, err := coreStrategy.GenerateRefreshToken(t.Context(), original)
			require.NoError(t, err)
			require.NoError(t, revocation.CreateRefreshTokenSession(t.Context(), signature, "", original))

			handler := &hoauth2.RefreshTokenGrantHandler{
				AccessTokenStrategy:    coreStrategy,
				RefreshTokenStrategy:   coreStrategy,
				TokenRevocationStorage: revocation,
				Config:                 config,
			}

			request := oauth2.NewAccessRequest(NewDefaultSession())
			request.Client = client
			request.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
			request.Form.Set(consts.FormParameterRefreshToken, token)

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.HandleTokenEndpointRequest(t.Context(), request)))

			response := oauth2.NewAccessResponse()

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(t.Context(), request, response)))

			refreshed, err := store.GetAccessTokenSession(t.Context(), coreStrategy.AccessTokenSignature(t.Context(), response.GetAccessToken()), NewDefaultSession())
			require.NoError(t, err)

			exchanged, ok := refreshed.GetSession().(Session)
			require.True(t, ok)

			claims := exchanged.AccessTokenClaimsMap()

			assert.Equal(t, act, claims[consts.ClaimActor])
			assert.Equal(t, mayAct, claims[consts.ClaimAuthorizedActor])
		})
	}
}
