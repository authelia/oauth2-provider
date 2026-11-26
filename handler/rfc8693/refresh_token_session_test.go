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
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestRefreshTokenSubjectExchangeKeepsTheGrantSession(t *testing.T) {
	act := map[string]any{consts.ClaimSubject: "actor", consts.ClaimClientIdentifier: "requester"}
	mayAct := map[string]any{consts.ClaimSubject: "actor"}

	testCases := []struct {
		name      string
		requested string
		rotate    bool
		actor     bool
	}{
		{name: "ShouldKeepItWithAnAccessToken", requested: consts.TokenTypeRFC8693AccessToken, rotate: true},
		{name: "ShouldKeepItWithAnAccessTokenWithoutRotation", requested: consts.TokenTypeRFC8693AccessToken},
		{name: "ShouldKeepItWithAnAccessTokenAndAddTheActor", requested: consts.TokenTypeRFC8693AccessToken, rotate: true, actor: true},
		{name: "ShouldKeepItForARefreshToken", requested: consts.TokenTypeRFC8693RefreshToken, rotate: true},
		{name: "ShouldKeepItForARefreshTokenWithoutRotation", requested: consts.TokenTypeRFC8693RefreshToken},
		{name: "ShouldKeepItForARefreshTokenAndAddTheActor", requested: consts.TokenTypeRFC8693RefreshToken, rotate: true, actor: true},
	}

	for _, sc := range bindingExchangeStores() {
		for _, tc := range testCases {
			t.Run(sc.name+"/"+tc.name, func(t *testing.T) {
				f := newRefreshSubjectGrantFixture(t, sc.newStore(), true)
				f.client.TokenExchangeRefreshTokenRotationOverride = true
				f.client.TokenExchangeRefreshTokenRotation = tc.rotate

				granted := NewDefaultSession()
				granted.Subject = "peter"
				granted.Username = "peter@example.com"
				granted.Claims.Subject = "peter"
				granted.Claims.Extra = map[string]any{"tenant": "acme"}
				granted.Extra[consts.ClaimAuthorizedActor] = mayAct
				granted.SetExpiresAt(oauth2.RefreshToken, time.Now().UTC().Add(10*time.Minute).Truncate(time.Second))

				f.grant.Session = granted

				subject := f.mint(t)

				request := f.request(t, subject, tc.requested)

				session := request.GetSession().(*DefaultSession)
				session.Username = "exchange"
				session.Claims.Extra = map[string]any{"exchange": true}

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.refresh.HandleTokenEndpointRequest(t.Context(), request)))

				session.Extra["exchange"] = true

				if tc.actor {
					session.SetActorToken(map[string]any{consts.ClaimSubject: "actor", consts.ClaimClientIdentifier: "requester"})
					session.SetClaimActor(act)
				}

				var handler oauth2.TokenEndpointHandler = f.access
				if tc.requested == consts.TokenTypeRFC8693RefreshToken {
					handler = f.refresh
				}

				response := oauth2.NewAccessResponse()

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(t.Context(), request, response)))

				refresh := response.GetAccessToken()

				if tc.requested == consts.TokenTypeRFC8693AccessToken {
					refresh, _ = response.GetExtra(consts.FormParameterRefreshToken).(string)

					issued, err := f.store.GetAccessTokenSession(t.Context(), f.strategy.AccessTokenSignature(t.Context(), response.GetAccessToken()), NewDefaultSession())
					require.NoError(t, err)

					exchanged, ok := issued.GetSession().(*DefaultSession)
					require.True(t, ok)

					assert.Equal(t, "exchange", exchanged.GetUsername())
					assert.Equal(t, true, exchanged.Extra["exchange"])
				}

				require.NotEmpty(t, refresh)

				// See: https://www.rfc-editor.org/rfc/rfc8707#section-2.2
				issued, err := f.store.GetRefreshTokenSession(t.Context(), f.strategy.RefreshTokenSignature(t.Context(), refresh), NewDefaultSession())
				require.NoError(t, err)

				replacement, ok := issued.GetSession().(*DefaultSession)
				require.True(t, ok)

				assert.Equal(t, "peter", replacement.GetSubject())
				assert.Equal(t, "peter@example.com", replacement.GetUsername())
				assert.Equal(t, "acme", replacement.Claims.Extra["tenant"])
				assert.Equal(t, mayAct, replacement.Extra[consts.ClaimAuthorizedActor])
				assert.NotContains(t, replacement.Extra, "exchange")
				assert.NotContains(t, replacement.Claims.Extra, "exchange")
				assert.WithinDuration(t, request.GetSession().GetExpiresAt(oauth2.RefreshToken), replacement.GetExpiresAt(oauth2.RefreshToken), time.Second)
				assert.False(t, replacement.GetExpiresAt(oauth2.RefreshToken).After(granted.GetExpiresAt(oauth2.RefreshToken)))

				// See: https://datatracker.ietf.org/doc/html/rfc8693#section-4.1
				if tc.actor {
					assert.Equal(t, act, replacement.AccessTokenClaimsMap()[consts.ClaimActor])
					assert.Equal(t, act, replacement.Claims.Extra[consts.ClaimActor])
				} else {
					assert.NotContains(t, replacement.AccessTokenClaimsMap(), consts.ClaimActor)
				}

				assert.NotContains(t, granted.Extra, consts.ClaimActor)
				assert.NotContains(t, granted.Claims.Extra, consts.ClaimActor)

				if !tc.rotate {
					original, err := f.store.GetRefreshTokenSession(t.Context(), f.strategy.RefreshTokenSignature(t.Context(), subject), NewDefaultSession())
					require.NoError(t, err)

					assert.NotContains(t, original.GetSession().(*DefaultSession).Extra, consts.ClaimActor)
				}
			})
		}
	}
}

func TestRefreshTokenSubjectExchangeKeepsTheActorWhenTheGrantSessionCannotRecordIt(t *testing.T) {
	act := map[string]any{consts.ClaimSubject: "actor"}

	for _, sc := range bindingExchangeStores() {
		t.Run(sc.name, func(t *testing.T) {
			f := newRefreshSubjectGrantFixture(t, sc.newStore(), true)

			_, ok := f.grant.GetSession().(Session)
			require.False(t, ok)

			request := f.request(t, f.mint(t), consts.TokenTypeRFC8693RefreshToken)

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.refresh.HandleTokenEndpointRequest(t.Context(), request)))

			session := request.GetSession().(*DefaultSession)
			session.SetActorToken(map[string]any{consts.ClaimSubject: "actor"})
			session.SetClaimActor(act)

			response := oauth2.NewAccessResponse()

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.refresh.PopulateTokenEndpointResponse(t.Context(), request, response)))

			issued, err := f.store.GetRefreshTokenSession(t.Context(), f.strategy.RefreshTokenSignature(t.Context(), response.GetAccessToken()), NewDefaultSession())
			require.NoError(t, err)

			replacement, ok := issued.GetSession().(Session)
			require.True(t, ok)

			// See: https://datatracker.ietf.org/doc/html/rfc8693#section-4.1
			assert.Equal(t, act, replacement.AccessTokenClaimsMap()[consts.ClaimActor])
		})
	}
}
