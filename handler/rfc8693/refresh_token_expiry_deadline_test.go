// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/hmac"
)

// §2.2.2: a subject refresh token past the expiry deadline of its grant is rejected as an expired one is.
func TestRefreshTokenSubjectPastTheExpiryDeadline(t *testing.T) {
	testCases := []struct {
		name     string
		expires  time.Duration
		deadline time.Duration
		err      bool
	}{
		{"ShouldRejectPastTheDeadline", time.Hour, -time.Second, true},
		{"ShouldRejectAnExpiredToken", -time.Second, 0, true},
		{"ShouldAcceptBeforeTheDeadline", time.Hour, time.Minute, false},
	}

	for _, sc := range bindingExchangeStores() {
		for _, tc := range testCases {
			t.Run(sc.name+"/"+tc.name, func(t *testing.T) {
				store := sc.newStore()
				cfg := newSpecConfig(t)
				strategy := &hoauth2.HMACCoreStrategy{Enigma: &hmac.HMACStrategy{Config: cfg}, Config: cfg}

				client := store.GetClients()["my-client"]

				issued := newIssuedRequest(client, "alice", nil, oauth2.RefreshToken)
				issued.GetSession().SetExpiresAt(oauth2.RefreshToken, time.Now().UTC().Add(tc.expires))

				if tc.deadline != 0 {
					issued.GetSession().(*oauth2.DefaultSession).ExpiryDeadline = time.Now().UTC().Add(tc.deadline)
				}

				token, signature, err := strategy.GenerateRefreshToken(t.Context(), issued)
				require.NoError(t, err)
				require.NoError(t, store.CreateRefreshTokenSession(t.Context(), signature, "", issued.Sanitize(nil)))

				req := newExchangeRequest(t, client, newSpecSession("alice"), url.Values{
					consts.FormParameterSubjectTokenType: {consts.TokenTypeRFC8693RefreshToken},
					consts.FormParameterSubjectToken:     {token},
				})

				handler := &RefreshTokenTypeHandler{
					Config:               cfg,
					RefreshTokenLifespan: 5 * time.Minute,
					CoreStrategy:         strategy,
					ScopeStrategy:        cfg.ScopeStrategy,
					Storage:              store,
				}

				err = handler.HandleTokenEndpointRequest(t.Context(), req)

				if !tc.err {
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

					return
				}

				require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
				assert.NotErrorIs(t, err, oauth2.ErrTokenExpired)
				assert.Equal(t, "Token is not valid or has expired.", oauth2.ErrorToRFC6749Error(err).HintField)
			})
		}
	}
}

func TestRefreshTokenSubjectCapsAtTheExpiryDeadline(t *testing.T) {
	for _, sc := range bindingExchangeStores() {
		t.Run(sc.name, func(t *testing.T) {
			store := sc.newStore()
			config, coreStrategy := newBindingExchangeConfig()

			now := time.Now().UTC().Truncate(time.Second)
			deadline := now.Add(10 * time.Minute)

			session := NewDefaultSession()
			session.SetSubject("peter")
			session.SetExpiresAt(oauth2.RefreshToken, now.Add(time.Hour))
			session.SetExpiryDeadline(deadline)

			issued := &oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{"password"},
				Request: oauth2.Request{
					ID:      uuid.New().String(),
					Session: session,
					Client:  store.GetClients()["my-client"],
				},
			}

			token, signature, err := coreStrategy.GenerateRefreshToken(t.Context(), issued)
			require.NoError(t, err)
			require.NoError(t, store.CreateRefreshTokenSession(t.Context(), signature, "", issued.Sanitize([]string{})))

			request := newLifetimeExchangeRequest(store, consts.TokenTypeRFC8693RefreshToken, token, "")

			refreshHandler := newLifetimeRefreshTokenHandler(config, coreStrategy, store)
			handler := newLifetimeAccessTokenHandler(config, coreStrategy, store)

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(refreshHandler.HandleTokenEndpointRequest(t.Context(), request)))

			response := oauth2.NewAccessResponse()

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(t.Context(), request, response)))

			assert.Equal(t, deadline, request.GetSession().(oauth2.ExpiryDeadlineSession).GetExpiryDeadline())
			assert.False(t, request.GetSession().GetExpiresAt(oauth2.AccessToken).After(deadline))
			assert.NotEmpty(t, response.GetExtra(consts.FormParameterRefreshToken))
			assert.False(t, request.GetSession().GetExpiresAt(oauth2.RefreshToken).After(deadline))
		})
	}
}
