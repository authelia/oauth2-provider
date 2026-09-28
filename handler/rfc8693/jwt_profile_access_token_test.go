// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestJWTProfileAccessTokenExchange(t *testing.T) {
	for _, sc := range bindingExchangeStores() {
		t.Run(sc.name, func(t *testing.T) {
			testCases := []struct {
				name  string
				actor map[string]any
			}{
				{
					name: "ShouldIssueAJWTProfileAccessToken",
				},
				{
					name:  "ShouldIssueAJWTProfileAccessTokenWithTheActorClaim",
					actor: map[string]any{consts.ClaimSubject: "service-a"},
				},
			}

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					store := sc.newStore()
					config, hmacStrategy := newBindingExchangeConfig()
					config.EnforceJWTProfileAccessTokens = true
					config.AccessTokenIssuer = "https://issuer.example.com"

					strategy := &hoauth2.JWTProfileCoreStrategy{
						Strategy:         &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)},
						HMACCoreStrategy: hmacStrategy.(*hoauth2.HMACCoreStrategy),
						Config:           config,
					}

					subject := NewDefaultSession()
					subject.SetSubject("peter")

					request := newLifetimeExchangeRequest(store, consts.TokenTypeRFC8693AccessToken, createSessionAccessToken(t.Context(), hmacStrategy, store, store.GetClients()["custom-lifespan-client"], subject), "")

					handler := newLifetimeAccessTokenHandler(config, strategy, store)

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.HandleTokenEndpointRequest(t.Context(), request)))

					if tc.actor != nil {
						request.GetSession().(Session).SetClaimActor(tc.actor)
					}

					response := oauth2.NewAccessResponse()

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(t.Context(), request, response)))

					claims := map[string]any{}

					token, err := jwt.UnsafeParseSignedAny(response.GetAccessToken(), &claims)
					require.NoError(t, err)
					require.Len(t, token.Headers, 1)

					// RFC 9068 Section 2.1.
					assert.Equal(t, consts.JSONWebTokenTypeAccessToken, token.Headers[0].ExtraHeaders[consts.JSONWebTokenHeaderType])

					// RFC 9068 Section 2.2.
					assert.Equal(t, "peter", claims[consts.ClaimSubject])
					assert.Equal(t, "https://issuer.example.com", claims[consts.ClaimIssuer])
					assert.Equal(t, "my-client", claims[consts.ClaimClientIdentifier])
					assert.NotEmpty(t, claims[consts.ClaimJWTID])
					assert.NotEmpty(t, claims[consts.ClaimIssuedAt])
					assert.NotEmpty(t, claims[consts.ClaimExpirationTime])

					if tc.actor != nil {
						assert.Equal(t, tc.actor, claims[consts.ClaimActor])
					} else {
						assert.NotContains(t, claims, consts.ClaimActor)
					}
				})
			}
		})
	}
}
