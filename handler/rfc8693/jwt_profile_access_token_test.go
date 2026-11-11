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
	"authelia.com/provider/oauth2/token/jwt"
)

func TestJWTProfileAccessTokenExchange(t *testing.T) {
	for _, sc := range bindingExchangeStores() {
		t.Run(sc.name, func(t *testing.T) {
			testCases := []struct {
				name  string
				actor map[string]any
				login bool
			}{
				{
					name: "ShouldIssueAJWTProfileAccessToken",
				},
				{
					name:  "ShouldIssueAJWTProfileAccessTokenWithTheAuthenticationContext",
					login: true,
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
					config.JWTProfileAccessTokenDefaultAudience = []string{"https://api.example.com"}
					config.EnforceJWTProfileAccessTokens = true
					config.Issuer = "https://issuer.example.com"

					strategy := &hoauth2.JWTProfileCoreStrategy{
						Strategy:         &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)},
						HMACCoreStrategy: hmacStrategy.(*hoauth2.HMACCoreStrategy),
						Config:           config,
					}

					subject := NewDefaultSession()
					subject.SetSubject("peter")

					authTime := time.Now().Add(-time.Hour).Truncate(time.Second)

					if tc.login {
						claims := subject.IDTokenClaims()
						claims.AuthTime = jwt.NewNumericDate(authTime)
						claims.AuthenticationContextClassReference = "gold"
						claims.AuthenticationMethodsReferences = []string{"mfa"}
					}

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
					assert.Contains(t, claims[consts.ClaimAudience], "https://api.example.com")
					assert.NotEmpty(t, claims[consts.ClaimJWTID])
					assert.NotEmpty(t, claims[consts.ClaimIssuedAt])
					assert.NotEmpty(t, claims[consts.ClaimExpirationTime])

					if tc.actor != nil {
						assert.Equal(t, tc.actor, claims[consts.ClaimActor])
					} else {
						assert.NotContains(t, claims, consts.ClaimActor)
					}

					// RFC 9068 Section 2.2.1.
					if tc.login {
						assert.Equal(t, float64(authTime.Unix()), claims[consts.ClaimAuthenticationTime])
						assert.Equal(t, "gold", claims[consts.ClaimAuthenticationContextClassReference])
						assert.Equal(t, []any{"mfa"}, claims[consts.ClaimAuthenticationMethodsReference])
					} else {
						assert.NotContains(t, claims, consts.ClaimAuthenticationTime)
						assert.NotContains(t, claims, consts.ClaimAuthenticationContextClassReference)
						assert.NotContains(t, claims, consts.ClaimAuthenticationMethodsReference)
					}
				})
			}
		})
	}
}
