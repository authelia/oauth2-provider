// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"
	josejwt "authelia.com/provider/jose/jwt"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestIDJAG(t *testing.T) {
	stores := []struct {
		name string
		new  func() (store hoauth2.CoreStorage, memory *storage.MemoryStore)
	}{
		{
			name: idjagStoreMemory,
			new: func() (hoauth2.CoreStorage, *storage.MemoryStore) {
				store := storage.NewMemoryStore()

				return store, store
			},
		},
		{
			name: idjagStoreHydrate,
			new: func() (hoauth2.CoreStorage, *storage.MemoryStore) {
				store := storage.NewHydratingMemoryStore()

				return store, store.MemoryStore
			},
		},
	}

	for _, s := range stores {
		t.Run(s.name, func(t *testing.T) {
			t.Run("ShouldExchangeAnIDToken", func(t *testing.T) {
				env := newIDJAGEnvironment(t, s.new)

				// Section 4.3: token exchange at the IdP.
				status, token, errBody := postIDJAGToken(t, env.idp, idjagIdPClientID, env.exchangeForm(env.idToken(t), consts.TokenTypeRFC8693IDToken, env.rs.URL), "")

				require.Equal(t, http.StatusOK, status, "exchange error: %+v", errBody)
				assert.Equal(t, oauth2.RFC8693NAToken, token.TokenType)
				assert.Equal(t, consts.TokenTypeRFC8693IDJAG, token.IssuedTokenType)
				assert.Empty(t, token.RefreshToken)
				assert.Equal(t, idjagScope, token.Scope)

				header, claims := env.decodeIDJAG(t, token.AccessToken)

				assert.Equal(t, consts.JSONWebTokenTypeIDJAG, header)
				assert.Equal(t, env.idp.URL, claims[consts.ClaimIssuer])
				assert.Equal(t, env.rs.URL, claims[consts.ClaimAudience])
				assert.Equal(t, idjagRSClientID, claims[consts.ClaimClientIdentifier])
				assert.Equal(t, idjagSubject, claims[consts.ClaimSubject])
				assert.Equal(t, idjagScope, claims[consts.ClaimScope])
				assert.Equal(t, env.rs.URL+idjagResourcePath, claims[consts.ClaimResource])
				assert.NotContains(t, claims, consts.ClaimConfirmation)

				// Section 3.1: the authentication context of the subject ID token is carried forward.
				assert.Equal(t, idjagACR, claims[consts.ClaimAuthenticationContextClassReference])
				assert.Equal(t, []any{idjagAMR}, claims[consts.ClaimAuthenticationMethodsReference])
				assert.InDelta(t, float64(time.Now().Add(-idjagAuthAge).Unix()), claims[consts.ClaimAuthenticationTime], 5)

				// Section 4.4: redemption at the Resource AS, and again per Section 4.4.3.
				for range 2 {
					status, redeemed, errBody := postIDJAGToken(t, env.rs, idjagRSClientID, idjagRedeemForm(token.AccessToken), "")

					require.Equal(t, http.StatusOK, status, "redeem error: %+v", errBody)
					assert.Equal(t, oauth2.BearerAccessToken, redeemed.TokenType)
					assert.Equal(t, idjagScope, redeemed.Scope)
					assert.Equal(t, env.rs.URL+idjagResourcePath, redeemed.Resource)
					assert.LessOrEqual(t, redeemed.ExpiresIn, int64(time.Until(time.Unix(int64(claims[consts.ClaimExpirationTime].(float64)), 0)).Seconds())+1)
					assert.NotEmpty(t, redeemed.AccessToken)
					assert.Empty(t, redeemed.RefreshToken)
				}
			})

			t.Run("ShouldExchangeARefreshToken", func(t *testing.T) {
				env := newIDJAGEnvironment(t, s.new)

				status, token, errBody := postIDJAGToken(t, env.idp, idjagIdPClientID, env.exchangeForm(env.refreshToken(t, []string{idjagScope}, []string{env.rs.URL}, []string{env.rs.URL + idjagResourcePath}), consts.TokenTypeRFC8693RefreshToken, env.rs.URL), "")

				require.Equal(t, http.StatusOK, status, "exchange error: %+v", errBody)
				assert.Equal(t, oauth2.RFC8693NAToken, token.TokenType)
				assert.Equal(t, consts.TokenTypeRFC8693IDJAG, token.IssuedTokenType)
				assert.Empty(t, token.RefreshToken)

				header, claims := env.decodeIDJAG(t, token.AccessToken)

				assert.Equal(t, consts.JSONWebTokenTypeIDJAG, header)
				assert.Equal(t, idjagSubject, claims[consts.ClaimSubject])
				assert.NotContains(t, claims, consts.ClaimAuthenticationTime)
				assert.NotContains(t, claims, consts.ClaimAuthenticationContextClassReference)
				assert.NotContains(t, claims, consts.ClaimAuthenticationMethodsReference)

				status, redeemed, errBody := postIDJAGToken(t, env.rs, idjagRSClientID, idjagRedeemForm(token.AccessToken), "")

				require.Equal(t, http.StatusOK, status, "redeem error: %+v", errBody)
				assert.Equal(t, oauth2.BearerAccessToken, redeemed.TokenType)
				assert.Equal(t, idjagScope, redeemed.Scope)
				assert.Empty(t, redeemed.RefreshToken)
			})

			t.Run("ShouldCarryTheAuthenticationContextOfARefreshToken", func(t *testing.T) {
				env := newIDJAGEnvironment(t, s.new)

				authTime := time.Now().UTC().Add(-idjagAuthAge)

				session := &openid.DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:                             idjagSubject,
						AuthTime:                            jwt.NewNumericDate(authTime),
						AuthenticationContextClassReference: idjagACR,
						AuthenticationMethodsReferences:     []string{idjagAMR},
					},
					Headers:  &jwt.Headers{},
					Username: idjagSubject,
					Subject:  idjagSubject,
					ExpiresAt: map[oauth2.TokenType]time.Time{
						oauth2.RefreshToken: time.Now().UTC().Add(10 * time.Minute),
					},
				}

				subjectToken := env.refreshTokenWithSession(t, session, []string{idjagScope}, []string{env.rs.URL}, []string{env.rs.URL + idjagResourcePath})

				status, token, errBody := postIDJAGToken(t, env.idp, idjagIdPClientID, env.exchangeForm(subjectToken, consts.TokenTypeRFC8693RefreshToken, env.rs.URL), "")

				require.Equal(t, http.StatusOK, status, "exchange error: %+v", errBody)

				_, claims := env.decodeIDJAG(t, token.AccessToken)

				// Section 4.3.3: the authentication context of the login the refresh token was issued for is carried forward.
				assert.Equal(t, idjagACR, claims[consts.ClaimAuthenticationContextClassReference])
				assert.Equal(t, []any{idjagAMR}, claims[consts.ClaimAuthenticationMethodsReference])
				assert.Equal(t, float64(authTime.Unix()), claims[consts.ClaimAuthenticationTime])
			})

			t.Run("ShouldBoundARefreshTokenSubjectByItsGrant", func(t *testing.T) {
				testCases := []struct {
					name            string
					grantedScopes   []string
					grantedAudience string
					grantedResource string
					requestedScope  string
					narrow          func(env *idjagEnvironment, client *oauth2.DefaultClient)
					expected        string
					err             string
				}{
					// Section 4.3.3: the requested scopes, audience and resources remain within the authorization context of the refresh token.
					{name: "ShouldRejectAScopeNotGranted", grantedScopes: []string{idjagOtherScope}, grantedAudience: idjagEnvironmentTarget, grantedResource: idjagEnvironmentTarget, requestedScope: idjagScope, err: oauth2.ErrInvalidScope.ErrorField},
					{name: "ShouldRejectAnAudienceNotGranted", grantedScopes: []string{idjagScope}, grantedAudience: idjagOtherTarget, grantedResource: idjagEnvironmentTarget, requestedScope: idjagScope, err: oauth2.ErrInvalidTarget.ErrorField},
					{name: "ShouldRejectAnAudienceWhenNoneWasGranted", grantedScopes: []string{idjagScope}, grantedResource: idjagEnvironmentTarget, requestedScope: idjagScope, err: oauth2.ErrInvalidTarget.ErrorField},
					{name: "ShouldRejectAResourceNotGranted", grantedScopes: []string{idjagScope}, grantedAudience: idjagEnvironmentTarget, grantedResource: idjagOtherTarget, requestedScope: idjagScope, err: oauth2.ErrInvalidTarget.ErrorField},
					{name: "ShouldRejectAResourceWhenNoneWasGranted", grantedScopes: []string{idjagScope}, grantedAudience: idjagEnvironmentTarget, requestedScope: idjagScope, err: oauth2.ErrInvalidTarget.ErrorField},
					// Section 4.3.3: the refresh token is validated as for a refresh_token grant, against the current registration.
					{name: "ShouldRejectAScopeRemovedFromTheClient", grantedScopes: []string{idjagScope}, grantedAudience: idjagEnvironmentTarget, grantedResource: idjagEnvironmentTarget, requestedScope: idjagScope, narrow: func(_ *idjagEnvironment, client *oauth2.DefaultClient) { client.Scopes = []string{idjagOtherScope} }, err: oauth2.ErrInvalidScope.ErrorField},
					{name: "ShouldRejectAnAudienceRemovedFromTheClient", grantedScopes: []string{idjagScope}, grantedAudience: idjagEnvironmentTarget, grantedResource: idjagEnvironmentTarget, requestedScope: idjagScope, narrow: func(env *idjagEnvironment, client *oauth2.DefaultClient) {
						client.Audience = []string{env.rs.URL + idjagResourcePath}
					}, err: oauth2.ErrInvalidTarget.ErrorField},
					{name: "ShouldRejectAResourceRemovedFromTheClient", grantedScopes: []string{idjagScope}, grantedAudience: idjagEnvironmentTarget, grantedResource: idjagEnvironmentTarget, requestedScope: idjagScope, narrow: func(env *idjagEnvironment, client *oauth2.DefaultClient) { client.Resource = nil }, err: oauth2.ErrInvalidTarget.ErrorField},
					// Section 4.3.3: the relationship policy still narrows the granted scopes.
					{name: "ShouldNarrowByTheRelationship", grantedScopes: []string{idjagScope, idjagOtherScope}, grantedAudience: idjagEnvironmentTarget, grantedResource: idjagEnvironmentTarget, requestedScope: idjagScope + " " + idjagOtherScope, expected: idjagScope},
				}

				for _, tc := range testCases {
					t.Run(tc.name, func(t *testing.T) {
						env := newIDJAGEnvironment(t, s.new)

						resolve := func(value, target string) []string {
							switch value {
							case "":
								return nil
							case idjagEnvironmentTarget:
								return []string{target}
							default:
								return []string{value}
							}
						}

						form := env.exchangeForm(env.refreshToken(t, tc.grantedScopes, resolve(tc.grantedAudience, env.rs.URL), resolve(tc.grantedResource, env.rs.URL+idjagResourcePath)), consts.TokenTypeRFC8693RefreshToken, env.rs.URL)

						if tc.narrow != nil {
							client, ok := env.idpClient.(*oauth2.DefaultClient)
							require.True(t, ok)

							tc.narrow(env, client)
						}

						form.Set(consts.FormParameterScope, tc.requestedScope)

						status, token, errBody := postIDJAGToken(t, env.idp, idjagIdPClientID, form, "")

						if tc.err != "" {
							assert.Equal(t, http.StatusBadRequest, status)
							assert.Equal(t, tc.err, errBody.Error)
							assert.Empty(t, token.AccessToken)

							return
						}

						require.Equal(t, http.StatusOK, status, "exchange error: %+v", errBody)
						assert.Equal(t, tc.expected, token.Scope)

						_, claims := env.decodeIDJAG(t, token.AccessToken)

						assert.Equal(t, tc.expected, claims[consts.ClaimScope])
					})
				}
			})

			t.Run("ShouldBindWithDPoP", func(t *testing.T) {
				env := newIDJAGEnvironment(t, s.new)
				key := newDPoPProofKey(t)

				grant := env.exchangeWithDPoP(t, key)

				proof := signDPoPProof(t, key, http.MethodPost, env.rs.URL+tokenRelativePath, nil)

				status, redeemed, errBody := postIDJAGToken(t, env.rs, idjagRSClientID, idjagRedeemForm(grant), proof)

				require.Equal(t, http.StatusOK, status, "redeem error: %+v", errBody)
				assert.Equal(t, oauth2.DPoPAccessToken, redeemed.TokenType)
				assert.Equal(t, idjagScope, redeemed.Scope)
				assert.Empty(t, redeemed.RefreshToken)
			})

			t.Run("ShouldRejectMissingProof", func(t *testing.T) {
				env := newIDJAGEnvironment(t, s.new)

				grant := env.exchangeWithDPoP(t, newDPoPProofKey(t))

				status, _, errBody := postIDJAGToken(t, env.rs, idjagRSClientID, idjagRedeemForm(grant), "")

				// Section 9.8.1.2.2.
				assert.Equal(t, http.StatusBadRequest, status)
				assert.Equal(t, "invalid_grant", errBody.Error)
			})

			t.Run("ShouldRejectMismatchedProof", func(t *testing.T) {
				env := newIDJAGEnvironment(t, s.new)

				grant := env.exchangeWithDPoP(t, newDPoPProofKey(t))

				proof := signDPoPProof(t, newDPoPProofKey(t), http.MethodPost, env.rs.URL+tokenRelativePath, nil)

				status, _, errBody := postIDJAGToken(t, env.rs, idjagRSClientID, idjagRedeemForm(grant), proof)

				// Section 9.8.1.2.1.
				assert.Equal(t, http.StatusBadRequest, status)
				assert.Equal(t, "invalid_grant", errBody.Error)
			})

			// Section 9.8.1.2.1 and draft-parecki-oauth-jwt-dpop-grant-01 Section 4.
			t.Run("ShouldRedeemWithJWTDPoP", func(t *testing.T) {
				testCases := []struct {
					name      string
					unbound   bool
					proof     string
					withheld  bool
					status    int
					err       string
					tokenType string
				}{
					{name: "ShouldIssueABoundToken", proof: idjagProofMatch, status: http.StatusOK, tokenType: oauth2.DPoPAccessToken},
					{name: "ShouldRejectMissingProof", status: http.StatusBadRequest, err: oauth2.ErrInvalidGrant.ErrorField},
					{name: "ShouldRejectMismatchedProof", proof: idjagProofOther, status: http.StatusBadRequest, err: oauth2.ErrInvalidGrant.ErrorField},
					{name: "ShouldRejectUnboundGrant", unbound: true, proof: idjagProofMatch, status: http.StatusBadRequest, err: oauth2.ErrInvalidGrant.ErrorField},
					{name: "ShouldRejectClientWithoutTheGrantType", withheld: true, proof: idjagProofMatch, status: http.StatusBadRequest, err: oauth2.ErrUnauthorizedClient.ErrorField},
				}

				for _, tc := range testCases {
					t.Run(tc.name, func(t *testing.T) {
						env := newIDJAGEnvironment(t, s.new)
						key := newDPoPProofKey(t)

						if !tc.withheld {
							client := env.rsMemory.Clients[idjagRSClientID].(*oauth2.DefaultClient)
							client.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer, consts.GrantTypeOAuthJWTDPoP}
						}

						var grant string

						if tc.unbound {
							grant = env.grant(t)
						} else {
							grant = env.exchangeWithDPoP(t, key)
						}

						var proof string

						switch tc.proof {
						case idjagProofMatch:
							proof = signDPoPProof(t, key, http.MethodPost, env.rs.URL+tokenRelativePath, nil)
						case idjagProofOther:
							proof = signDPoPProof(t, newDPoPProofKey(t), http.MethodPost, env.rs.URL+tokenRelativePath, nil)
						}

						form := idjagRedeemForm(grant)
						form.Set(consts.FormParameterGrantType, consts.GrantTypeOAuthJWTDPoP)

						status, redeemed, errBody := postIDJAGToken(t, env.rs, idjagRSClientID, form, proof)
						require.Equal(t, tc.status, status, "redeem error: %+v", errBody)
						assert.Equal(t, tc.err, errBody.Error, "%+v", errBody)
						assert.Equal(t, tc.tokenType, redeemed.TokenType)
					})
				}
			})

			// Section 9.8.1.2.2: the Resource Server requires DPoP.
			t.Run("ShouldRejectMissingProofWhenEnforced", func(t *testing.T) {
				env := newIDJAGEnvironment(t, s.new, idjagOptions{enforce: true})

				grant := env.exchangeWithDPoP(t, newDPoPProofKey(t))

				status, _, errBody := postIDJAGToken(t, env.rs, idjagRSClientID, idjagRedeemForm(grant), "")
				assert.Equal(t, http.StatusBadRequest, status)
				assert.Equal(t, oauth2.ErrInvalidGrant.ErrorField, errBody.Error, "%+v", errBody)
			})

			// Section 9.8.1.2.4 item 2.
			t.Run("ShouldRejectUnboundGrantWithoutProofWhenEnforced", func(t *testing.T) {
				env := newIDJAGEnvironment(t, s.new, idjagOptions{enforce: true})

				status, _, errBody := postIDJAGToken(t, env.rs, idjagRSClientID, idjagRedeemForm(env.grant(t)), "")
				assert.Equal(t, http.StatusBadRequest, status)
				assert.Equal(t, oauth2.ErrInvalidGrant.ErrorField, errBody.Error, "%+v", errBody)
			})

			// RFC 9449 Section 4.3: a malformed proof is still an invalid DPoP proof.
			t.Run("ShouldRejectMalformedProofWhenEnforced", func(t *testing.T) {
				env := newIDJAGEnvironment(t, s.new, idjagOptions{enforce: true})

				grant := env.exchangeWithDPoP(t, newDPoPProofKey(t))

				status, _, errBody := postIDJAGToken(t, env.rs, idjagRSClientID, idjagRedeemForm(grant), "not-a-proof")
				assert.Equal(t, http.StatusBadRequest, status)
				assert.Equal(t, oauth2.ErrInvalidDPoPProof.ErrorField, errBody.Error, "%+v", errBody)
			})

			t.Run("ShouldBindWithDPoPWhenEnforced", func(t *testing.T) {
				env := newIDJAGEnvironment(t, s.new, idjagOptions{enforce: true})
				key := newDPoPProofKey(t)

				grant := env.exchangeWithDPoP(t, key)

				proof := signDPoPProof(t, key, http.MethodPost, env.rs.URL+tokenRelativePath, nil)

				status, redeemed, errBody := postIDJAGToken(t, env.rs, idjagRSClientID, idjagRedeemForm(grant), proof)
				require.Equal(t, http.StatusOK, status, "redeem error: %+v", errBody)
				assert.Equal(t, oauth2.DPoPAccessToken, redeemed.TokenType)
			})

			// Section 9.8.1.2.3: an unbound grant presented with a proof yields a DPoP-bound access token.
			t.Run("ShouldBindUnboundGrantPresentedWithProof", func(t *testing.T) {
				env := newIDJAGEnvironment(t, s.new)

				status, token, errBody := postIDJAGToken(t, env.idp, idjagIdPClientID, env.exchangeForm(env.idToken(t), consts.TokenTypeRFC8693IDToken, env.rs.URL), "")
				require.Equal(t, http.StatusOK, status, "exchange error: %+v", errBody)

				proof := signDPoPProof(t, newDPoPProofKey(t), http.MethodPost, env.rs.URL+tokenRelativePath, nil)

				status, redeemed, errBody := postIDJAGToken(t, env.rs, idjagRSClientID, idjagRedeemForm(token.AccessToken), proof)

				require.Equal(t, http.StatusOK, status, "redeem error: %+v", errBody)
				assert.Equal(t, oauth2.DPoPAccessToken, redeemed.TokenType)
			})

			// RFC 7521 Section 4.1.1: a replayed single-use grant is an invalid grant.
			t.Run("ShouldRejectReplayWhenSingleUse", func(t *testing.T) {
				env := newIDJAGEnvironment(t, s.new, idjagOptions{singleUse: true})

				grant := env.grant(t)

				status, _, errBody := postIDJAGToken(t, env.rs, idjagRSClientID, idjagRedeemForm(grant), "")
				require.Equal(t, http.StatusOK, status, "redeem error: %+v", errBody)

				status, _, errBody = postIDJAGToken(t, env.rs, idjagRSClientID, idjagRedeemForm(grant), "")
				assert.Equal(t, http.StatusBadRequest, status)
				assert.Equal(t, oauth2.ErrInvalidGrant.ErrorField, errBody.Error)
			})

			t.Run("ShouldNotConsumeAGrantRejectedForScope", func(t *testing.T) {
				env := newIDJAGEnvironment(t, s.new, idjagOptions{singleUse: true})

				grant := env.grant(t)

				form := idjagRedeemForm(grant)
				form.Set(consts.FormParameterScope, idjagOtherScope)

				status, _, errBody := postIDJAGToken(t, env.rs, idjagRSClientID, form, "")
				require.Equal(t, http.StatusBadRequest, status)
				require.Equal(t, oauth2.ErrInvalidScope.ErrorField, errBody.Error)

				status, _, errBody = postIDJAGToken(t, env.rs, idjagRSClientID, idjagRedeemForm(grant), "")
				assert.Equal(t, http.StatusOK, status, "redeem error: %+v", errBody)
			})

			t.Run("ShouldNotConsumeAGrantRejectedForMissingProof", func(t *testing.T) {
				env := newIDJAGEnvironment(t, s.new, idjagOptions{singleUse: true})
				key := newDPoPProofKey(t)

				grant := env.exchangeWithDPoP(t, key)

				status, _, errBody := postIDJAGToken(t, env.rs, idjagRSClientID, idjagRedeemForm(grant), "")
				require.Equal(t, http.StatusBadRequest, status)
				require.Equal(t, oauth2.ErrInvalidGrant.ErrorField, errBody.Error)

				proof := signDPoPProof(t, key, http.MethodPost, env.rs.URL+tokenRelativePath, nil)

				status, redeemed, errBody := postIDJAGToken(t, env.rs, idjagRSClientID, idjagRedeemForm(grant), proof)
				require.Equal(t, http.StatusOK, status, "redeem error: %+v", errBody)
				assert.Equal(t, oauth2.DPoPAccessToken, redeemed.TokenType)
			})

			// RFC 8707 Section 2.2: a requested resource must be within the grant.
			t.Run("ShouldRejectARequestedResourceOutsideTheGrant", func(t *testing.T) {
				env := newIDJAGEnvironment(t, s.new)

				form := idjagRedeemForm(env.grant(t))
				form.Set(consts.FormParameterResource, idjagOtherTarget)

				status, _, errBody := postIDJAGToken(t, env.rs, idjagRSClientID, form, "")
				assert.Equal(t, http.StatusBadRequest, status)
				assert.Equal(t, oauth2.ErrInvalidTarget.ErrorField, errBody.Error)
			})

			// Section 4.4: the client authenticates, even when RFC 7523 grants may skip client authentication.
			t.Run("ShouldRejectAnUnauthenticatedGrantWhenSkipClientAuthIsEnabled", func(t *testing.T) {
				env := newIDJAGEnvironment(t, s.new, idjagOptions{skipClientAuth: true})

				status, redeemed, errBody := postIDJAGToken(t, env.rs, "", idjagRedeemForm(env.grant(t)), "")
				assert.Equal(t, http.StatusUnauthorized, status)
				assert.Equal(t, oauth2.ErrInvalidClient.ErrorField, errBody.Error, "%+v", errBody)
				assert.Empty(t, redeemed.AccessToken)
			})

			t.Run("ShouldCarryAuthorizationDetails", func(t *testing.T) {
				env := newIDJAGEnvironment(t, s.new, idjagOptions{rar: true})

				requested := idjagDetailsInitiate

				form := env.exchangeForm(env.idToken(t), consts.TokenTypeRFC8693IDToken, env.rs.URL)
				form.Set(consts.FormParameterAuthorizationDetails, requested)

				status, token, errBody := postIDJAGToken(t, env.idp, idjagIdPClientID, form, "")
				require.Equal(t, http.StatusOK, status, "exchange error: %+v", errBody)
				assert.JSONEq(t, requested, string(token.AuthorizationDetails))

				_, claims := env.decodeIDJAG(t, token.AccessToken)
				assert.Equal(t, []any{map[string]any{"type": internal.AuthorizationDetailsTypePaymentInitiation, "actions": []any{idjagInitiate}}}, claims[consts.ClaimAuthorizationDetails])

				// Section 4.4.1: the granted details are included in the access token response.
				status, redeemed, errBody := postIDJAGToken(t, env.rs, idjagRSClientID, idjagRedeemForm(token.AccessToken), "")
				require.Equal(t, http.StatusOK, status, "redeem error: %+v", errBody)
				assert.JSONEq(t, requested, string(redeemed.AuthorizationDetails))

				// Section 4.4.1: the granted details are bound to the issued access token.
				_, ar, err := env.rsProvider.IntrospectToken(t.Context(), redeemed.AccessToken, oauth2.AccessToken, &oauth2.DefaultSession{})
				require.NoError(t, err)
				assert.Equal(t, oauth2.AuthorizationDetails{{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{idjagInitiate}}}, ar.GetGrantedAuthorizationDetails())
			})

			t.Run("ShouldBoundARefreshTokenSubjectAuthorizationDetailsByItsGrant", func(t *testing.T) {
				initiate := oauth2.AuthorizationDetail{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{idjagInitiate}}
				both := oauth2.AuthorizationDetail{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{idjagInitiate, idjagStatus}}

				testCases := []struct {
					name      string
					granted   oauth2.AuthorizationDetails
					requested string
					err       string
				}{
					// Section 4.3.3: the requested details remain within the authorization context of the refresh token.
					{name: "ShouldAcceptContainedDetails", granted: oauth2.AuthorizationDetails{both}, requested: idjagDetailsStatus},
					{name: "ShouldRejectDetailsNotGranted", granted: oauth2.AuthorizationDetails{initiate}, requested: idjagDetailsStatus, err: oauth2.ErrInvalidAuthorizationDetails.ErrorField},
					{name: "ShouldRejectDetailsWhenNoneWereGranted", requested: idjagDetailsInitiate, err: oauth2.ErrInvalidAuthorizationDetails.ErrorField},
				}

				for _, tc := range testCases {
					t.Run(tc.name, func(t *testing.T) {
						env := newIDJAGEnvironment(t, s.new, idjagOptions{rar: true})

						form := env.exchangeForm(env.refreshToken(t, []string{idjagScope}, []string{env.rs.URL}, []string{env.rs.URL + idjagResourcePath}, tc.granted...), consts.TokenTypeRFC8693RefreshToken, env.rs.URL)
						form.Set(consts.FormParameterAuthorizationDetails, tc.requested)

						status, token, errBody := postIDJAGToken(t, env.idp, idjagIdPClientID, form, "")

						if tc.err != "" {
							assert.Equal(t, http.StatusBadRequest, status)
							assert.Equal(t, tc.err, errBody.Error)
							assert.Empty(t, token.AccessToken)

							return
						}

						require.Equal(t, http.StatusOK, status, "exchange error: %+v", errBody)
						assert.JSONEq(t, tc.requested, string(token.AuthorizationDetails))
					})
				}
			})

			t.Run("ShouldIgnoreAuthorizationDetailsWhenDisabled", func(t *testing.T) {
				env := newIDJAGEnvironment(t, s.new)

				form := env.exchangeForm(env.idToken(t), consts.TokenTypeRFC8693IDToken, env.rs.URL)
				form.Set(consts.FormParameterAuthorizationDetails, "not json")

				status, token, errBody := postIDJAGToken(t, env.idp, idjagIdPClientID, form, "")
				require.Equal(t, http.StatusOK, status, "exchange error: %+v", errBody)
				assert.Empty(t, token.AuthorizationDetails)

				_, claims := env.decodeIDJAG(t, token.AccessToken)
				assert.NotContains(t, claims, consts.ClaimAuthorizationDetails)
			})

			// Section 9.1: the grant is for confidential clients.
			t.Run("ShouldRejectPublicClient", func(t *testing.T) {
				env := newIDJAGEnvironment(t, s.new)

				status, token, errBody := postIDJAGToken(t, env.idp, idjagIdPClientID, env.exchangeForm(env.idToken(t), consts.TokenTypeRFC8693IDToken, env.rs.URL), "")
				require.Equal(t, http.StatusOK, status, "exchange error: %+v", errBody)

				env.rsMemory.Clients[idjagRSClientID] = &oauth2.DefaultClient{
					ID:         idjagRSClientID,
					Public:     true,
					GrantTypes: []string{consts.GrantTypeOAuthJWTBearer},
					Scopes:     []string{idjagScope},
					Resource:   []string{env.rs.URL + idjagResourcePath},
				}

				form := idjagRedeemForm(token.AccessToken)
				form.Set(consts.FormParameterClientID, idjagRSClientID)

				status, redeemed, errBody := postIDJAGToken(t, env.rs, "", form, "")

				assert.Equal(t, http.StatusBadRequest, status)
				assert.Equal(t, "unauthorized_client", errBody.Error)
				assert.Empty(t, redeemed.AccessToken)
			})

			t.Run("ShouldRejectUnknownAudience", func(t *testing.T) {
				env := newIDJAGEnvironment(t, s.new)

				status, token, errBody := postIDJAGToken(t, env.idp, idjagIdPClientID, env.exchangeForm(env.idToken(t), consts.TokenTypeRFC8693IDToken, "https://unknown.example/"), "")

				assert.Equal(t, http.StatusBadRequest, status)
				assert.Equal(t, "invalid_target", errBody.Error)
				assert.Empty(t, token.AccessToken)
			})
		})
	}
}

type idjagTokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	RefreshToken    string `json:"refresh_token"`
	TokenType       string `json:"token_type"`
	Scope           string `json:"scope"`
	ExpiresIn       int64  `json:"expires_in"`
	Resource        any    `json:"resource"`

	AuthorizationDetails json.RawMessage `json:"authorization_details"`
}

type idjagOptions struct {
	enforce        bool
	singleUse      bool
	skipClientAuth bool
	rar            bool
}

type idjagEnvironment struct {
	idp, rs *httptest.Server

	rsProvider oauth2.Provider

	idpKey      *rsa.PrivateKey
	rsMemory    *storage.MemoryStore
	idpClient   oauth2.Client
	idpStore    hoauth2.CoreStorage
	idpJWT      jwt.Strategy
	idpStrategy hoauth2.CoreStrategy
}

func newIDJAGEnvironment(t *testing.T, newStore func() (hoauth2.CoreStorage, *storage.MemoryStore), opts ...idjagOptions) *idjagEnvironment {
	t.Helper()

	idpMux, rsMux := http.NewServeMux(), http.NewServeMux()

	env := &idjagEnvironment{
		idp:    httptest.NewServer(idpMux),
		rs:     httptest.NewServer(rsMux),
		idpKey: gen.MustRSAKey(),
	}

	t.Cleanup(env.idp.Close)
	t.Cleanup(env.rs.Close)

	idpConfig := &oauth2.Config{
		GlobalSecret:              []byte("idjag-integration-idp-secret-32-bytes"),
		AccessTokenIssuer:         env.idp.URL,
		DPoPEnabled:               true,
		DefaultRequestedTokenType: consts.TokenTypeRFC8693AccessToken,
		RFC8693TokenTypes: map[string]oauth2.RFC8693TokenType{
			consts.TokenTypeRFC8693IDToken:      &rfc8693.DefaultTokenType{Name: consts.TokenTypeRFC8693IDToken},
			consts.TokenTypeRFC8693RefreshToken: &rfc8693.DefaultTokenType{Name: consts.TokenTypeRFC8693RefreshToken},
			consts.TokenTypeRFC8693IDJAG:        &rfc8693.DefaultTokenType{Name: consts.TokenTypeRFC8693IDJAG},
		},
	}

	idpStore, idpMemory := newStore()

	env.idpClient = &oauth2.DefaultClient{
		ID:           idjagIdPClientID,
		ClientSecret: oauth2.NewBCryptClientSecret(idjagSecretHash),
		GrantTypes:   []string{consts.GrantTypeOAuthTokenExchange, consts.GrantTypeRefreshToken},
		Scopes:       []string{idjagScope, idjagOtherScope},
		Audience:     []string{env.rs.URL},
		Resource:     []string{env.rs.URL + idjagResourcePath},
	}

	idpMemory.Clients[idjagIdPClientID] = env.idpClient
	idpMemory.IDJAGRelationships[storage.IDJAGRelationshipKey{ClientID: idjagIdPClientID, Audience: env.rs.URL}] = oauth2.IDJAGRelationship{
		Issuer:    env.rs.URL,
		ClientID:  idjagRSClientID,
		Scopes:    []string{idjagScope},
		Resources: []string{env.rs.URL + idjagResourcePath},
	}

	idpJWT := &jwt.DefaultStrategy{Config: idpConfig, Issuer: jwt.NewDefaultIssuerRS256Unverified(env.idpKey)}
	idpStrategy := compose.NewOAuth2HMACStrategy(idpConfig)

	env.idpStore, env.idpJWT, env.idpStrategy = idpStore, idpJWT, idpStrategy

	idpProvider := compose.Compose(
		idpConfig,
		idpStore,
		&compose.CommonStrategy{
			CoreStrategy:               idpStrategy,
			OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(func(context.Context) (any, error) { return env.idpKey, nil }, idpJWT, idpConfig),
			Strategy:                   idpJWT,
		},
		compose.RFC8693TokenExchangeGrantFactory,
		compose.RFC8693RefreshTokenTypeFactory,
		compose.RFC8693IDTokenTypeFactory,
		compose.IDJAGIssueFactory,
		compose.RFC8693ActorTokenValidationFactory,
		compose.DPoPTokenFactory,
	)

	idpMux.HandleFunc(tokenRelativePath, idjagTokenHandler(idpProvider, func() oauth2.Session { return rfc8693.NewDefaultSession() }))

	rsConfig := &oauth2.Config{
		GlobalSecret:                            []byte("idjag-integration-rs-secret-32-bytes!"),
		AuthorizationServerIdentificationIssuer: env.rs.URL,
		DPoPEnabled:                             true,
	}

	if len(opts) != 0 {
		rsConfig.DPoPEnforce = opts[0].enforce
		rsConfig.IDJAGSingleUse = opts[0].singleUse
		rsConfig.GrantTypeJWTBearerCanSkipClientAuth = opts[0].skipClientAuth

		if opts[0].rar {
			idpConfig.AuthorizationDetailsTypeHandlers = []oauth2.AuthorizationDetailsTypeHandler{internal.PaymentInitiationTypeHandler{}}
			rsConfig.AuthorizationDetailsTypeHandlers = []oauth2.AuthorizationDetailsTypeHandler{internal.PaymentInitiationTypeHandler{}}
		}
	}

	rsStore, rsMemory := newStore()

	env.rsMemory = rsMemory

	rsMemory.Clients[idjagRSClientID] = &oauth2.DefaultClient{
		ID:           idjagRSClientID,
		ClientSecret: oauth2.NewBCryptClientSecret(idjagSecretHash),
		GrantTypes:   []string{consts.GrantTypeOAuthJWTBearer},
		Scopes:       []string{idjagScope},
		Resource:     []string{env.rs.URL + idjagResourcePath},
	}

	rsMemory.IDJAGTrustedIssuers[env.idp.URL] = oauth2.IDJAGTrustedIssuer{
		Issuer: env.idp.URL,
		JSONWebKeys: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       &env.idpKey.PublicKey,
			KeyID:     "default",
			Algorithm: string(jose.RS256),
			Use:       consts.JSONWebTokenUseSignature,
		}}},
		SigningAlgs: []string{string(jose.RS256)},
	}
	rsMemory.IDJAGSubjects[storage.IDJAGSubjectKey{Issuer: env.idp.URL, Subject: idjagSubject}] = idjagSubject

	rsJWT := &jwt.DefaultStrategy{Config: rsConfig, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())}

	rsProvider := compose.Compose(
		rsConfig,
		rsStore,
		&compose.CommonStrategy{
			CoreStrategy: compose.NewOAuth2HMACStrategy(rsConfig),
			Strategy:     rsJWT,
		},
		compose.RFC7523AssertionGrantFactory,
		compose.DPoPTokenFactory,
		compose.IDJAGRedeemFactory,
		compose.OAuth2TokenIntrospectionFactory,
	)

	env.rsProvider = rsProvider

	rsMux.HandleFunc(tokenRelativePath, idjagTokenHandler(rsProvider, func() oauth2.Session { return &oauth2.DefaultSession{} }))

	return env
}

func (env *idjagEnvironment) idToken(t *testing.T) string {
	t.Helper()

	now := time.Now().UTC()

	token, _, err := env.idpJWT.Encode(context.Background(), jwt.MapClaims{
		consts.ClaimAudience:                            []string{idjagIdPClientID},
		consts.ClaimSubject:                             idjagSubject,
		consts.ClaimIssuer:                              env.idp.URL,
		consts.ClaimExpirationTime:                      now.Add(10 * time.Minute).Unix(),
		consts.ClaimIssuedAt:                            now.Unix(),
		consts.ClaimAuthenticationTime:                  now.Add(-idjagAuthAge).Unix(),
		consts.ClaimAuthenticationContextClassReference: idjagACR,
		consts.ClaimAuthenticationMethodsReference:      []string{idjagAMR},
	}, jwt.WithIDTokenClient(env.idpClient))
	require.NoError(t, err)

	return token
}

func (env *idjagEnvironment) refreshToken(t *testing.T, scopes, audience, resources []string, details ...oauth2.AuthorizationDetail) string {
	t.Helper()

	return env.refreshTokenWithSession(t, &oauth2.DefaultSession{
		Username: idjagSubject,
		Subject:  idjagSubject,
		ExpiresAt: map[oauth2.TokenType]time.Time{
			oauth2.RefreshToken: time.Now().UTC().Add(10 * time.Minute),
		},
	}, scopes, audience, resources, details...)
}

func (env *idjagEnvironment) refreshTokenWithSession(t *testing.T, session oauth2.Session, scopes, audience, resources []string, details ...oauth2.AuthorizationDetail) string {
	t.Helper()

	ctx := context.Background()

	request := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
		Request: oauth2.Request{
			ID:              uuid.New().String(),
			RequestedAt:     time.Now().UTC(),
			Client:          env.idpClient,
			GrantedScope:    append(oauth2.Arguments{consts.ScopeOfflineAccess}, scopes...),
			GrantedAudience: audience,
			GrantedResource: resources,
			Session:         session,
		},
	}

	if len(details) != 0 {
		request.SetGrantedAuthorizationDetails(details)
	}

	token, signature, err := env.idpStrategy.GenerateRefreshToken(ctx, request)
	require.NoError(t, err)
	require.NoError(t, env.idpStore.CreateRefreshTokenSession(ctx, signature, "", request.Sanitize(nil)))

	return token
}

func (env *idjagEnvironment) grant(t *testing.T) string {
	t.Helper()

	status, token, errBody := postIDJAGToken(t, env.idp, idjagIdPClientID, env.exchangeForm(env.idToken(t), consts.TokenTypeRFC8693IDToken, env.rs.URL), "")
	require.Equal(t, http.StatusOK, status, "exchange error: %+v", errBody)

	return token.AccessToken
}

func (env *idjagEnvironment) exchangeForm(subjectToken, subjectTokenType, audience string) url.Values {
	return url.Values{
		consts.FormParameterGrantType:          {consts.GrantTypeOAuthTokenExchange},
		consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693IDJAG},
		consts.FormParameterAudience:           {audience},
		consts.FormParameterResource:           {env.rs.URL + idjagResourcePath},
		consts.FormParameterScope:              {idjagScope},
		consts.FormParameterSubjectToken:       {subjectToken},
		consts.FormParameterSubjectTokenType:   {subjectTokenType},
	}
}

func (env *idjagEnvironment) exchangeWithDPoP(t *testing.T, key *jose.JSONWebKey) string {
	t.Helper()

	proof := signDPoPProof(t, key, http.MethodPost, env.idp.URL+tokenRelativePath, nil)

	status, token, errBody := postIDJAGToken(t, env.idp, idjagIdPClientID, env.exchangeForm(env.idToken(t), consts.TokenTypeRFC8693IDToken, env.rs.URL), proof)

	require.Equal(t, http.StatusOK, status, "exchange error: %+v", errBody)
	assert.Equal(t, oauth2.RFC8693NAToken, token.TokenType)
	assert.Equal(t, consts.TokenTypeRFC8693IDJAG, token.IssuedTokenType)
	assert.Empty(t, token.RefreshToken)

	_, claims := env.decodeIDJAG(t, token.AccessToken)

	pub := key.Public()

	jkt, err := jwt.ThumbprintJWK(&pub)
	require.NoError(t, err)

	assert.Equal(t, map[string]any{consts.ClaimConfirmationJWKThumbprint: jkt}, claims[consts.ClaimConfirmation])

	return token.AccessToken
}

func (env *idjagEnvironment) decodeIDJAG(t *testing.T, raw string) (typ string, claims map[string]any) {
	t.Helper()

	token, err := josejwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)
	require.Len(t, token.Headers, 1)

	require.NoError(t, token.Claims(&env.idpKey.PublicKey, &claims))

	typ, _ = token.Headers[0].ExtraHeaders[jose.HeaderKey(consts.JSONWebTokenHeaderType)].(string)

	return typ, claims
}

func idjagRedeemForm(assertion string) url.Values {
	return url.Values{
		consts.FormParameterGrantType: {consts.GrantTypeOAuthJWTBearer},
		consts.FormParameterAssertion: {assertion},
	}
}

func idjagTokenHandler(provider oauth2.Provider, newSession func() oauth2.Session) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		ctx := req.Context()

		request, err := provider.NewAccessRequest(ctx, req, newSession())
		if err != nil {
			provider.WriteAccessError(ctx, rw, request, err)

			return
		}

		response, err := provider.NewAccessResponse(ctx, request)
		if err != nil {
			provider.WriteAccessError(ctx, rw, request, err)

			return
		}

		provider.WriteAccessResponse(ctx, rw, request, response)
	}
}

func postIDJAGToken(t *testing.T, ts *httptest.Server, clientID string, form url.Values, dpopProof string) (status int, token idjagTokenResponse, errBody oidckbErrorResponse) {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, ts.URL+tokenRelativePath, strings.NewReader(form.Encode()))
	require.NoError(t, err)

	req.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
	if clientID != "" {
		req.SetBasicAuth(clientID, idjagClientSecret)
	}

	if dpopProof != "" {
		req.Header.Set(consts.HeaderDPoP, dpopProof)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	if resp.StatusCode >= http.StatusBadRequest {
		require.NoError(t, json.Unmarshal(body, &errBody), "error response: %s", body)
	} else {
		require.NoError(t, json.Unmarshal(body, &token), "token response: %s", body)
	}

	return resp.StatusCode, token, errBody
}
