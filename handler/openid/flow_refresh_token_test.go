// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestOpenIDConnectRefreshHandler_HandleTokenEndpointRequest(t *testing.T) {
	testCases := []struct {
		name      string
		requester *oauth2.AccessRequest
		error     error
	}{
		{
			name: "ShouldFailInvalidGrantType",
			requester: &oauth2.AccessRequest{
				GrantTypes: []string{"foo"},
			},
			error: oauth2.ErrUnknownRequest,
		},
		{
			name: "ShouldFailWithCorrectGrantTypeButMissingScope",
			requester: &oauth2.AccessRequest{
				GrantTypes: []string{consts.GrantTypeRefreshToken},
				Request: oauth2.Request{
					GrantedScope: []string{"something"},
				},
			},
			error: oauth2.ErrUnknownRequest,
		},
		{
			name: "ShouldFailInvalidGrantTypeForClient",
			requester: &oauth2.AccessRequest{
				GrantTypes: []string{consts.GrantTypeRefreshToken},
				Request: oauth2.Request{
					GrantedScope: []string{consts.ScopeOpenID},
					Client:       &oauth2.DefaultClient{},
				},
			},
			error: oauth2.ErrUnauthorizedClient,
		},
		{
			name: "ShouldPass",
			requester: &oauth2.AccessRequest{
				GrantTypes: []string{consts.GrantTypeRefreshToken},
				Request: oauth2.Request{
					GrantedScope: []string{consts.ScopeOpenID},
					Client: &oauth2.DefaultClient{
						GrantTypes: []string{consts.GrantTypeRefreshToken},
					},
					Session: &DefaultSession{},
				},
			},
		},
	}

	handler := &OpenIDConnectRefreshHandler{Config: &oauth2.Config{}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := handler.HandleTokenEndpointRequest(t.Context(), tc.requester)

			if tc.error != nil {
				require.EqualError(t, err, tc.error.Error(), "%v", err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestOpenIDConnectRefreshHandler_PopulateTokenEndpointResponse(t *testing.T) {
	testCases := []struct {
		name  string
		areq  *oauth2.AccessRequest
		err   string
		check func(t *testing.T, aresp *oauth2.AccessResponse)
	}{
		{
			name: "ShouldFailGrantTypeIsWrong",
			areq: &oauth2.AccessRequest{
				GrantTypes: []string{"foo"},
			},
			err: "The handler is not responsible for this request.",
		},
		{
			name: "ShouldFailGrantTypeIsRightButScopeIsMissing",
			areq: &oauth2.AccessRequest{
				GrantTypes: []string{consts.GrantTypeRefreshToken},
				Request: oauth2.Request{
					GrantedScope: []string{"something"},
				},
			},
			err: "The handler is not responsible for this request.",
		},
		{
			name: "ShouldPass",
			areq: &oauth2.AccessRequest{
				GrantTypes: []string{consts.GrantTypeRefreshToken},
				Request: oauth2.Request{
					GrantedScope: []string{consts.ScopeOpenID},
					Client: &oauth2.DefaultClient{
						GrantTypes: []string{consts.GrantTypeRefreshToken},
					},
					Session: &DefaultSession{
						Subject: "foo",
						Claims: &jwt.IDTokenClaims{
							Subject: "foo",
						},
					},
				},
			},
			check: func(t *testing.T, aresp *oauth2.AccessResponse) {
				assert.NotEmpty(t, aresp.GetExtra(consts.AccessResponseIDToken))
				idToken, _ := aresp.GetExtra(consts.AccessResponseIDToken).(string)
				decodedIdToken, err := jwt.Parse(idToken, func(token *jwt.Token) (any, error) {
					return key.PublicKey, nil
				})
				require.NoError(t, err)
				claims := decodedIdToken.Claims.ToMapClaims()
				assert.NotEmpty(t, claims[consts.ClaimAccessTokenHash])
				idTokenExp := internal.ExtractJwtExpClaim(t, idToken)
				require.NotEmpty(t, idTokenExp)
				internal.RequireEqualTime(t, time.Now().Add(time.Hour).UTC(), *idTokenExp, time.Minute)
			},
		},
		{
			name: "ShouldPassWithCustomLifespans",
			areq: &oauth2.AccessRequest{
				GrantTypes: []string{consts.GrantTypeRefreshToken},
				Request: oauth2.Request{
					GrantedScope: []string{consts.ScopeOpenID},
					Client: &oauth2.DefaultClientWithCustomTokenLifespans{
						DefaultClient: &oauth2.DefaultClient{
							GrantTypes: []string{consts.GrantTypeRefreshToken},
							//ResponseTypes: []string{"id_token"},
						},
						TokenLifespans: &internal.TestLifespans,
					},
					Session: &DefaultSession{
						Subject: "foo",
						Claims: &jwt.IDTokenClaims{
							Subject: "foo",
						},
					},
				},
			},
			check: func(t *testing.T, aresp *oauth2.AccessResponse) {
				assert.NotEmpty(t, aresp.GetExtra(consts.AccessResponseIDToken))
				idToken, _ := aresp.GetExtra(consts.AccessResponseIDToken).(string)
				decodedIdToken, err := jwt.Parse(idToken, func(token *jwt.Token) (any, error) {
					return key.PublicKey, nil
				})
				require.NoError(t, err)
				claims := decodedIdToken.Claims.ToMapClaims()
				assert.NotEmpty(t, claims[consts.ClaimAccessTokenHash])
				idTokenExp := internal.ExtractJwtExpClaim(t, idToken)
				require.NotEmpty(t, idTokenExp)
				internal.RequireEqualTime(t, time.Now().Add(*internal.TestLifespans.RefreshTokenGrantIDTokenLifespan).UTC(), *idTokenExp, time.Minute)
			},
		},
		{
			name: "ShouldFailMissingSubjectClaim",
			areq: &oauth2.AccessRequest{
				GrantTypes: []string{consts.GrantTypeRefreshToken},
				Request: oauth2.Request{
					GrantedScope: []string{consts.ScopeOpenID},
					Client: &oauth2.DefaultClient{
						GrantTypes: []string{consts.GrantTypeRefreshToken},
						//ResponseTypes: []string{"id_token"},
					},
					Session: &DefaultSession{
						Subject: "foo",
						Claims:  &jwt.IDTokenClaims{},
					},
				},
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Failed to generate ID Token because subject is an empty string.",
		},
		{
			name: "ShouldFailMissingSession",
			areq: &oauth2.AccessRequest{
				GrantTypes: []string{consts.GrantTypeRefreshToken},
				Request: oauth2.Request{
					GrantedScope: []string{consts.ScopeOpenID},
					Client: &oauth2.DefaultClient{
						GrantTypes: []string{consts.GrantTypeRefreshToken},
					},
				},
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Failed to generate ID Token because the session is not of type 'openid.Session' which is required.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &oauth2.Config{}

			j := &DefaultStrategy{
				Strategy: &jwt.DefaultStrategy{
					Config: config,
					Issuer: jwt.NewDefaultIssuerRS256Unverified(key),
				},
				Config: &oauth2.Config{
					MinParameterEntropy: oauth2.MinParameterEntropy,
				},
			}

			h := &OpenIDConnectRefreshHandler{
				IDTokenHandleHelper: &IDTokenHandleHelper{
					IDTokenStrategy: j,
				},
				Config: config,
			}

			aresp := oauth2.NewAccessResponse()
			err := h.PopulateTokenEndpointResponse(t.Context(), tc.areq, aresp)
			if tc.err != "" {
				require.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err, "%v", err)
			} else {
				require.NoError(t, err)
			}

			if tc.check != nil {
				tc.check(t, aresp)
			}
		})
	}
}
