// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
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
	h := &OpenIDConnectRefreshHandler{Config: &oauth2.Config{}}
	for _, c := range []struct {
		areq        *oauth2.AccessRequest
		expectedErr error
		description string
	}{
		{
			description: "should not pass because grant_type is wrong",
			areq: &oauth2.AccessRequest{
				GrantTypes: []string{"foo"},
			},
			expectedErr: oauth2.ErrUnknownRequest,
		},
		{
			description: "should not pass because grant_type is right but scope is missing",
			areq: &oauth2.AccessRequest{
				GrantTypes: []string{consts.GrantTypeRefreshToken},
				Request: oauth2.Request{
					GrantedScope: []string{"something"},
				},
			},
			expectedErr: oauth2.ErrUnknownRequest,
		},
		{
			description: "should not pass because client may not execute this grant type",
			areq: &oauth2.AccessRequest{
				GrantTypes: []string{consts.GrantTypeRefreshToken},
				Request: oauth2.Request{
					GrantedScope: []string{consts.ScopeOpenID},
					Client:       &oauth2.DefaultClient{},
				},
			},
			expectedErr: oauth2.ErrUnauthorizedClient,
		},
		{
			description: "should pass",
			areq: &oauth2.AccessRequest{
				GrantTypes: []string{consts.GrantTypeRefreshToken},
				Request: oauth2.Request{
					GrantedScope: []string{consts.ScopeOpenID},
					Client: &oauth2.DefaultClient{
						GrantTypes: []string{consts.GrantTypeRefreshToken},
						//ResponseTypes: []string{"id_token"},
					},
					Session: &DefaultSession{},
				},
			},
		},
	} {
		t.Run("case="+c.description, func(t *testing.T) {
			err := h.HandleTokenEndpointRequest(context.TODO(), c.areq)
			if c.expectedErr != nil {
				require.EqualError(t, err, c.expectedErr.Error(), "%v", err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestOpenIDConnectRefreshHandler_PopulateTokenEndpointResponse(t *testing.T) {
	var j = &DefaultStrategy{
		Signer: &jwt.DefaultSigner{
			GetPrivateKey: func(ctx context.Context) (any, error) {
				return key, nil
			},
		},
		Config: &oauth2.Config{
			MinParameterEntropy: oauth2.MinParameterEntropy,
		},
	}

	h := &OpenIDConnectRefreshHandler{
		IDTokenHandleHelper: &IDTokenHandleHelper{
			IDTokenStrategy: j,
		},
		Config: &oauth2.Config{},
	}
	for _, c := range []struct {
		areq        *oauth2.AccessRequest
		expectedErr error
		check       func(t *testing.T, aresp *oauth2.AccessResponse)
		description string
	}{
		{
			description: "should not pass because grant_type is wrong",
			areq: &oauth2.AccessRequest{
				GrantTypes: []string{"foo"},
			},
			expectedErr: oauth2.ErrUnknownRequest,
		},
		{
			description: "should not pass because grant_type is right but scope is missing",
			areq: &oauth2.AccessRequest{
				GrantTypes: []string{consts.GrantTypeRefreshToken},
				Request: oauth2.Request{
					GrantedScope: []string{"something"},
				},
			},
			expectedErr: oauth2.ErrUnknownRequest,
		},
		// Disabled because this is already handled at the authorize_request_handler
		//{
		//	description: "should not pass because client may not ask for id_token",
		//	areq: &oauth2.AccessRequest{
		//		GrantTypes: []string{consts.GrantTypeRefreshToken},
		//		Request: oauth2.Request{
		//			GrantedScope: []string{consts.ScopeOpenID},
		//			Client: &oauth2.DefaultClient{
		//				GrantTypes: []string{consts.GrantTypeRefreshToken},
		//			},
		//		},
		//	},
		//	expectedErr: oauth2.ErrUnknownRequest,
		//},
		{
			description: "should pass",
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
				claims := decodedIdToken.Claims
				assert.NotEmpty(t, claims[consts.ClaimAccessTokenHash])
				idTokenExp := internal.ExtractJwtExpClaim(t, idToken)
				require.NotEmpty(t, idTokenExp)
				internal.RequireEqualTime(t, time.Now().Add(time.Hour).UTC(), *idTokenExp, time.Minute)
			},
		},
		{
			description: "should pass",
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
				claims := decodedIdToken.Claims
				assert.NotEmpty(t, claims[consts.ClaimAccessTokenHash])
				idTokenExp := internal.ExtractJwtExpClaim(t, idToken)
				require.NotEmpty(t, idTokenExp)
				internal.RequireEqualTime(t, time.Now().Add(*internal.TestLifespans.RefreshTokenGrantIDTokenLifespan).UTC(), *idTokenExp, time.Minute)
			},
		},
		{
			description: "should fail because missing subject claim",
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
			expectedErr: oauth2.ErrServerError,
		},
		{
			description: "should fail because missing session",
			areq: &oauth2.AccessRequest{
				GrantTypes: []string{consts.GrantTypeRefreshToken},
				Request: oauth2.Request{
					GrantedScope: []string{consts.ScopeOpenID},
					Client: &oauth2.DefaultClient{
						GrantTypes: []string{consts.GrantTypeRefreshToken},
					},
				},
			},
			expectedErr: oauth2.ErrServerError,
		},
	} {
		t.Run("case="+c.description, func(t *testing.T) {
			aresp := oauth2.NewAccessResponse()
			err := h.PopulateTokenEndpointResponse(context.TODO(), c.areq, aresp)
			if c.expectedErr != nil {
				require.EqualError(t, err, c.expectedErr.Error(), "%v", err)
			} else {
				require.NoError(t, err)
			}

			if c.check != nil {
				c.check(t, aresp)
			}
		})
	}
}
