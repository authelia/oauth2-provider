// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/goauth2"
	"github.com/authelia/goauth2/internal"
	"github.com/authelia/goauth2/token/jwt"
)

func TestOpenIDConnectRefreshHandler_HandleTokenEndpointRequest(t *testing.T) {
	h := &OpenIDConnectRefreshHandler{Config: &goauth2.Config{}}
	for _, c := range []struct {
		areq        *goauth2.AccessRequest
		expectedErr error
		description string
	}{
		{
			description: "should not pass because grant_type is wrong",
			areq: &goauth2.AccessRequest{
				GrantTypes: []string{"foo"},
			},
			expectedErr: goauth2.ErrUnknownRequest,
		},
		{
			description: "should not pass because grant_type is right but scope is missing",
			areq: &goauth2.AccessRequest{
				GrantTypes: []string{"refresh_token"},
				Request: goauth2.Request{
					GrantedScope: []string{"something"},
				},
			},
			expectedErr: goauth2.ErrUnknownRequest,
		},
		{
			description: "should not pass because client may not execute this grant type",
			areq: &goauth2.AccessRequest{
				GrantTypes: []string{"refresh_token"},
				Request: goauth2.Request{
					GrantedScope: []string{"openid"},
					Client:       &goauth2.DefaultClient{},
				},
			},
			expectedErr: goauth2.ErrUnauthorizedClient,
		},
		{
			description: "should pass",
			areq: &goauth2.AccessRequest{
				GrantTypes: []string{"refresh_token"},
				Request: goauth2.Request{
					GrantedScope: []string{"openid"},
					Client: &goauth2.DefaultClient{
						GrantTypes: []string{"refresh_token"},
						//ResponseTypes: []string{"id_token"},
					},
					Session: &DefaultSession{},
				},
			},
		},
	} {
		t.Run("case="+c.description, func(t *testing.T) {
			err := h.HandleTokenEndpointRequest(nil, c.areq)
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
			GetPrivateKey: func(ctx context.Context) (interface{}, error) {
				return key, nil
			},
		},
		Config: &goauth2.Config{
			MinParameterEntropy: goauth2.MinParameterEntropy,
		},
	}

	h := &OpenIDConnectRefreshHandler{
		IDTokenHandleHelper: &IDTokenHandleHelper{
			IDTokenStrategy: j,
		},
		Config: &goauth2.Config{},
	}
	for _, c := range []struct {
		areq        *goauth2.AccessRequest
		expectedErr error
		check       func(t *testing.T, aresp *goauth2.AccessResponse)
		description string
	}{
		{
			description: "should not pass because grant_type is wrong",
			areq: &goauth2.AccessRequest{
				GrantTypes: []string{"foo"},
			},
			expectedErr: goauth2.ErrUnknownRequest,
		},
		{
			description: "should not pass because grant_type is right but scope is missing",
			areq: &goauth2.AccessRequest{
				GrantTypes: []string{"refresh_token"},
				Request: goauth2.Request{
					GrantedScope: []string{"something"},
				},
			},
			expectedErr: goauth2.ErrUnknownRequest,
		},
		// Disabled because this is already handled at the authorize_request_handler
		//{
		//	description: "should not pass because client may not ask for id_token",
		//	areq: &goauth2.AccessRequest{
		//		GrantTypes: []string{"refresh_token"},
		//		Request: goauth2.Request{
		//			GrantedScope: []string{"openid"},
		//			Client: &goauth2.DefaultClient{
		//				GrantTypes: []string{"refresh_token"},
		//			},
		//		},
		//	},
		//	expectedErr: goauth2.ErrUnknownRequest,
		//},
		{
			description: "should pass",
			areq: &goauth2.AccessRequest{
				GrantTypes: []string{"refresh_token"},
				Request: goauth2.Request{
					GrantedScope: []string{"openid"},
					Client: &goauth2.DefaultClient{
						GrantTypes: []string{"refresh_token"},
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
			check: func(t *testing.T, aresp *goauth2.AccessResponse) {
				assert.NotEmpty(t, aresp.GetExtra("id_token"))
				idToken, _ := aresp.GetExtra("id_token").(string)
				decodedIdToken, err := jwt.Parse(idToken, func(token *jwt.Token) (interface{}, error) {
					return key.PublicKey, nil
				})
				require.NoError(t, err)
				claims := decodedIdToken.Claims
				assert.NotEmpty(t, claims["at_hash"])
				idTokenExp := internal.ExtractJwtExpClaim(t, idToken)
				require.NotEmpty(t, idTokenExp)
				internal.RequireEqualTime(t, time.Now().Add(time.Hour).UTC(), *idTokenExp, time.Minute)
			},
		},
		{
			description: "should pass",
			areq: &goauth2.AccessRequest{
				GrantTypes: []string{"refresh_token"},
				Request: goauth2.Request{
					GrantedScope: []string{"openid"},
					Client: &goauth2.DefaultClientWithCustomTokenLifespans{
						DefaultClient: &goauth2.DefaultClient{
							GrantTypes: []string{"refresh_token"},
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
			check: func(t *testing.T, aresp *goauth2.AccessResponse) {
				assert.NotEmpty(t, aresp.GetExtra("id_token"))
				idToken, _ := aresp.GetExtra("id_token").(string)
				decodedIdToken, err := jwt.Parse(idToken, func(token *jwt.Token) (interface{}, error) {
					return key.PublicKey, nil
				})
				require.NoError(t, err)
				claims := decodedIdToken.Claims
				assert.NotEmpty(t, claims["at_hash"])
				idTokenExp := internal.ExtractJwtExpClaim(t, idToken)
				require.NotEmpty(t, idTokenExp)
				internal.RequireEqualTime(t, time.Now().Add(*internal.TestLifespans.RefreshTokenGrantIDTokenLifespan).UTC(), *idTokenExp, time.Minute)
			},
		},
		{
			description: "should fail because missing subject claim",
			areq: &goauth2.AccessRequest{
				GrantTypes: []string{"refresh_token"},
				Request: goauth2.Request{
					GrantedScope: []string{"openid"},
					Client: &goauth2.DefaultClient{
						GrantTypes: []string{"refresh_token"},
						//ResponseTypes: []string{"id_token"},
					},
					Session: &DefaultSession{
						Subject: "foo",
						Claims:  &jwt.IDTokenClaims{},
					},
				},
			},
			expectedErr: goauth2.ErrServerError,
		},
		{
			description: "should fail because missing session",
			areq: &goauth2.AccessRequest{
				GrantTypes: []string{"refresh_token"},
				Request: goauth2.Request{
					GrantedScope: []string{"openid"},
					Client: &goauth2.DefaultClient{
						GrantTypes: []string{"refresh_token"},
					},
				},
			},
			expectedErr: goauth2.ErrServerError,
		},
	} {
		t.Run("case="+c.description, func(t *testing.T) {
			aresp := goauth2.NewAccessResponse()
			err := h.PopulateTokenEndpointResponse(nil, c.areq, aresp)
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
