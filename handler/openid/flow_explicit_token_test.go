// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"fmt"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/testing/mock"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestHandleTokenEndpointRequest(t *testing.T) {
	h := &OpenIDConnectExplicitHandler{Config: &oauth2.Config{}}
	areq := oauth2.NewAccessRequest(nil)
	areq.Client = &oauth2.DefaultClient{
		//ResponseTypes: oauth2.Arguments{"id_token"},
	}
	assert.EqualError(t, h.HandleTokenEndpointRequest(t.Context(), areq), oauth2.ErrUnknownRequest.Error())
}

func TestExplicit_PopulateTokenEndpointResponse(t *testing.T) {
	for k, c := range []struct {
		description string
		setup       func(store *mock.MockOpenIDConnectRequestStorage, req *oauth2.AccessRequest)
		expectErr   error
		check       func(t *testing.T, aresp *oauth2.AccessResponse)
	}{
		{
			description: "should fail because current request has invalid grant type",
			setup: func(store *mock.MockOpenIDConnectRequestStorage, req *oauth2.AccessRequest) {
				req.GrantTypes = oauth2.Arguments{"some_other_grant_type"}
			},
			expectErr: oauth2.ErrUnknownRequest,
		},
		{
			description: "should fail because storage lookup returns not found",
			setup: func(store *mock.MockOpenIDConnectRequestStorage, req *oauth2.AccessRequest) {
				req.GrantTypes = oauth2.Arguments{consts.GrantTypeAuthorizationCode}
				req.Form.Set(consts.FormParameterAuthorizationCode, "foobar")
				store.EXPECT().GetOpenIDConnectSession(t.Context(), "foobar", req).Return(nil, ErrNoSessionFound)
			},
			expectErr: oauth2.ErrUnknownRequest,
		},
		{
			description: "should fail because storage lookup fails",
			setup: func(store *mock.MockOpenIDConnectRequestStorage, req *oauth2.AccessRequest) {
				req.GrantTypes = oauth2.Arguments{consts.GrantTypeAuthorizationCode}
				req.Form.Set(consts.FormParameterAuthorizationCode, "foobar")
				store.EXPECT().GetOpenIDConnectSession(t.Context(), "foobar", req).Return(nil, errors.New(""))
			},
			expectErr: oauth2.ErrServerError,
		},
		{
			description: "should fail because stored request is missing openid scope",
			setup: func(store *mock.MockOpenIDConnectRequestStorage, req *oauth2.AccessRequest) {
				req.GrantTypes = oauth2.Arguments{consts.GrantTypeAuthorizationCode}
				req.Form.Set(consts.FormParameterAuthorizationCode, "foobar")
				store.EXPECT().GetOpenIDConnectSession(t.Context(), "foobar", req).Return(oauth2.NewAuthorizeRequest(), nil)
			},
			expectErr: oauth2.ErrMisconfiguration,
		},
		{
			description: "should fail because current request's client does not have authorization_code grant type",
			setup: func(store *mock.MockOpenIDConnectRequestStorage, req *oauth2.AccessRequest) {
				req.Client = &oauth2.DefaultClient{
					GrantTypes: oauth2.Arguments{"some_other_grant_type"},
				}
				req.GrantTypes = oauth2.Arguments{consts.GrantTypeAuthorizationCode}
				req.Form.Set(consts.FormParameterAuthorizationCode, "foobar")
				storedReq := oauth2.NewAuthorizeRequest()
				storedReq.GrantedScope = oauth2.Arguments{consts.ScopeOpenID}
				store.EXPECT().GetOpenIDConnectSession(t.Context(), "foobar", req).Return(storedReq, nil)
			},
			expectErr: oauth2.ErrUnauthorizedClient,
		},
		{
			description: "should pass with custom client lifespans",
			setup: func(store *mock.MockOpenIDConnectRequestStorage, req *oauth2.AccessRequest) {
				req.Client = &oauth2.DefaultClientWithCustomTokenLifespans{
					DefaultClient: &oauth2.DefaultClient{
						GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
					},
					TokenLifespans: &internal.TestLifespans,
				}
				req.GrantTypes = oauth2.Arguments{consts.GrantTypeAuthorizationCode}
				req.Form.Set(consts.FormParameterAuthorizationCode, "foobar")
				storedSession := &DefaultSession{
					Claims: &jwt.IDTokenClaims{Subject: testSubjectPeter},
				}
				storedReq := oauth2.NewAuthorizeRequest()
				storedReq.Session = storedSession
				storedReq.GrantedScope = oauth2.Arguments{consts.ScopeOpenID}
				storedReq.Form.Set(consts.FormParameterNonce, "1111111111111111")
				store.EXPECT().GetOpenIDConnectSession(t.Context(), "foobar", req).Return(storedReq, nil)
				store.EXPECT().DeleteOpenIDConnectSession(gomock.Any(), "foobar").Return(nil)
			},
			check: func(t *testing.T, aresp *oauth2.AccessResponse) {
				assert.NotEmpty(t, aresp.GetExtra(consts.AccessResponseIDToken))
				idToken, _ := aresp.GetExtra(consts.AccessResponseIDToken).(string)
				decodedIdToken, err := jwt.Parse(idToken, func(token *jwt.Token) (any, error) {
					return key.PublicKey, nil
				})
				require.NoError(t, err)
				claims := decodedIdToken.Claims.ToMapClaims()
				assert.NotEmpty(t, claims["at_hash"])
				idTokenExp := internal.ExtractJwtExpClaim(t, idToken)
				internal.RequireEqualTime(t, time.Now().Add(*internal.TestLifespans.AuthorizationCodeGrantIDTokenLifespan).UTC(), *idTokenExp, time.Minute)
			},
		},
		{
			description: "should pass",
			setup: func(store *mock.MockOpenIDConnectRequestStorage, req *oauth2.AccessRequest) {
				req.Client = &oauth2.DefaultClient{
					GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				}
				req.GrantTypes = oauth2.Arguments{consts.GrantTypeAuthorizationCode}
				req.Form.Set(consts.FormParameterAuthorizationCode, "foobar")
				storedSession := &DefaultSession{
					Claims: &jwt.IDTokenClaims{Subject: testSubjectPeter},
				}
				storedReq := oauth2.NewAuthorizeRequest()
				storedReq.Session = storedSession
				storedReq.GrantedScope = oauth2.Arguments{consts.ScopeOpenID}
				storedReq.Form.Set("nonce", "1111111111111111")
				store.EXPECT().GetOpenIDConnectSession(t.Context(), "foobar", req).Return(storedReq, nil)
				store.EXPECT().DeleteOpenIDConnectSession(gomock.Any(), "foobar").Return(nil)
			},
			check: func(t *testing.T, aresp *oauth2.AccessResponse) {
				assert.NotEmpty(t, aresp.GetExtra("id_token"))
				idToken, _ := aresp.GetExtra("id_token").(string)
				decodedIdToken, err := jwt.Parse(idToken, func(token *jwt.Token) (any, error) {
					return key.PublicKey, nil
				})
				require.NoError(t, err)
				claims := decodedIdToken.Claims.ToMapClaims()
				assert.NotEmpty(t, claims["at_hash"])
				idTokenExp := internal.ExtractJwtExpClaim(t, idToken)
				internal.RequireEqualTime(t, time.Now().Add(time.Hour), *idTokenExp, time.Minute)
			},
		},
		{
			description: "should fail because stored request's session is missing subject claim",
			setup: func(store *mock.MockOpenIDConnectRequestStorage, req *oauth2.AccessRequest) {
				req.GrantTypes = oauth2.Arguments{consts.GrantTypeAuthorizationCode}
				req.Form.Set(consts.FormParameterAuthorizationCode, "foobar")
				storedSession := &DefaultSession{
					Claims: &jwt.IDTokenClaims{Subject: ""},
				}
				storedReq := oauth2.NewAuthorizeRequest()
				storedReq.Session = storedSession
				storedReq.GrantedScope = oauth2.Arguments{consts.ScopeOpenID}
				store.EXPECT().GetOpenIDConnectSession(t.Context(), "foobar", req).Return(storedReq, nil)
			},
			expectErr: oauth2.ErrServerError,
		},
		{
			description: "should fail because stored request is missing session",
			setup: func(store *mock.MockOpenIDConnectRequestStorage, req *oauth2.AccessRequest) {
				req.GrantTypes = oauth2.Arguments{consts.GrantTypeAuthorizationCode}
				req.Form.Set(consts.FormParameterAuthorizationCode, "foobar")
				storedReq := oauth2.NewAuthorizeRequest()
				storedReq.Session = nil
				storedReq.GrantScope(consts.ScopeOpenID)
				store.EXPECT().GetOpenIDConnectSession(t.Context(), "foobar", req).Return(storedReq, nil)
			},
			expectErr: oauth2.ErrServerError,
		},
		{
			description: "should fail because storage returns error when deleting openid session",
			setup: func(store *mock.MockOpenIDConnectRequestStorage, req *oauth2.AccessRequest) {
				req.Client = &oauth2.DefaultClient{
					GrantTypes: oauth2.Arguments{"authorization_code"},
				}
				req.GrantTypes = oauth2.Arguments{"authorization_code"}
				req.Form.Set("code", "foobar")
				storedSession := &DefaultSession{
					Claims: &jwt.IDTokenClaims{Subject: testSubjectPeter},
				}
				storedReq := oauth2.NewAuthorizeRequest()
				storedReq.Session = storedSession
				storedReq.GrantedScope = oauth2.Arguments{"openid"}
				store.EXPECT().GetOpenIDConnectSession(gomock.Any(), "foobar", req).Return(storedReq, nil)
				store.EXPECT().DeleteOpenIDConnectSession(gomock.Any(), "foobar").Return(errors.New("delete openid session err"))
			},
			expectErr: oauth2.ErrServerError,
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, c.description), func(t *testing.T) {
			ctrl := gomock.NewController(t)
			store := mock.NewMockOpenIDConnectRequestStorage(ctrl)
			defer ctrl.Finish()

			session := &DefaultSession{
				Claims: &jwt.IDTokenClaims{
					Subject: testSubjectPeter,
				},
				Headers: &jwt.Headers{},
			}
			aresp := oauth2.NewAccessResponse()
			areq := oauth2.NewAccessRequest(session)

			config := &oauth2.Config{
				MinParameterEntropy: oauth2.MinParameterEntropy,
			}

			jwtStrategy := &jwt.DefaultStrategy{
				Config: config,
				Issuer: jwt.NewDefaultIssuerRS256Unverified(key),
			}

			var j = &DefaultStrategy{
				Strategy: jwtStrategy,
				Config:   config,
			}

			h := &OpenIDConnectExplicitHandler{
				OpenIDConnectRequestStorage: store,
				IDTokenHandleHelper: &IDTokenHandleHelper{
					IDTokenStrategy: j,
				},
				Config: &oauth2.Config{},
			}

			c.setup(store, areq)
			err := h.PopulateTokenEndpointResponse(t.Context(), areq, aresp)

			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
			}
			if c.check != nil {
				c.check(t, aresp)
			}
		})
	}
}
