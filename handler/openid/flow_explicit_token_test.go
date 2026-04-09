// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
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
	testCases := []struct {
		name  string
		setup func(store *mock.MockOpenIDConnectRequestStorage, req *oauth2.AccessRequest)
		err   string
		check func(t *testing.T, aresp *oauth2.AccessResponse)
	}{
		{
			name: "ShouldFailCurrentRequestHasInvalidGrantType",
			setup: func(store *mock.MockOpenIDConnectRequestStorage, req *oauth2.AccessRequest) {
				req.GrantTypes = oauth2.Arguments{"some_other_grant_type"}
			},
			err: "The handler is not responsible for this request.",
		},
		{
			name: "ShouldFailStorageLookupReturnsNotFound",
			setup: func(store *mock.MockOpenIDConnectRequestStorage, req *oauth2.AccessRequest) {
				req.GrantTypes = oauth2.Arguments{consts.GrantTypeAuthorizationCode}
				req.Form.Set(consts.FormParameterAuthorizationCode, "foobar")
				store.EXPECT().GetOpenIDConnectSession(t.Context(), "foobar", req).Return(nil, ErrNoSessionFound)
			},
			err: "The handler is not responsible for this request. Could not find the requested resource(s).",
		},
		{
			name: "ShouldFailStorageLookupFails",
			setup: func(store *mock.MockOpenIDConnectRequestStorage, req *oauth2.AccessRequest) {
				req.GrantTypes = oauth2.Arguments{consts.GrantTypeAuthorizationCode}
				req.Form.Set(consts.FormParameterAuthorizationCode, "foobar")
				store.EXPECT().GetOpenIDConnectSession(t.Context(), "foobar", req).Return(nil, errors.New(""))
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
		},
		{
			name: "ShouldFailStoredRequestIsMissingOpenIDScope",
			setup: func(store *mock.MockOpenIDConnectRequestStorage, req *oauth2.AccessRequest) {
				req.GrantTypes = oauth2.Arguments{consts.GrantTypeAuthorizationCode}
				req.Form.Set(consts.FormParameterAuthorizationCode, "foobar")
				store.EXPECT().GetOpenIDConnectSession(t.Context(), "foobar", req).Return(oauth2.NewAuthorizeRequest(), nil)
			},
			err: "The request failed because of an internal error that is probably caused by misconfiguration. An OpenID Connect 1.0 session was found but the 'openid' scope is missing, probably due to a broken code configuration.",
		},
		{
			name: "ShouldFailCurrentRequestClientDoesNotHaveAuthorizationCodeGrantType",
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
			err: "The client is not authorized to request a token using this method. The OAuth 2.0 Client is not allowed to use the authorization grant 'authorization_code'.",
		},
		{
			name: "ShouldPassWithCustomClientLifespans",
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
			name: "ShouldPass",
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
			name: "ShouldFailStoredRequestSessionIsMissingSubjectClaim",
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
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Failed to generate ID Token because subject is an empty string.",
		},
		{
			name: "ShouldFailStoredRequestIsMissingSession",
			setup: func(store *mock.MockOpenIDConnectRequestStorage, req *oauth2.AccessRequest) {
				req.GrantTypes = oauth2.Arguments{consts.GrantTypeAuthorizationCode}
				req.Form.Set(consts.FormParameterAuthorizationCode, "foobar")
				storedReq := oauth2.NewAuthorizeRequest()
				storedReq.Session = nil
				storedReq.GrantScope(consts.ScopeOpenID)
				store.EXPECT().GetOpenIDConnectSession(t.Context(), "foobar", req).Return(storedReq, nil)
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Failed to generate ID Token because the session is not of type 'openid.Session' which is required.",
		},
		{
			name: "ShouldFailStorageReturnsErrorWhenDeletingOpenIDSession",
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
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. delete openid session err",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			store := mock.NewMockOpenIDConnectRequestStorage(ctrl)

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

			tc.setup(store, areq)
			err := h.PopulateTokenEndpointResponse(t.Context(), areq, aresp)

			if tc.err != "" {
				require.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)
			} else {
				require.NoError(t, err)
			}
			if tc.check != nil {
				tc.check(t, aresp)
			}
		})
	}
}
