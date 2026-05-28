// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/testing/mock"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestOpenIDConnectCIBAHandler_HandleOpenIDCIBAEndpointRequest(t *testing.T) {
	testCases := []struct {
		name  string
		setup func(req *oauth2.CIBARequest, oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler)
		err   string
	}{
		{
			name: "ShouldPass",
			setup: func(req *oauth2.CIBARequest, oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) {
				req.GrantedScope = []string{consts.ScopeOpenID}
				req.Client = &oauth2.DefaultClient{
					GrantTypes: []string{string(oauth2.GrantTypeOpenIDCIBA)},
				}
				req.SetAuthRequestIDSignature("sig-1")
				oidcStore.EXPECT().CreateOpenIDConnectSession(gomock.Any(), "sig-1", gomock.Any()).Return(nil)
			},
		},
		{
			name: "ShouldPassNoOpenIDScope",
			setup: func(req *oauth2.CIBARequest, oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) {
				req.GrantedScope = []string{"profile"}
			},
		},
		{
			name: "ShouldPassClientDoesNotSupportCIBAGrant",
			setup: func(req *oauth2.CIBARequest, oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) {
				req.GrantedScope = []string{consts.ScopeOpenID}
				req.Client = &oauth2.DefaultClient{
					GrantTypes: []string{string(oauth2.GrantTypeAuthorizationCode)},
				}
			},
		},
		{
			name: "ShouldFailMissingAuthRequestIDSignature",
			setup: func(req *oauth2.CIBARequest, oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) {
				req.GrantedScope = []string{consts.ScopeOpenID}
				req.Client = &oauth2.DefaultClient{
					GrantTypes: []string{string(oauth2.GrantTypeOpenIDCIBA)},
				}
				req.SetAuthRequestIDSignature("")
			},
			err: "The request failed because of an internal error that is probably caused by misconfiguration. The auth_req_id has not been issued yet, indicating a broken handler ordering.",
		},
		{
			name: "ShouldFailFailedToCreateOIDCSession",
			setup: func(req *oauth2.CIBARequest, oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) {
				req.GrantedScope = []string{consts.ScopeOpenID}
				req.Client = &oauth2.DefaultClient{
					GrantTypes: []string{string(oauth2.GrantTypeOpenIDCIBA)},
				}
				req.SetAuthRequestIDSignature("sig-1")
				oidcStore.EXPECT().CreateOpenIDConnectSession(gomock.Any(), "sig-1", gomock.Any()).Return(errors.New("foobar"))
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. foobar",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			config := &oauth2.Config{}
			jwtStrategy := &jwt.DefaultStrategy{
				Config: config,
				Issuer: jwt.NewDefaultIssuerRS256Unverified(key),
			}
			j := &DefaultStrategy{
				Strategy: jwtStrategy,
				Config:   config,
			}

			oidcStore := mock.NewMockOpenIDConnectRequestStorage(ctrl)
			tokenHandler := mock.NewMockCodeTokenEndpointHandler(ctrl)

			handler := &OpenIDConnectCIBAHandler{
				OpenIDConnectRequestStorage:   oidcStore,
				OpenIDConnectRequestValidator: NewOpenIDConnectRequestValidator(j.Strategy, config),
				CodeTokenEndpointHandler:      tokenHandler,
				Config:                        config,
				IDTokenHandleHelper: &IDTokenHandleHelper{
					IDTokenStrategy: j,
				},
			}

			req := oauth2.NewCIBARequest()
			resp := oauth2.NewCIBAResponse()

			tc.setup(req, oidcStore, tokenHandler)
			err := handler.HandleOpenIDCIBAEndpointRequest(t.Context(), req, resp)

			if tc.err != "" {
				require.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestOpenIDConnectCIBAHandler_HandleTokenEndpointRequest(t *testing.T) {
	handler := &OpenIDConnectCIBAHandler{}

	err := handler.HandleTokenEndpointRequest(t.Context(), oauth2.NewAccessRequest(nil))
	require.ErrorIs(t, err, oauth2.ErrUnknownRequest)
}

func TestOpenIDConnectCIBAHandler_CanSkipClientAuth(t *testing.T) {
	handler := &OpenIDConnectCIBAHandler{}

	require.False(t, handler.CanSkipClientAuth(t.Context(), oauth2.NewAccessRequest(nil)))
}

func TestOpenIDConnectCIBAHandler_CanHandleTokenEndpointRequest(t *testing.T) {
	handler := &OpenIDConnectCIBAHandler{}

	wrong := oauth2.NewAccessRequest(nil)
	wrong.GrantTypes = oauth2.Arguments{string(oauth2.GrantTypeAuthorizationCode)}
	require.False(t, handler.CanHandleTokenEndpointRequest(t.Context(), wrong))

	right := oauth2.NewAccessRequest(nil)
	right.GrantTypes = oauth2.Arguments{string(oauth2.GrantTypeOpenIDCIBA)}
	require.True(t, handler.CanHandleTokenEndpointRequest(t.Context(), right))
}

func TestOpenIDConnectCIBAHandler_PopulateTokenEndpointResponse(t *testing.T) {
	testCases := []struct {
		name  string
		setup func(oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) (req *oauth2.AccessRequest, resp *oauth2.AccessResponse)
		err   string
	}{
		{
			name: "ShouldPass",
			setup: func(oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) (*oauth2.AccessRequest, *oauth2.AccessResponse) {
				session := &DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "user-1",
					},
					Headers:     &jwt.Headers{},
					RequestedAt: time.Now(),
				}

				req := oauth2.NewAccessRequest(nil)
				req.GrantedScope = []string{consts.ScopeOpenID}
				req.GrantTypes = []string{string(oauth2.GrantTypeOpenIDCIBA)}
				req.Session = session
				req.Client = &oauth2.DefaultClient{
					GrantTypes: []string{string(oauth2.GrantTypeOpenIDCIBA)},
				}
				req.Form.Set(consts.FormParameterAuthReqID, "the-auth-req-id")

				resp := oauth2.NewAccessResponse()

				authReq := oauth2.NewAuthorizeRequest()
				authReq.GrantedScope = []string{consts.ScopeOpenID}
				authReq.Session = session

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), "the-auth-req-id").Return("sig-1", nil)
				oidcStore.EXPECT().GetOpenIDConnectSession(gomock.Any(), "sig-1", req).Return(authReq, nil)
				oidcStore.EXPECT().DeleteOpenIDConnectSession(gomock.Any(), "sig-1").Return(nil)

				return req, resp
			},
		},
		{
			name: "ShouldFailRequestHasNoCIBAGrantType",
			setup: func(oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) (*oauth2.AccessRequest, *oauth2.AccessResponse) {
				req := oauth2.NewAccessRequest(nil)
				req.GrantTypes = []string{string(oauth2.GrantTypeAuthorizationCode)}
				return req, oauth2.NewAccessResponse()
			},
			err: "The handler is not responsible for this request.",
		},
		{
			name: "ShouldFailSignatureError",
			setup: func(oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) (*oauth2.AccessRequest, *oauth2.AccessResponse) {
				req := oauth2.NewAccessRequest(nil)
				req.GrantTypes = []string{string(oauth2.GrantTypeOpenIDCIBA)}

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("", errors.New("boom"))

				return req, oauth2.NewAccessResponse()
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. boom",
		},
		{
			name: "ShouldFailGetOIDCSessionErrNoSessionFound",
			setup: func(oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) (*oauth2.AccessRequest, *oauth2.AccessResponse) {
				req := oauth2.NewAccessRequest(nil)
				req.GrantTypes = []string{string(oauth2.GrantTypeOpenIDCIBA)}

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("sig-1", nil)
				oidcStore.EXPECT().GetOpenIDConnectSession(gomock.Any(), "sig-1", req).Return(nil, ErrNoSessionFound)

				return req, oauth2.NewAccessResponse()
			},
			err: "The handler is not responsible for this request. Could not find the requested resource(s).",
		},
		{
			name: "ShouldFailGetOIDCSessionOtherError",
			setup: func(oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) (*oauth2.AccessRequest, *oauth2.AccessResponse) {
				req := oauth2.NewAccessRequest(nil)
				req.GrantTypes = []string{string(oauth2.GrantTypeOpenIDCIBA)}

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("sig-1", nil)
				oidcStore.EXPECT().GetOpenIDConnectSession(gomock.Any(), "sig-1", req).Return(nil, errors.New("kaboom"))

				return req, oauth2.NewAccessResponse()
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. kaboom",
		},
		{
			name: "ShouldFailAuthRequestHasNoOpenIDScopeGranted",
			setup: func(oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) (*oauth2.AccessRequest, *oauth2.AccessResponse) {
				req := oauth2.NewAccessRequest(nil)
				req.GrantTypes = []string{string(oauth2.GrantTypeOpenIDCIBA)}

				authReq := oauth2.NewAuthorizeRequest()
				authReq.GrantedScope = []string{"profile"}

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("sig-1", nil)
				oidcStore.EXPECT().GetOpenIDConnectSession(gomock.Any(), "sig-1", req).Return(authReq, nil)

				return req, oauth2.NewAccessResponse()
			},
			err: "The request failed because of an internal error that is probably caused by misconfiguration. An OpenID Connect session was found but the openid scope is missing, probably due to a broken handler configuration.",
		},
		{
			name: "ShouldFailClientHasNoCIBAGrantType",
			setup: func(oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) (*oauth2.AccessRequest, *oauth2.AccessResponse) {
				req := oauth2.NewAccessRequest(nil)
				req.GrantedScope = []string{consts.ScopeOpenID}
				req.GrantTypes = []string{string(oauth2.GrantTypeOpenIDCIBA)}
				req.Client = &oauth2.DefaultClient{
					GrantTypes: []string{string(oauth2.GrantTypeAuthorizationCode)},
				}

				authReq := oauth2.NewAuthorizeRequest()
				authReq.GrantedScope = []string{consts.ScopeOpenID}

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("sig-1", nil)
				oidcStore.EXPECT().GetOpenIDConnectSession(gomock.Any(), "sig-1", req).Return(authReq, nil)

				return req, oauth2.NewAccessResponse()
			},
			err: "The client is not authorized to request a token using this method. The OAuth 2.0 Client is not allowed to use the authorization grant 'urn:openid:params:grant-type:ciba'.",
		},
		{
			name: "ShouldFailNoOpenIDSession",
			setup: func(oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) (*oauth2.AccessRequest, *oauth2.AccessResponse) {
				req := oauth2.NewAccessRequest(nil)
				req.GrantedScope = []string{consts.ScopeOpenID}
				req.GrantTypes = []string{string(oauth2.GrantTypeOpenIDCIBA)}
				req.Session = nil
				req.Client = &oauth2.DefaultClient{
					GrantTypes: []string{string(oauth2.GrantTypeOpenIDCIBA)},
				}

				authReq := oauth2.NewAuthorizeRequest()
				authReq.GrantedScope = []string{consts.ScopeOpenID}
				authReq.Session = nil

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("sig-1", nil)
				oidcStore.EXPECT().GetOpenIDConnectSession(gomock.Any(), "sig-1", req).Return(authReq, nil)

				return req, oauth2.NewAccessResponse()
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Failed to generate ID Token because the session must be of type 'openid.Session'.",
		},
		{
			name: "ShouldFailIDTokenClaimHasNoSubject",
			setup: func(oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) (*oauth2.AccessRequest, *oauth2.AccessResponse) {
				session := &DefaultSession{
					Claims:      &jwt.IDTokenClaims{Subject: ""},
					Headers:     &jwt.Headers{},
					RequestedAt: time.Now(),
				}

				req := oauth2.NewAccessRequest(nil)
				req.GrantedScope = []string{consts.ScopeOpenID}
				req.GrantTypes = []string{string(oauth2.GrantTypeOpenIDCIBA)}
				req.Session = session
				req.Client = &oauth2.DefaultClient{
					GrantTypes: []string{string(oauth2.GrantTypeOpenIDCIBA)},
				}

				authReq := oauth2.NewAuthorizeRequest()
				authReq.GrantedScope = []string{consts.ScopeOpenID}
				authReq.Session = session

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("sig-1", nil)
				oidcStore.EXPECT().GetOpenIDConnectSession(gomock.Any(), "sig-1", req).Return(authReq, nil)

				return req, oauth2.NewAccessResponse()
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Failed to generate ID Token because subject is an empty string.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			config := &oauth2.Config{
				AccessTokenLifespan:   time.Minute * 24,
				AuthorizeCodeLifespan: time.Minute * 24,
			}

			jwtStrategy := &jwt.DefaultStrategy{
				Config: config,
				Issuer: jwt.NewDefaultIssuerRS256Unverified(key),
			}

			j := &DefaultStrategy{
				Strategy: jwtStrategy,
				Config:   config,
			}

			oidcStore := mock.NewMockOpenIDConnectRequestStorage(ctrl)
			tokenHandler := mock.NewMockCodeTokenEndpointHandler(ctrl)

			handler := &OpenIDConnectCIBAHandler{
				OpenIDConnectRequestStorage:   oidcStore,
				OpenIDConnectRequestValidator: NewOpenIDConnectRequestValidator(j.Strategy, config),
				CodeTokenEndpointHandler:      tokenHandler,
				Config:                        config,
				IDTokenHandleHelper: &IDTokenHandleHelper{
					IDTokenStrategy: j,
				},
			}

			req, resp := tc.setup(oidcStore, tokenHandler)
			err := handler.PopulateTokenEndpointResponse(t.Context(), req, resp)

			if tc.err != "" {
				require.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
