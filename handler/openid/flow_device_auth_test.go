// Copyright © 2023 Ory Corp
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

func TestOpenIDConnectDeviceAuthorizeHandler_PopulateRFC8628UserAuthorizeEndpointResponse(t *testing.T) {
	testCases := []struct {
		name  string
		setup func(req *oauth2.DeviceAuthorizeRequest, oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler)
		err   string
	}{
		{
			name: "ShouldPass",
			setup: func(req *oauth2.DeviceAuthorizeRequest, oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) {
				req.GrantedScope = []string{consts.ScopeOpenID}
				req.Client = &oauth2.DefaultClient{
					GrantTypes: []string{string(oauth2.GrantTypeDeviceCode), string(oauth2.GrantTypeAuthorizationCode)},
				}
				req.SetDeviceCodeSignature("foobar")
				oidcStore.EXPECT().CreateOpenIDConnectSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			},
		},
		{
			name: "ShouldPassNoOpenIDScope",
			setup: func(req *oauth2.DeviceAuthorizeRequest, oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) {
				req.GrantedScope = []string{"foobar"}
			},
		},
		{
			name: "ShouldPassClientDoesNotSupportDeviceCodeGrantType",
			setup: func(req *oauth2.DeviceAuthorizeRequest, oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) {
				req.GrantedScope = []string{consts.ScopeOpenID, "foobar"}
				req.Client = &oauth2.DefaultClient{
					GrantTypes: []string{string(oauth2.GrantTypeImplicit)},
				}
			},
		},
		{
			name: "ShouldFailRequestDoesNotHaveDeviceSignature",
			setup: func(req *oauth2.DeviceAuthorizeRequest, oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) {
				req.GrantedScope = []string{consts.ScopeOpenID, "foobar"}
				req.Client = &oauth2.DefaultClient{
					GrantTypes: []string{string(oauth2.GrantTypeDeviceCode)},
				}
				req.SetDeviceCodeSignature("")
			},
			err: "The request failed because of an internal error that is probably caused by misconfiguration. The device code has not been issued yet, indicating a broken code configuration.",
		},
		{
			name: "ShouldFailFailedToCreateOIDCSession",
			setup: func(req *oauth2.DeviceAuthorizeRequest, oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) {
				req.GrantedScope = []string{consts.ScopeOpenID}
				req.Client = &oauth2.DefaultClient{
					GrantTypes: []string{string(oauth2.GrantTypeDeviceCode), string(oauth2.GrantTypeAuthorizationCode)},
				}
				req.SetDeviceCodeSignature("foobar")
				oidcStore.EXPECT().CreateOpenIDConnectSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("foobar"))
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. foobar",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			config := &oauth2.Config{
				AccessTokenLifespan:   time.Minute * 24,
				AuthorizeCodeLifespan: time.Minute * 24,
				RFC8628CodeLifespan:   time.Minute * 24,
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

			handler := &OpenIDConnectDeviceAuthorizeHandler{
				OpenIDConnectRequestStorage:   oidcStore,
				OpenIDConnectRequestValidator: NewOpenIDConnectRequestValidator(j.Strategy, config),
				CodeTokenEndpointHandler:      tokenHandler,
				Config:                        config,
				IDTokenHandleHelper: &IDTokenHandleHelper{
					IDTokenStrategy: j,
				},
			}
			req := oauth2.NewDeviceAuthorizeRequest()
			resp := oauth2.NewRFC8628UserAuthorizeResponse()

			tc.setup(req, oidcStore, tokenHandler)
			err := handler.PopulateRFC8628UserAuthorizeEndpointResponse(t.Context(), req, resp)

			if tc.err != "" {
				require.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestOpenIDConnectDeviceAuthorizeHandler_PopulateTokenEndpointResponse(t *testing.T) {
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
						Subject: "foobar",
					},
					Headers:     &jwt.Headers{},
					RequestedAt: time.Now(),
				}

				req := oauth2.NewAccessRequest(nil)
				req.GrantedScope = []string{consts.ScopeOpenID}
				req.GrantTypes = []string{string(oauth2.GrantTypeDeviceCode)}
				req.Session = session
				req.Client = &oauth2.DefaultClient{
					GrantTypes: []string{string(oauth2.GrantTypeDeviceCode), string(oauth2.GrantTypeAuthorizationCode)},
				}

				resp := oauth2.NewAccessResponse()

				authReq := oauth2.NewAuthorizeRequest()
				authReq.GrantedScope = []string{consts.ScopeOpenID}
				authReq.Session = session

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("foobar", nil)
				oidcStore.EXPECT().GetOpenIDConnectSession(gomock.Any(), "foobar", req).Return(authReq, nil)
				oidcStore.EXPECT().DeleteOpenIDConnectSession(gomock.Any(), "foobar").Return(nil)

				return req, resp
			},
		},
		{
			name: "ShouldFailRequestHasNoDeviceCodeGrantType",
			setup: func(oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) (*oauth2.AccessRequest, *oauth2.AccessResponse) {
				req := oauth2.NewAccessRequest(nil)
				req.GrantedScope = []string{consts.ScopeOpenID}
				req.GrantTypes = []string{string(oauth2.GrantTypeAuthorizationCode)}
				return req, oauth2.NewAccessResponse()
			},
			err: "The handler is not responsible for this request.",
		},
		{
			name: "ShouldFailNoDeviceCode",
			setup: func(oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) (*oauth2.AccessRequest, *oauth2.AccessResponse) {
				req := oauth2.NewAccessRequest(nil)
				req.GrantTypes = []string{string(oauth2.GrantTypeDeviceCode)}

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("", errors.New(""))
				return req, oauth2.NewAccessResponse()
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
		},
		{
			name: "ShouldFailGetOIDCSessionErrNoSessionFound",
			setup: func(oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) (*oauth2.AccessRequest, *oauth2.AccessResponse) {
				req := oauth2.NewAccessRequest(nil)
				req.GrantTypes = []string{string(oauth2.GrantTypeDeviceCode)}

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("foobar", nil)
				oidcStore.EXPECT().GetOpenIDConnectSession(gomock.Any(), "foobar", req).Return(nil, ErrNoSessionFound)
				return req, oauth2.NewAccessResponse()
			},
			err: "The handler is not responsible for this request. Could not find the requested resource(s).",
		},
		{
			name: "ShouldFailGetOIDCSessionOtherError",
			setup: func(oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) (*oauth2.AccessRequest, *oauth2.AccessResponse) {
				req := oauth2.NewAccessRequest(nil)
				req.GrantTypes = []string{string(oauth2.GrantTypeDeviceCode)}

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("foobar", nil)
				oidcStore.EXPECT().GetOpenIDConnectSession(gomock.Any(), "foobar", req).Return(nil, errors.New(""))
				return req, oauth2.NewAccessResponse()
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
		},
		{
			name: "ShouldFailAuthRequestHasNoOpenIDScopeGranted",
			setup: func(oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) (*oauth2.AccessRequest, *oauth2.AccessResponse) {
				req := oauth2.NewAccessRequest(nil)
				req.GrantTypes = []string{string(oauth2.GrantTypeDeviceCode)}

				resp := oauth2.NewAccessResponse()

				authReq := oauth2.NewAuthorizeRequest()
				authReq.GrantedScope = []string{"foobar"}

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("foobar", nil)
				oidcStore.EXPECT().GetOpenIDConnectSession(gomock.Any(), "foobar", req).Return(authReq, nil)
				return req, resp
			},
			err: "The request failed because of an internal error that is probably caused by misconfiguration. An OpenID Connect session was found but the openid scope is missing, probably due to a broken code configuration.",
		},
		{
			name: "ShouldFailClientHasNoDeviceCodeGrantType",
			setup: func(oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) (*oauth2.AccessRequest, *oauth2.AccessResponse) {
				req := oauth2.NewAccessRequest(nil)
				req.GrantedScope = []string{consts.ScopeOpenID}
				req.GrantTypes = []string{string(oauth2.GrantTypeDeviceCode)}
				req.Client = &oauth2.DefaultClient{
					GrantTypes: []string{string(oauth2.GrantTypeAuthorizationCode)},
				}

				resp := oauth2.NewAccessResponse()

				authReq := oauth2.NewAuthorizeRequest()
				authReq.GrantedScope = []string{consts.ScopeOpenID}

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("foobar", nil)
				oidcStore.EXPECT().GetOpenIDConnectSession(gomock.Any(), "foobar", req).Return(authReq, nil)
				return req, resp
			},
			err: "The client is not authorized to request a token using this method. The OAuth 2.0 Client is not allowed to use the authorization grant 'urn:ietf:params:oauth:grant-type:device_code'.",
		},
		{
			name: "ShouldFailNoSession",
			setup: func(oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) (*oauth2.AccessRequest, *oauth2.AccessResponse) {
				req := oauth2.NewAccessRequest(nil)
				req.GrantedScope = []string{consts.ScopeOpenID}
				req.GrantTypes = []string{string(oauth2.GrantTypeDeviceCode)}
				req.Session = nil
				req.Client = &oauth2.DefaultClient{
					GrantTypes: []string{string(oauth2.GrantTypeDeviceCode), string(oauth2.GrantTypeAuthorizationCode)},
				}

				resp := oauth2.NewAccessResponse()

				authReq := oauth2.NewAuthorizeRequest()
				authReq.GrantedScope = []string{consts.ScopeOpenID}
				authReq.Session = nil

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("foobar", nil)
				oidcStore.EXPECT().GetOpenIDConnectSession(gomock.Any(), "foobar", req).Return(authReq, nil)
				return req, resp
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Failed to generate ID Token because the session must be of type 'openid.Session'.",
		},
		{
			name: "ShouldFailIDTokenClaimHasNoSubject",
			setup: func(oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) (*oauth2.AccessRequest, *oauth2.AccessResponse) {
				session := &DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "",
					},
					Headers:     &jwt.Headers{},
					RequestedAt: time.Now(),
				}

				req := oauth2.NewAccessRequest(nil)
				req.GrantedScope = []string{consts.ScopeOpenID}
				req.GrantTypes = []string{string(oauth2.GrantTypeDeviceCode)}
				req.Session = session
				req.Client = &oauth2.DefaultClient{
					GrantTypes: []string{string(oauth2.GrantTypeDeviceCode), string(oauth2.GrantTypeAuthorizationCode)},
				}

				resp := oauth2.NewAccessResponse()

				authReq := oauth2.NewAuthorizeRequest()
				authReq.GrantedScope = []string{consts.ScopeOpenID}
				authReq.Session = session

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("foobar", nil)
				oidcStore.EXPECT().GetOpenIDConnectSession(gomock.Any(), "foobar", req).Return(authReq, nil)
				return req, resp
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
				RFC8628CodeLifespan:   time.Minute * 24,
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

			handler := &OpenIDConnectDeviceAuthorizeHandler{
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
