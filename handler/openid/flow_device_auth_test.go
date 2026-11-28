// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
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
			name: "ShouldPassNotApproved",
			setup: func(req *oauth2.DeviceAuthorizeRequest, oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) {
				req.GrantedScope = []string{consts.ScopeOpenID}
				req.Client = &oauth2.DefaultClient{
					GrantTypes: []string{string(oauth2.GrantTypeDeviceCode)},
				}
				req.SetDeviceCodeSignature("foobar")
				req.SetStatus(oauth2.DeviceAuthorizeStatusDenied)
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
		{
			name: "ShouldFailSessionIsNotAnOpenIDConnectSession",
			setup: func(req *oauth2.DeviceAuthorizeRequest, oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) {
				req.GrantedScope = []string{consts.ScopeOpenID}
				req.Client = &oauth2.DefaultClient{
					GrantTypes: []string{string(oauth2.GrantTypeDeviceCode)},
				}
				req.SetDeviceCodeSignature("foobar")
				req.SetSession(&oauth2.DefaultSession{Subject: testSubjectPeter})
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Failed to validate OpenID Connect 1.0 request because the session is not of type 'openid.Session' which is required.",
		},
		{
			name: "ShouldFailSessionHasNoSubject",
			setup: func(req *oauth2.DeviceAuthorizeRequest, oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) {
				req.GrantedScope = []string{consts.ScopeOpenID}
				req.Client = &oauth2.DefaultClient{
					GrantTypes: []string{string(oauth2.GrantTypeDeviceCode)},
				}
				req.SetDeviceCodeSignature("foobar")
				req.SetSession(NewDefaultSession())
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Failed to validate OpenID Connect 1.0 request because the session subject is empty.",
		},
		{
			name: "ShouldFailAuthenticationOlderThanMaxAge",
			setup: func(req *oauth2.DeviceAuthorizeRequest, oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) {
				req.GrantedScope = []string{consts.ScopeOpenID}
				req.Client = &oauth2.DefaultClient{
					GrantTypes: []string{string(oauth2.GrantTypeDeviceCode)},
				}
				req.Form = url.Values{consts.FormParameterMaximumAge: {"60"}}
				req.SetDeviceCodeSignature("foobar")
				req.GetSession().(*DefaultSession).Claims.AuthTime = jwt.NewNumericDate(time.Now().Add(-time.Hour))
			},
			err: "The Authorization Server requires End-User authentication. Failed to validate OpenID Connect request because authentication time does not satisfy max_age time.",
		},
		{
			name: "ShouldFailAuthenticationAfterRequestWithPromptNone",
			setup: func(req *oauth2.DeviceAuthorizeRequest, oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) {
				req.GrantedScope = []string{consts.ScopeOpenID}
				req.Client = &oauth2.DefaultClient{
					GrantTypes: []string{string(oauth2.GrantTypeDeviceCode)},
				}
				req.Form = url.Values{consts.FormParameterPrompt: {consts.PromptTypeNone}}
				req.SetDeviceCodeSignature("foobar")

				session := req.GetSession().(*DefaultSession)
				session.RequestedAt = time.Unix(1000000000, 0).UTC()
				session.Claims.AuthTime = jwt.NewNumericDate(time.Unix(1000000060, 0).UTC())
			},
			err: "The Authorization Server requires End-User authentication. Failed to validate OpenID Connect request because prompt was set to 'none' but auth_time ('2001-09-09 01:47:40 +0000 UTC') happened after the authorization request ('2001-09-09 01:46:40 +0000 UTC') was registered, indicating that the user was logged in during this request which is not allowed.",
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
			session := NewDefaultSession()
			session.Subject, session.Claims.Subject = testSubjectPeter, testSubjectPeter

			req := oauth2.NewDeviceAuthorizeRequest()
			req.SetStatus(oauth2.DeviceAuthorizeStatusApproved)
			req.SetSession(session)

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
			name: "ShouldFailGetOIDCSessionErrNoSessionFoundOpenIDScopeGranted",
			setup: func(oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) (*oauth2.AccessRequest, *oauth2.AccessResponse) {
				req := oauth2.NewAccessRequest(nil)
				req.GrantedScope = []string{consts.ScopeOpenID}
				req.GrantTypes = []string{string(oauth2.GrantTypeDeviceCode)}

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("foobar", nil)
				oidcStore.EXPECT().GetOpenIDConnectSession(gomock.Any(), "foobar", req).Return(nil, ErrNoSessionFound)

				return req, oauth2.NewAccessResponse()
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. The 'openid' scope was granted but no OpenID Connect session exists for the device code, so no ID Token can be issued.",
		},
		{
			name: "ShouldFailSessionSubjectIsNotTheDecisionSubject",
			setup: func(oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) (*oauth2.AccessRequest, *oauth2.AccessResponse) {
				req := oauth2.NewAccessRequest(nil)
				req.GrantedScope = []string{consts.ScopeOpenID}
				req.GrantTypes = []string{string(oauth2.GrantTypeDeviceCode)}
				req.Session = &DefaultSession{Subject: "peter", Claims: &jwt.IDTokenClaims{Subject: "peter"}, Headers: &jwt.Headers{}}
				req.Client = &oauth2.DefaultClient{
					GrantTypes: []string{string(oauth2.GrantTypeDeviceCode)},
				}

				authReq := oauth2.NewAuthorizeRequest()
				authReq.GrantedScope = []string{consts.ScopeOpenID}
				authReq.Session = &DefaultSession{Subject: "mallory", Claims: &jwt.IDTokenClaims{Subject: "mallory"}, Headers: &jwt.Headers{}}

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("foobar", nil)
				oidcStore.EXPECT().GetOpenIDConnectSession(gomock.Any(), "foobar", req).DoAndReturn(func(_ context.Context, _ string, requester oauth2.Requester) (oauth2.Requester, error) {
					requester.SetSession(authReq.Session)

					return authReq, nil
				})

				return req, oauth2.NewAccessResponse()
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Failed to generate ID Token because the OpenID Connect session is not for the subject the device code was approved by.",
		},
		{
			name: "ShouldFailSessionIsNotFromTheApprovalOfTheDecision",
			setup: func(oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) (*oauth2.AccessRequest, *oauth2.AccessResponse) {
				return newDeviceApprovalTestRequest(oidcStore, tokenHandler, &DefaultSession{ApprovalID: "winner"}, &DefaultSession{ApprovalID: "loser"})
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Failed to generate ID Token because the OpenID Connect session is not from the approval the device code decision was recorded for.",
		},
		{
			name: "ShouldFailSessionWithoutApprovalIDForADecisionWithOne",
			setup: func(oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) (*oauth2.AccessRequest, *oauth2.AccessResponse) {
				return newDeviceApprovalTestRequest(oidcStore, tokenHandler, &DefaultSession{ApprovalID: "winner"}, &DefaultSession{})
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Failed to generate ID Token because the OpenID Connect session is not from the approval the device code decision was recorded for.",
		},
		{
			name: "ShouldPassSessionIsFromTheApprovalOfTheDecision",
			setup: func(oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) (*oauth2.AccessRequest, *oauth2.AccessResponse) {
				return newDeviceApprovalTestRequest(oidcStore, tokenHandler, &DefaultSession{ApprovalID: "winner"}, &DefaultSession{ApprovalID: "winner"})
			},
		},
		{
			name: "ShouldPassNeitherSessionHasAnApprovalID",
			setup: func(oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) (*oauth2.AccessRequest, *oauth2.AccessResponse) {
				return newDeviceApprovalTestRequest(oidcStore, tokenHandler, &DefaultSession{}, &DefaultSession{})
			},
		},
		{
			name: "ShouldPassDecisionSessionWithoutApprovalSession",
			setup: func(oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler) (*oauth2.AccessRequest, *oauth2.AccessResponse) {
				req, resp := newDeviceApprovalTestRequest(oidcStore, tokenHandler, &DefaultSession{ApprovalID: "winner"}, &DefaultSession{ApprovalID: "loser"})

				req.Session = &deviceApprovalTestUntrackedSession{Session: req.Session.(*DefaultSession)}

				return req, resp
			},
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

func TestGetSessionApprovalID(t *testing.T) {
	testCases := []struct {
		name     string
		session  any
		id       string
		expected bool
	}{
		{"ShouldNotTrackNil", nil, "", false},
		{"ShouldNotTrackTypedNil", (*DefaultSession)(nil), "", false},
		{"ShouldNotTrackSessionWithoutApprovalSession", &oauth2.DefaultSession{}, "", false},
		{"ShouldTrackSessionWithoutApprovalID", &DefaultSession{}, "", true},
		{"ShouldTrackSessionWithApprovalID", &DefaultSession{ApprovalID: "approval"}, "approval", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			id, ok := getSessionApprovalID(tc.session)

			assert.Equal(t, tc.id, id)
			assert.Equal(t, tc.expected, ok)
		})
	}
}

type deviceApprovalTestUntrackedSession struct {
	Session
}

func newDeviceApprovalTestRequest(oidcStore *mock.MockOpenIDConnectRequestStorage, tokenHandler *mock.MockCodeTokenEndpointHandler, decision, stored *DefaultSession) (*oauth2.AccessRequest, *oauth2.AccessResponse) {
	for _, session := range []*DefaultSession{decision, stored} {
		session.Subject, session.Claims, session.Headers, session.RequestedAt = "peter", &jwt.IDTokenClaims{Subject: "peter"}, &jwt.Headers{}, time.Now()
	}

	req := oauth2.NewAccessRequest(nil)
	req.GrantedScope = []string{consts.ScopeOpenID}
	req.GrantTypes = []string{string(oauth2.GrantTypeDeviceCode)}
	req.Session = decision
	req.Client = &oauth2.DefaultClient{
		GrantTypes: []string{string(oauth2.GrantTypeDeviceCode)},
	}

	tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("foobar", nil)
	oidcStore.EXPECT().GetOpenIDConnectSession(gomock.Any(), "foobar", req).DoAndReturn(func(_ context.Context, _ string, requester oauth2.Requester) (oauth2.Requester, error) {
		authReq := oauth2.NewAuthorizeRequest()
		authReq.GrantedScope = []string{consts.ScopeOpenID}
		authReq.Session = requester.GetSession()

		if hydrated, ok := requester.GetSession().(*DefaultSession); ok {
			*hydrated = *stored
		} else {
			*requester.GetSession().(*deviceApprovalTestUntrackedSession).Session.(*DefaultSession) = *stored
		}

		return authReq, nil
	}).AnyTimes()
	oidcStore.EXPECT().DeleteOpenIDConnectSession(gomock.Any(), "foobar").Return(nil).AnyTimes()

	return req, oauth2.NewAccessResponse()
}
