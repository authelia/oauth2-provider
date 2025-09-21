// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"net/url"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/testing/mock"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestExplicit_HandleAuthorizeEndpointRequest(t *testing.T) {
	testCases := []struct {
		name          string
		setup         func(ctrl *gomock.Controller, request *oauth2.AuthorizeRequest, responder *mock.MockAuthorizeResponder) (handler OpenIDConnectExplicitHandler)
		expected      string
		expectedField string
	}{
		{
			name: "should pass because not responsible for handling an empty response type",
			setup: func(ctrl *gomock.Controller, request *oauth2.AuthorizeRequest, responder *mock.MockAuthorizeResponder) (handler OpenIDConnectExplicitHandler) {
				handler, _ = makeOpenIDConnectExplicitHandler(ctrl, oauth2.MinParameterEntropy)
				request.ResponseTypes = oauth2.Arguments{""}

				return
			},
		},
		{
			name: "ShouldHandleSuccessWithoutOpenIDScope",
			setup: func(ctrl *gomock.Controller, request *oauth2.AuthorizeRequest, responder *mock.MockAuthorizeResponder) (handler OpenIDConnectExplicitHandler) {
				handler, _ = makeOpenIDConnectExplicitHandler(ctrl, oauth2.MinParameterEntropy)

				request.GrantedScope = oauth2.Arguments{}
				request.RequestedScope = oauth2.Arguments{}
				request.ResponseTypes = oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow}
				request.Client = &oauth2.DefaultClient{
					ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
				}

				return
			},
		},
		{
			name: "ShouldFailWithoutCode",
			setup: func(ctrl *gomock.Controller, request *oauth2.AuthorizeRequest, responder *mock.MockAuthorizeResponder) (handler OpenIDConnectExplicitHandler) {
				handler, _ = makeOpenIDConnectExplicitHandler(ctrl, oauth2.MinParameterEntropy)

				request.GrantedScope = oauth2.Arguments{consts.ScopeOpenID}
				request.Form.Set(consts.FormParameterNonce, "11111111111111111111111111111")

				responder.EXPECT().GetCode().Return("")

				return
			},
			expected:      "The request failed because of an internal error that is probably caused by misconfiguration. The authorization code has not been issued yet, indicating a broken code configuration.",
			expectedField: "misconfiguration",
		},
		{
			name: "ShouldFailWithStorageError",
			setup: func(ctrl *gomock.Controller, request *oauth2.AuthorizeRequest, responder *mock.MockAuthorizeResponder) (handler OpenIDConnectExplicitHandler) {
				handler, store := makeOpenIDConnectExplicitHandler(ctrl, oauth2.MinParameterEntropy)
				responder.EXPECT().GetCode().AnyTimes().Return("codeexample")

				store.EXPECT().CreateOpenIDConnectSession(t.Context(), "codeexample", gomock.Eq(request.Sanitize(oidcParameters))).Return(errors.New("connection refused"))

				return
			},
			expected:      "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. connection refused",
			expectedField: "server_error",
		},
		{
			name: "ShouldHandleSuccess",
			setup: func(ctrl *gomock.Controller, request *oauth2.AuthorizeRequest, responder *mock.MockAuthorizeResponder) (handler OpenIDConnectExplicitHandler) {
				handler, store := makeOpenIDConnectExplicitHandler(ctrl, oauth2.MinParameterEntropy)

				responder.EXPECT().GetCode().AnyTimes().Return("codeexample")
				store.EXPECT().CreateOpenIDConnectSession(t.Context(), "codeexample", gomock.Eq(request.Sanitize(oidcParameters))).AnyTimes().Return(nil)

				return
			},
		},
		{
			name: "ShouldFailBecauseRedirectURLIsMissing",
			setup: func(ctrl *gomock.Controller, request *oauth2.AuthorizeRequest, responder *mock.MockAuthorizeResponder) (handler OpenIDConnectExplicitHandler) {
				request.Form.Del(consts.FormParameterRedirectURI)

				handler, store := makeOpenIDConnectExplicitHandler(ctrl, oauth2.MinParameterEntropy)

				responder.EXPECT().GetCode().Return("codeexample")
				store.EXPECT().CreateOpenIDConnectSession(gomock.Any(), "codeexample", gomock.Eq(request.Sanitize(oidcParameters))).AnyTimes().Return(nil)

				return
			},
			expected:      "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter is required when using OpenID Connect 1.0.",
			expectedField: "invalid_request",
		},
		{
			name: "ShouldFailBecausePromptNotWhitelisted",
			setup: func(ctrl *gomock.Controller, request *oauth2.AuthorizeRequest, responder *mock.MockAuthorizeResponder) (handler OpenIDConnectExplicitHandler) {
				request.Form.Set(consts.FormParameterPrompt, "x")

				handler, store := makeOpenIDConnectExplicitHandler(ctrl, oauth2.MinParameterEntropy)

				responder.EXPECT().GetCode().Return("codeexample")
				store.EXPECT().CreateOpenIDConnectSession(gomock.Any(), "codeexample", gomock.Eq(request.Sanitize(oidcParameters))).AnyTimes().Return(nil)

				return
			},
			expected:      "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The requested prompt value 'x' either contains unknown, unsupported, or prohibited prompt values. The permitted prompt values are 'login', 'none', 'consent', 'select_account'.",
			expectedField: "invalid_request",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			responder := mock.NewMockAuthorizeResponder(ctrl)

			session := NewDefaultSession()
			session.Claims.Subject = "foo"

			requester := oauth2.NewAuthorizeRequest()

			requester.RequestedScope = oauth2.Arguments{consts.ScopeOpenID}
			requester.GrantedScope = oauth2.Arguments{consts.ScopeOpenID}
			requester.ResponseTypes = oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow}
			requester.Session = session
			requester.RedirectURI, _ = url.ParseRequestURI("https://example.com")
			requester.Form = url.Values{
				consts.FormParameterRedirectURI:  {"https://example.com"},
				consts.FormParameterScope:        {consts.ScopeOpenID},
				consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow},
			}

			handler := tc.setup(ctrl, requester, responder)

			err := handler.HandleAuthorizeEndpointRequest(t.Context(), requester, responder)

			if len(tc.expected) != 0 || len(tc.expectedField) != 0 {
				require.NotNil(t, err)

				var (
					e  *oauth2.DebugRFC6749Error
					ok bool
				)

				e, ok = oauth2.ErrorToDebugRFC6749Error(err).(*oauth2.DebugRFC6749Error)
				require.True(t, ok)

				assert.EqualError(t, e, tc.expected)
				assert.Equal(t, tc.expectedField, e.ErrorField)
			} else {
				assert.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			}
		})
	}
}

// expose key to verify id_token
var key = gen.MustRSAKey()

//nolint:unparam
func makeOpenIDConnectExplicitHandler(ctrl *gomock.Controller, minParameterEntropy int) (OpenIDConnectExplicitHandler, *mock.MockOpenIDConnectRequestStorage) {
	store := mock.NewMockOpenIDConnectRequestStorage(ctrl)
	config := &oauth2.Config{MinParameterEntropy: minParameterEntropy}

	jwtStrategy := &jwt.DefaultStrategy{
		Config: config,
		Issuer: jwt.NewDefaultIssuerRS256Unverified(key),
	}

	var j = &DefaultStrategy{
		Strategy: jwtStrategy,
		Config:   config,
	}

	return OpenIDConnectExplicitHandler{
		OpenIDConnectRequestStorage: store,
		IDTokenHandleHelper: &IDTokenHandleHelper{
			IDTokenStrategy: j,
		},
		OpenIDConnectRequestValidator: NewOpenIDConnectRequestValidator(j.Strategy, config),
		Config:                        config,
	}, store
}
