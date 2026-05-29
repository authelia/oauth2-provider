// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/testing/mock"
	"authelia.com/provider/oauth2/x/errorsx"
)

func TestNewRevocationRequest(t *testing.T) {
	testCases := []struct {
		name     string
		header   http.Header
		form     url.Values
		body     io.Reader
		method   string
		mock     func(store *mock.MockStorage, handler *mock.MockRevocationHandler, client *DefaultClient)
		handlers RevocationHandlers
		err      string
	}{
		{
			name:   "ShouldFailWhenMethodIsNotPOST",
			header: http.Header{},
			method: http.MethodGet,
			mock:   func(store *mock.MockStorage, handler *mock.MockRevocationHandler, client *DefaultClient) {},
			err:    "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. HTTP method is 'GET' but expected 'POST'.",
		},
		{
			name:   "ShouldFailWhenPOSTBodyEmpty",
			header: http.Header{},
			method: http.MethodPost,
			mock:   func(store *mock.MockStorage, handler *mock.MockRevocationHandler, client *DefaultClient) {},
			err:    "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The POST body can not be empty.",
		},
		{
			name: "ShouldFailWhenMultipartBodyIsMalformed",
			header: http.Header{
				consts.HeaderContentType: {"multipart/form-data; boundary=foo"},
			},
			method: http.MethodPost,
			body:   strings.NewReader("not a real multipart body"),
			mock:   func(store *mock.MockStorage, handler *mock.MockRevocationHandler, client *DefaultClient) {},
			err:    "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Unable to parse HTTP body, make sure to send a properly formatted form request body. multipart: NextPart: EOF",
		},
		{
			name:   "ShouldFailWhenClientCredentialsMissing",
			header: http.Header{},
			method: http.MethodPost,
			form: url.Values{
				consts.FormParameterToken: {"foo"},
			},
			mock: func(store *mock.MockStorage, handler *mock.MockRevocationHandler, client *DefaultClient) {},
			err:  "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The required credentials were not found, used an unknown method, could not be parsed, were otherwise malformed, or were otherwise incorrect. The Client ID was missing from the request but it is required when there is no client assertion.",
		},
		{
			name: "ShouldFailWhenClientLookupFails",
			header: http.Header{
				consts.HeaderAuthorization: {basicAuth("foo", "bar")},
			},
			method: http.MethodPost,
			form: url.Values{
				consts.FormParameterToken: {"foo"},
			},
			mock: func(store *mock.MockStorage, handler *mock.MockRevocationHandler, client *DefaultClient) {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(nil, errors.New(""))
			},
			err: "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The required credentials were not found, used an unknown method, could not be parsed, were otherwise malformed, or were otherwise incorrect.",
		},
		{
			name: "ShouldFailWhenClientSecretInvalid",
			header: http.Header{
				consts.HeaderAuthorization: {basicAuth("foo", "bar")},
			},
			method: http.MethodPost,
			form: url.Values{
				consts.FormParameterToken: {"foo"},
			},
			mock: func(store *mock.MockStorage, handler *mock.MockRevocationHandler, client *DefaultClient) {
				client.ClientSecret = testClientSecretFoo
				client.Public = false
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
			},
			err: "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). crypto/bcrypt: hashedPassword is not the hash of the given password",
		},
		{
			name: "ShouldPassWhenHandlerSucceeds",
			header: http.Header{
				consts.HeaderAuthorization: {basicAuth("foo", "bar")},
			},
			method: http.MethodPost,
			form: url.Values{
				consts.FormParameterToken: {"foo"},
			},
			mock: func(store *mock.MockStorage, handler *mock.MockRevocationHandler, client *DefaultClient) {
				client.ClientSecret = testClientSecretBar
				client.Public = false
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				handler.EXPECT().RevokeToken(gomock.Any(), gomock.Eq("foo"), gomock.Any(), gomock.Eq(client)).Return(nil)
			},
		},
		{
			name: "ShouldPassWithAccessTokenHint",
			header: http.Header{
				consts.HeaderAuthorization: {basicAuth("foo", "bar")},
			},
			method: http.MethodPost,
			form: url.Values{
				consts.FormParameterToken:         {"foo"},
				consts.FormParameterTokenTypeHint: {consts.TokenTypeAccessToken},
			},
			mock: func(store *mock.MockStorage, handler *mock.MockRevocationHandler, client *DefaultClient) {
				client.ClientSecret = testClientSecretBar
				client.Public = false
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				handler.EXPECT().RevokeToken(gomock.Any(), gomock.Eq("foo"), gomock.Eq(AccessToken), gomock.Eq(client)).Return(nil)
			},
		},
		{
			name: "ShouldPassWithPublicClient",
			header: http.Header{
				consts.HeaderAuthorization: {basicAuth("foo", "")},
			},
			method: http.MethodPost,
			form: url.Values{
				consts.FormParameterToken:         {"foo"},
				consts.FormParameterTokenTypeHint: {consts.TokenTypeRefreshToken},
			},
			mock: func(store *mock.MockStorage, handler *mock.MockRevocationHandler, client *DefaultClient) {
				client.Public = true
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				handler.EXPECT().RevokeToken(gomock.Any(), gomock.Eq("foo"), gomock.Eq(RefreshToken), gomock.Eq(client)).Return(nil)
			},
		},
		{
			name: "ShouldPassWithRefreshTokenHint",
			header: http.Header{
				consts.HeaderAuthorization: {basicAuth("foo", "bar")},
			},
			method: http.MethodPost,
			form: url.Values{
				consts.FormParameterToken:         {"foo"},
				consts.FormParameterTokenTypeHint: {consts.TokenTypeRefreshToken},
			},
			mock: func(store *mock.MockStorage, handler *mock.MockRevocationHandler, client *DefaultClient) {
				client.ClientSecret = testClientSecretBar
				client.Public = false
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				handler.EXPECT().RevokeToken(gomock.Any(), gomock.Eq("foo"), gomock.Eq(RefreshToken), gomock.Eq(client)).Return(nil)
			},
		},
		{
			name: "ShouldIgnoreUnknownTokenTypeHint",
			header: http.Header{
				consts.HeaderAuthorization: {basicAuth("foo", "bar")},
			},
			method: http.MethodPost,
			form: url.Values{
				consts.FormParameterToken:         {"foo"},
				consts.FormParameterTokenTypeHint: {"bar"},
			},
			mock: func(store *mock.MockStorage, handler *mock.MockRevocationHandler, client *DefaultClient) {
				client.ClientSecret = testClientSecretBar
				client.Public = false
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				handler.EXPECT().RevokeToken(gomock.Any(), gomock.Eq("foo"), gomock.Eq(TokenType("bar")), gomock.Eq(client)).Return(nil)
			},
		},
		{
			name: "ShouldContinueWhenHandlerReturnsErrUnknownRequest",
			header: http.Header{
				consts.HeaderAuthorization: {basicAuth("foo", "bar")},
			},
			method: http.MethodPost,
			form: url.Values{
				consts.FormParameterToken: {"foo"},
			},
			mock: func(store *mock.MockStorage, handler *mock.MockRevocationHandler, client *DefaultClient) {
				client.ClientSecret = testClientSecretBar
				client.Public = false
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				handler.EXPECT().RevokeToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(errorsx.WithStack(ErrUnknownRequest))
			},
			err: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified.",
		},
		{
			name: "ShouldFailWhenHandlerReturnsOtherError",
			header: http.Header{
				consts.HeaderAuthorization: {basicAuth("foo", "bar")},
			},
			method: http.MethodPost,
			form: url.Values{
				consts.FormParameterToken: {"foo"},
			},
			mock: func(store *mock.MockStorage, handler *mock.MockRevocationHandler, client *DefaultClient) {
				client.ClientSecret = testClientSecretBar
				client.Public = false
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				handler.EXPECT().RevokeToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(errorsx.WithStack(ErrServerError.WithHint("Storage exploded.")))
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Storage exploded.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			store := mock.NewMockStorage(ctrl)
			handler := mock.NewMockRevocationHandler(ctrl)
			client := &DefaultClient{}

			config := &Config{}
			if tc.handlers == nil {
				config.RevocationHandlers = RevocationHandlers{handler}
			} else {
				config.RevocationHandlers = tc.handlers
			}

			provider := &Fosite{Store: store, Config: config}

			tc.mock(store, handler, client)

			r := &http.Request{
				Header:   tc.header,
				PostForm: tc.form,
				Form:     tc.form,
				Method:   tc.method,
			}

			if tc.body != nil {
				r.Body = io.NopCloser(tc.body)
			}

			err := provider.NewRevocationRequest(t.Context(), r)

			if tc.err != "" {
				assert.EqualError(t, ErrorToDebugRFC6749Error(err), tc.err)
				return
			}

			require.NoError(t, ErrorToDebugRFC6749Error(err))
		})
	}
}

func TestWriteRevocationResponse(t *testing.T) {
	testCases := []struct {
		name     string
		have     error
		expected int
	}{
		{
			name:     "ShouldHandleNil",
			have:     nil,
			expected: http.StatusOK,
		},
		{
			name:     "ShouldHandleErrInvalidRequest",
			have:     ErrInvalidRequest,
			expected: -1,
		},
		{
			name:     "ShouldHandleErrInvalidClient",
			have:     ErrInvalidClient,
			expected: -1,
		},
		{
			name:     "ShouldHandleErrInvalidGrant",
			have:     ErrInvalidGrant,
			expected: -1,
		},
		{
			name:     "ShouldHandleErrUnauthorizedClient",
			have:     ErrUnauthorizedClient,
			expected: -1,
		},
		{
			name:     "ShouldHandleErrUnsupportedGrantType",
			have:     ErrUnsupportedGrantType,
			expected: -1,
		},
		{
			name:     "ShouldHandleErrInvalidScope",
			have:     ErrInvalidScope,
			expected: -1,
		},
		{
			name:     "ShouldHandleOtherErrors",
			have:     fmt.Errorf("example"),
			expected: http.StatusInternalServerError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			store := mock.NewMockStorage(ctrl)
			provider := &Fosite{Store: store, Config: &Config{}}

			rw := httptest.NewRecorder()
			provider.WriteRevocationResponse(context.Background(), rw, tc.have)

			expected := tc.expected

			var rfc *RFC6749Error
			if errors.As(tc.have, &rfc) {
				if expected == -1 {
					expected = rfc.CodeField
				}
			}

			assert.Equal(t, expected, rw.Code)
			assert.Equal(t, consts.CacheControlNoStore, rw.Header().Get(consts.HeaderCacheControl))
			assert.Equal(t, consts.PragmaNoCache, rw.Header().Get(consts.HeaderPragma))

			if rfc != nil {
				assert.Equal(t, consts.ContentTypeApplicationJSON, rw.Header().Get(consts.HeaderContentType))
				assert.Contains(t, rw.Body.String(), rfc.ErrorField)
				assert.Contains(t, rw.Body.String(), rfc.HintField)
			}
		})
	}
}
