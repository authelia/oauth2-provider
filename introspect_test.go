// Copyright © 2026 Authelia
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/testing/mock"
)

func TestAccessTokenFromRequest(t *testing.T) {
	testCases := []struct {
		name     string
		setup    func() *http.Request
		expected string
	}{
		{
			name: "ShouldReturnEmptyWhenNoToken",
			setup: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com/test", nil)
				return req
			},
			expected: "",
		},
		{
			name: "ShouldReturnTokenFromBearerHeader",
			setup: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com/test", nil)
				req.Header.Add(consts.HeaderAuthorization, "Bearer TokenFromHeader")
				return req
			},
			expected: "TokenFromHeader",
		},
		{
			name: "ShouldReturnTokenFromBearerHeaderCaseInsensitive",
			setup: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com/test", nil)
				req.Header.Add(consts.HeaderAuthorization, "bearer TokenFromHeader")
				return req
			},
			expected: "TokenFromHeader",
		},
		{
			name: "ShouldReturnTokenFromQueryParameter",
			setup: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com/test?access_token=TokenFromQueryParam", nil)
				return req
			},
			expected: "TokenFromQueryParam",
		},
		{
			name: "ShouldFallThroughToFormWhenAuthorizationHeaderIsMalformed",
			setup: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com/test?access_token=TokenFromQueryParam", nil)
				req.Header.Add(consts.HeaderAuthorization, "Basic abc")
				return req
			},
			expected: "TokenFromQueryParam",
		},
		{
			name: "ShouldFallThroughToFormWhenAuthorizationHeaderHasSingleSegment",
			setup: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com/test?access_token=TokenFromQueryParam", nil)
				req.Header.Add(consts.HeaderAuthorization, "Bearer")
				return req
			},
			expected: "TokenFromQueryParam",
		},
		{
			name: "ShouldReturnEmptyWhenMultipartFormIsMalformed",
			setup: func() *http.Request {
				req, _ := http.NewRequest(http.MethodPost, "http://example.com/test", io.NopCloser(strings.NewReader("not a real multipart body")))
				req.Header.Set(consts.HeaderContentType, "multipart/form-data; boundary=foo")
				return req
			},
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := AccessTokenFromRequest(tc.setup())
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestIntrospect(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/test", nil)
	req.Header.Add(consts.HeaderAuthorization, "bearer some-token")

	testCases := []struct {
		name   string
		scopes []string
		setup  func(ctrl *gomock.Controller, config *Config, validator *mock.MockTokenIntrospector)
		err    string
	}{
		{
			name:   "ShouldFailNoIntrospectors",
			scopes: []string{},
			setup:  func(ctrl *gomock.Controller, config *Config, validator *mock.MockTokenIntrospector) {},
			err:    "The request could not be authorized. Check that you provided valid credentials in the right format. Could not find the requested resource(s).",
		},
		{
			name:   "ShouldFailIntrospectorReturnsErrUnknownRequest",
			scopes: []string{"foo"},
			setup: func(ctrl *gomock.Controller, config *Config, validator *mock.MockTokenIntrospector) {
				config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{validator}
				validator.EXPECT().IntrospectToken(gomock.Any(), "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(TokenUse(""), ErrUnknownRequest)
			},
			err: "The request could not be authorized. Unable to find a suitable validation strategy for the token, thus it is invalid.",
		},
		{
			name:   "ShouldFailIntrospectorReturnsErrInvalidClient",
			scopes: []string{"foo"},
			setup: func(ctrl *gomock.Controller, config *Config, validator *mock.MockTokenIntrospector) {
				config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{validator}
				validator.EXPECT().IntrospectToken(gomock.Any(), "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(TokenUse(""), ErrInvalidClient)
			},
			err: "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).",
		},
		{
			name: "ShouldFailIntrospectorReturnsGenericError",
			setup: func(ctrl *gomock.Controller, config *Config, validator *mock.MockTokenIntrospector) {
				config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{validator}
				validator.EXPECT().IntrospectToken(gomock.Any(), "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(TokenUse(""), assertError("some generic error"))
			},
			err: "The error is unrecognizable some generic error",
		},
		{
			name: "ShouldPass",
			setup: func(ctrl *gomock.Controller, config *Config, validator *mock.MockTokenIntrospector) {
				config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{validator}
				validator.EXPECT().IntrospectToken(gomock.Any(), "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Do(func(ctx context.Context, _ string, _ TokenUse, requester AccessRequester, _ []string) {
					requester.(*AccessRequest).GrantedScope = []string{"bar"}
				}).Return(TokenUse(""), nil)
			},
		},
		{
			name:   "ShouldPassWithScopes",
			scopes: []string{"bar"},
			setup: func(ctrl *gomock.Controller, config *Config, validator *mock.MockTokenIntrospector) {
				config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{validator}
				validator.EXPECT().IntrospectToken(gomock.Any(), "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Do(func(ctx context.Context, _ string, _ TokenType, requester AccessRequester, _ []string) {
					requester.(*AccessRequest).GrantedScope = []string{"bar"}
				}).Return(TokenUse(""), nil)
			},
		},
		{
			name: "ShouldPassWithMultipleHandlersIgnoringErrUnknownRequest",
			setup: func(ctrl *gomock.Controller, config *Config, validator *mock.MockTokenIntrospector) {
				other := mock.NewMockTokenIntrospector(ctrl)
				config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{other, validator}
				other.EXPECT().IntrospectToken(gomock.Any(), "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(TokenUse(""), ErrUnknownRequest)
				validator.EXPECT().IntrospectToken(gomock.Any(), "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(AccessToken, nil)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			validator := mock.NewMockTokenIntrospector(ctrl)
			config := new(Config)
			provider := compose.ComposeAllEnabled(config, storage.NewMemoryStore(), nil).(*Fosite)

			tc.setup(ctrl, config, validator)

			_, _, err := provider.IntrospectToken(t.Context(), AccessTokenFromRequest(req), AccessToken, nil, tc.scopes...)

			if tc.err != "" {
				assert.EqualError(t, ErrorToDebugRFC6749Error(err), tc.err)

				return
			}

			require.NoError(t, ErrorToDebugRFC6749Error(err))
		})
	}
}

type assertError string

func (e assertError) Error() string { return string(e) }
