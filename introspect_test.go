// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"net/http"
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

func TestAccessTokenFromRequestNoToken(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com/test", nil)

	assert.Equal(t, AccessTokenFromRequest(req), "", "No token should produce an empty string")
}

func TestAccessTokenFromRequestHeader(t *testing.T) {
	token := "TokenFromHeader"

	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Add(consts.HeaderAuthorization, "Bearer "+token)

	assert.Equal(t, AccessTokenFromRequest(req), token, "Token should be obtainable from header")
}

func TestAccessTokenFromRequestQuery(t *testing.T) {
	token := "TokenFromQueryParam"

	req, _ := http.NewRequest("GET", "http://example.com/test?access_token="+token, nil)

	assert.Equal(t, AccessTokenFromRequest(req), token, "Token should be obtainable from access_token query parameter")
}

func TestIntrospect(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Add(consts.HeaderAuthorization, "bearer some-token")

	testCases := []struct {
		name   string
		scopes []string
		setup  func(config *Config, validator *mock.MockTokenIntrospector)
		err    string
	}{
		{
			name:   "ShouldFailNoIntrospectors",
			scopes: []string{},
			setup: func(config *Config, validator *mock.MockTokenIntrospector) {
			},
			err: "The request could not be authorized. Check that you provided valid credentials in the right format. Could not find the requested resource(s).",
		},
		{
			name:   "ShouldFailIntrospectorReturnsErrUnknownRequest",
			scopes: []string{"foo"},
			setup: func(config *Config, validator *mock.MockTokenIntrospector) {
				config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{validator}
				validator.EXPECT().IntrospectToken(t.Context(), "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(TokenUse(""), ErrUnknownRequest)
			},
			err: "The request could not be authorized. Unable to find a suitable validation strategy for the token, thus it is invalid.",
		},
		{
			name:   "ShouldFailIntrospectorReturnsErrInvalidClient",
			scopes: []string{"foo"},
			setup: func(config *Config, validator *mock.MockTokenIntrospector) {
				config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{validator}
				validator.EXPECT().IntrospectToken(t.Context(), "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(TokenUse(""), ErrInvalidClient)
			},
			err: "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).",
		},
		{
			name: "ShouldPass",
			setup: func(config *Config, validator *mock.MockTokenIntrospector) {
				config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{validator}
				validator.EXPECT().IntrospectToken(t.Context(), "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Do(func(ctx context.Context, _ string, _ TokenUse, requester AccessRequester, _ []string) {
					requester.(*AccessRequest).GrantedScope = []string{"bar"}
				}).Return(TokenUse(""), nil)
			},
		},
		{
			name:   "ShouldPassWithScopes",
			scopes: []string{"bar"},
			setup: func(config *Config, validator *mock.MockTokenIntrospector) {
				config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{validator}
				validator.EXPECT().IntrospectToken(t.Context(), "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Do(func(ctx context.Context, _ string, _ TokenType, requester AccessRequester, _ []string) {
					requester.(*AccessRequest).GrantedScope = []string{"bar"}
				}).Return(TokenUse(""), nil)
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

			tc.setup(config, validator)
			_, _, err := provider.IntrospectToken(t.Context(), AccessTokenFromRequest(req), AccessToken, nil, tc.scopes...)
			if tc.err != "" {
				assert.EqualError(t, ErrorToDebugRFC6749Error(err), tc.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
