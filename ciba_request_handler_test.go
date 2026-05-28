// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/testing/mock"
)

func TestFosite_NewOpenIDCIBARequest(t *testing.T) {
	testCases := []struct {
		name   string
		r      *http.Request
		err    string
		mock   func(store *mock.MockStorage)
		assert func(t *testing.T, requester CIBARequester)
	}{
		{
			name: "ShouldFailInvalidMethodGET",
			r: &http.Request{
				Method: http.MethodGet,
			},
			err:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. HTTP method is 'GET', expected 'POST'.",
			mock: func(store *mock.MockStorage) {},
		},
		{
			name: "ShouldFailInvalidMethodPUT",
			r: &http.Request{
				Method: http.MethodPut,
			},
			err:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. HTTP method is 'PUT', expected 'POST'.",
			mock: func(store *mock.MockStorage) {},
		},
		{
			name: "ShouldFailMissingClientID",
			r:    &http.Request{Method: http.MethodPost},
			err:  "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client could not be authenticated. The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Client Credentials missing or malformed. The Client ID was missing from the request but it is required when there is no client assertion.",
			mock: func(store *mock.MockStorage) {},
		},
		{
			name: "ShouldFailClientWithoutCIBAGrant",
			r: &http.Request{
				Method: http.MethodPost,
				Header: http.Header{
					consts.HeaderAuthorization: {basicAuth("1234", "foo")},
				},
				PostForm: url.Values{
					consts.FormParameterScope: {"openid"},
				},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ID:           "1234",
					ClientSecret: testClientSecretFoo,
					GrantTypes:   []string{"authorization_code"},
					Scopes:       []string{"openid"},
				}, nil)
			},
			err: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The requested OAuth 2.0 Client does not have the 'urn:openid:params:grant-type:ciba' grant.",
		},
		{
			name: "ShouldFailScopeMissingOpenID",
			r: &http.Request{
				Method: http.MethodPost,
				Header: http.Header{
					consts.HeaderAuthorization: {basicAuth("1234", "foo")},
				},
				PostForm: url.Values{
					consts.FormParameterScope:     {"profile"},
					consts.FormParameterLoginHint: {"user@example.com"},
				},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ID:           "1234",
					ClientSecret: testClientSecretFoo,
					GrantTypes:   []string{"urn:openid:params:grant-type:ciba"},
					Scopes:       []string{"openid", "profile"},
				}, nil)
			},
			err: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'scope' parameter is required for OpenID Connect CIBA and must contain the 'openid' scope value.",
		},
		{
			name: "ShouldFailScopeNotAllowedForClient",
			r: &http.Request{
				Method: http.MethodPost,
				Header: http.Header{
					consts.HeaderAuthorization: {basicAuth("1234", "foo")},
				},
				PostForm: url.Values{
					consts.FormParameterScope:     {"openid baz"},
					consts.FormParameterLoginHint: {"user@example.com"},
				},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ID:           "1234",
					ClientSecret: testClientSecretFoo,
					GrantTypes:   []string{"urn:openid:params:grant-type:ciba"},
					Scopes:       []string{"openid"},
				}, nil)
			},
			err: "The requested scope is invalid, unknown, or malformed. The OAuth 2.0 Client is not allowed to request scope 'baz'.",
		},
		{
			name: "ShouldFailNoHints",
			r: &http.Request{
				Method: http.MethodPost,
				Header: http.Header{
					consts.HeaderAuthorization: {basicAuth("1234", "foo")},
				},
				PostForm: url.Values{
					consts.FormParameterScope: {"openid"},
				},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ID:           "1234",
					ClientSecret: testClientSecretFoo,
					GrantTypes:   []string{"urn:openid:params:grant-type:ciba"},
					Scopes:       []string{"openid"},
				}, nil)
			},
			err: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The CIBA request must include exactly one of 'login_hint', 'login_hint_token', or 'id_token_hint'.",
		},
		{
			name: "ShouldFailMultipleHints",
			r: &http.Request{
				Method: http.MethodPost,
				Header: http.Header{
					consts.HeaderAuthorization: {basicAuth("1234", "foo")},
				},
				PostForm: url.Values{
					consts.FormParameterScope:       {"openid"},
					consts.FormParameterLoginHint:   {"user@example.com"},
					consts.FormParameterIDTokenHint: {"some-id-token"},
				},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ID:           "1234",
					ClientSecret: testClientSecretFoo,
					GrantTypes:   []string{"urn:openid:params:grant-type:ciba"},
					Scopes:       []string{"openid"},
				}, nil)
			},
			err: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The CIBA request must include exactly one of 'login_hint', 'login_hint_token', or 'id_token_hint'.",
		},
		{
			name: "ShouldPassWithLoginHint",
			r: &http.Request{
				Method: http.MethodPost,
				Header: http.Header{
					consts.HeaderAuthorization: {basicAuth("1234", "foo")},
				},
				PostForm: url.Values{
					consts.FormParameterScope:     {"openid"},
					consts.FormParameterLoginHint: {"user@example.com"},
				},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ID:           "1234",
					ClientSecret: testClientSecretFoo,
					GrantTypes:   []string{"urn:openid:params:grant-type:ciba"},
					Scopes:       []string{"openid"},
				}, nil)
			},
			assert: func(t *testing.T, requester CIBARequester) {
				assert.Equal(t, "1234", requester.GetClient().GetID())
				assert.True(t, requester.GetRequestedScopes().Has("openid"))
			},
		},
		{
			name: "ShouldPassWithLoginHintToken",
			r: &http.Request{
				Method: http.MethodPost,
				Header: http.Header{
					consts.HeaderAuthorization: {basicAuth("1234", "foo")},
				},
				PostForm: url.Values{
					consts.FormParameterScope:          {"openid"},
					consts.FormParameterLoginHintToken: {"a-token"},
				},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ID:           "1234",
					ClientSecret: testClientSecretFoo,
					GrantTypes:   []string{"urn:openid:params:grant-type:ciba"},
					Scopes:       []string{"openid"},
				}, nil)
			},
			assert: func(t *testing.T, requester CIBARequester) {
				assert.Equal(t, "a-token", requester.GetRequestForm().Get(consts.FormParameterLoginHintToken))
			},
		},
		{
			name: "ShouldPassWithIDTokenHint",
			r: &http.Request{
				Method: http.MethodPost,
				Header: http.Header{
					consts.HeaderAuthorization: {basicAuth("1234", "foo")},
				},
				PostForm: url.Values{
					consts.FormParameterScope:       {"openid profile"},
					consts.FormParameterIDTokenHint: {"the.id.token"},
				},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ID:           "1234",
					ClientSecret: testClientSecretFoo,
					GrantTypes:   []string{"urn:openid:params:grant-type:ciba"},
					Scopes:       []string{"openid", "profile"},
				}, nil)
			},
			assert: func(t *testing.T, requester CIBARequester) {
				assert.True(t, requester.GetRequestedScopes().Has("openid"))
				assert.True(t, requester.GetRequestedScopes().Has("profile"))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			store := mock.NewMockStorage(ctrl)
			conf := &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy}}

			tc.mock(store)

			r := tc.r
			if r == nil {
				r = &http.Request{Method: http.MethodPost, Header: http.Header{}}
			}

			ar, err := conf.NewOpenIDCIBARequest(context.Background(), r)

			if tc.err != "" {
				assert.EqualError(t, ErrorToDebugRFC6749Error(err), tc.err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, ar)
			assert.NotNil(t, ar.GetRequestedAt())

			if tc.assert != nil {
				tc.assert(t, ar)
			}
		})
	}
}
