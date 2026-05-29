// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/testing/mock"
)

func TestNewDeviceAuthorizeRequest(t *testing.T) {
	testCases := []struct {
		name   string
		r      *http.Request
		err    string
		mock   func(store *mock.MockStorage)
		expect *DeviceAuthorizeRequest
	}{
		{
			name: "ShouldFailEmptyRequest",
			err:  "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). Client Credentials missing or malformed. The Client ID was missing from the request but it is required when there is no client assertion.",
			mock: func(store *mock.MockStorage) {},
		},
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
			name: "ShouldFailInvalidClient",
			r: &http.Request{
				Method: http.MethodPost,
				PostForm: url.Values{
					consts.FormParameterClientID: {"1234"},
					consts.FormParameterScope:    {"foo bar"},
				},
			},
			err: "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). foo",
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(nil, errors.New("foo"))
			},
		},
		{
			name: "ShouldFailConfidentialClientWithoutSecret",
			r: &http.Request{
				PostForm: url.Values{
					consts.FormParameterClientID: {"1234"},
					consts.FormParameterScope:    {"foo bar"},
				},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ID:         "1234",
					Public:     false,
					GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"},
					Scopes:     []string{"foo", "bar"},
				}, nil)
			},
			err: "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The request was determined to be using 'none_endpoint_auth_method' method 'token', however the OAuth 2.0 client registration does not allow this method. The registered client with id '1234' is configured with a confidential client type but only client registrations with a public client type can use this 'token_endpoint_auth_method'.",
		},
		{
			name: "ShouldFailConfidentialClientWrongSecretBasic",
			r: &http.Request{
				Header: http.Header{
					consts.HeaderAuthorization: {basicAuth("1234", "wrong")},
				},
				PostForm: url.Values{
					consts.FormParameterScope: {"foo bar"},
				},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ID:           "1234",
					Public:       false,
					ClientSecret: testClientSecretFoo,
					GrantTypes:   []string{"urn:ietf:params:oauth:grant-type:device_code"},
					Scopes:       []string{"foo", "bar"},
				}, nil)
			},
			err: "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). crypto/bcrypt: hashedPassword is not the hash of the given password",
		},
		{
			name: "ShouldFailClientWithoutScopeBaz",
			r: &http.Request{
				PostForm: url.Values{
					consts.FormParameterClientID: {"1234"},
					consts.FormParameterScope:    {"foo bar baz"},
				},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ID:         "1234",
					Public:     true,
					GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"},
					Scopes:     []string{"foo", "bar"},
				}, nil)
			},
			err: "The requested scope is invalid, unknown, or malformed. The OAuth 2.0 Client is not allowed to request scope 'baz'.",
		},
		{
			name: "ShouldFailClientWithoutDeviceCodeGrant",
			r: &http.Request{
				PostForm: url.Values{
					consts.FormParameterClientID: {"1234"},
					consts.FormParameterScope:    {"foo bar"},
				},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ID:     "1234",
					Public: true,
					Scopes: []string{"foo", "bar"},
				}, nil)
			},
			err: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The requested OAuth 2.0 Client does not have the 'urn:ietf:params:oauth:grant-type:device_code' grant.",
		},
		{
			name: "ShouldPassPublicClient",
			r: &http.Request{
				PostForm: url.Values{
					consts.FormParameterClientID: {"1234"},
					consts.FormParameterScope:    {"foo bar"},
				},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ID:         "1234",
					Public:     true,
					Scopes:     []string{"foo", "bar"},
					GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"},
				}, nil)
			},
			expect: &DeviceAuthorizeRequest{
				Request: Request{
					Client: &DefaultClient{
						ID:     "1234",
						Public: true,
						Scopes: []string{"foo", "bar"},
					},
					RequestedScope: []string{"foo", "bar"},
				},
			},
		},
		{
			name: "ShouldPassConfidentialClientBasicAuth",
			r: &http.Request{
				Header: http.Header{
					consts.HeaderAuthorization: {basicAuth("1234", "foo")},
				},
				PostForm: url.Values{
					consts.FormParameterScope: {"foo bar"},
				},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ID:           "1234",
					Public:       false,
					ClientSecret: testClientSecretFoo,
					Scopes:       []string{"foo", "bar"},
					GrantTypes:   []string{"urn:ietf:params:oauth:grant-type:device_code"},
				}, nil)
			},
		},
		{
			name: "ShouldPassConfidentialClientPostSecret",
			r: &http.Request{
				PostForm: url.Values{
					consts.FormParameterClientID:     {"1234"},
					consts.FormParameterClientSecret: {"foo"},
					consts.FormParameterScope:        {"foo bar"},
				},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ID:           "1234",
					Public:       false,
					ClientSecret: testClientSecretFoo,
					Scopes:       []string{"foo", "bar"},
					GrantTypes:   []string{"urn:ietf:params:oauth:grant-type:device_code"},
				}, nil)
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
				r = &http.Request{Header: http.Header{}, Method: http.MethodPost}
			} else if r.Method == "" {
				r.Method = http.MethodPost
			}

			ar, err := conf.NewRFC862DeviceAuthorizeRequest(context.Background(), r)
			if tc.err != "" {
				assert.EqualError(t, ErrorToDebugRFC6749Error(err), tc.err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, ar.GetRequestedAt())
			}
		})
	}
}
