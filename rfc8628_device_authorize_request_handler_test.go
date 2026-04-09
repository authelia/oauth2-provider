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
	"authelia.com/provider/oauth2/testing/mock"
)

func TestNewDeviceAuthorizeRequest(t *testing.T) {
	testCases := []struct {
		name   string
		r      *http.Request
		query  url.Values
		err    string
		mock   func(store *mock.MockStorage)
		expect *DeviceAuthorizeRequest
	}{
		{
			name: "ShouldFailEmptyRequest",
			err:  "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client does not exist. foo",
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), gomock.Any()).Return(nil, errors.New("foo"))
			},
		},
		{
			name: "ShouldFailInvalidClient",
			r: &http.Request{
				PostForm: url.Values{
					"client_id": {"1234"},
					"scope":     {"foo bar"},
				},
			},
			err: "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client does not exist. foo",
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), gomock.Any()).Return(nil, errors.New("foo"))
			},
		},
		{
			name: "ShouldFailClientWithoutScopeBaz",
			r: &http.Request{
				PostForm: url.Values{
					"client_id": {"1234"},
					"scope":     {"foo bar baz"},
				},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"},
					Scopes:     []string{"foo", "bar"},
				}, nil)
			},
			err: "The requested scope is invalid, unknown, or malformed. The OAuth 2.0 Client is not allowed to request scope 'baz'.",
		},
		{
			name: "ShouldPass",
			r: &http.Request{
				PostForm: url.Values{
					"client_id": {"1234"},
					"scope":     {"foo bar"},
				},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					Scopes:     []string{"foo", "bar"},
					GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"},
				}, nil)
			},
			expect: &DeviceAuthorizeRequest{
				Request: Request{
					Client: &DefaultClient{
						Scopes: []string{"foo", "bar"},
					},
					RequestedScope: []string{"foo", "bar"},
				},
			},
		},
		{
			name: "ShouldFailClientWithoutDeviceCodeGrant",
			r: &http.Request{
				PostForm: url.Values{
					"client_id": {"1234"},
					"scope":     {"foo bar"},
				},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					Scopes: []string{"foo", "bar"},
				}, nil)
			},
			err: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The requested OAuth 2.0 Client does not have the 'urn:ietf:params:oauth:grant-type:device_code' grant.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			store := mock.NewMockStorage(ctrl)
			conf := &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}}

			tc.mock(store)
			r := tc.r
			if r == nil {
				r = &http.Request{Header: http.Header{}}
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
