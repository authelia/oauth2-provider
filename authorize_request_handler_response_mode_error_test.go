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

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestNewAuthorizeRequestErrorResponseMode(t *testing.T) {
	testCases := []struct {
		name     string
		client   Client
		redirect string
		mode     string
		scope    string
		err      error
		expected ResponseModeType
		noURI    bool
	}{
		{
			name:     "ShouldRefuseFormPostToAPrivateUseRedirectURI",
			client:   &DefaultResponseModeClient{DefaultClient: &DefaultClient{ID: "app", Public: true, RedirectURIs: []string{"com.example.app:/cb"}, Scopes: []string{"foo"}, ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow}}, ResponseModes: []ResponseModeType{ResponseModeFormPost, ResponseModeQuery}},
			redirect: "com.example.app:/cb",
			mode:     consts.ResponseModeFormPost,
			scope:    "foo",
			err:      ErrUnsupportedResponseMode,
			expected: ResponseModeQuery,
		},
		{
			name:     "ShouldAcceptFormPostToAnHTTPSRedirectURI",
			client:   &DefaultResponseModeClient{DefaultClient: &DefaultClient{ID: "app", RedirectURIs: []string{"https://client.example.com/cb"}, Scopes: []string{"foo"}, ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow}}, ResponseModes: []ResponseModeType{ResponseModeFormPost}},
			redirect: "https://client.example.com/cb",
			mode:     consts.ResponseModeFormPost,
			scope:    "foo",
			expected: ResponseModeFormPost,
		},
		{
			name:     "ShouldNotRedirectToAJavaScriptRedirectURI",
			client:   &DefaultClient{ID: "app", RedirectURIs: []string{"javascript:alert(1)"}, Scopes: []string{"foo"}, ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow}},
			redirect: "javascript:alert(1)",
			scope:    "foo",
			err:      ErrInvalidRequest,
			noURI:    true,
		},
		{
			name: "ShouldDeliverAnEarlyErrorInARegisteredResponseMode",
			client: &DefaultResponseModeClient{
				DefaultClient: &DefaultClient{ID: "app", RedirectURIs: []string{"https://client.example.com/cb"}, Scopes: []string{"foo"}, ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow}},
				ResponseModes: []ResponseModeType{ResponseModeFragment},
			},
			redirect: "https://client.example.com/cb",
			mode:     consts.ResponseModeFormPost,
			scope:    "bar",
			err:      ErrInvalidScope,
			expected: ResponseModeFragment,
		},
		{
			name: "ShouldPreferTheDefaultResponseModeWhenRegistered",
			client: &DefaultResponseModeClient{
				DefaultClient: &DefaultClient{ID: "app", RedirectURIs: []string{"https://client.example.com/cb"}, Scopes: []string{"foo"}, ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow}},
				ResponseModes: []ResponseModeType{ResponseModeFragment, ResponseModeQuery},
			},
			redirect: "https://client.example.com/cb",
			mode:     consts.ResponseModeFormPost,
			scope:    "bar",
			err:      ErrInvalidScope,
			expected: ResponseModeQuery,
		},
		{
			name: "ShouldResolveARegisteredJWTResponseModeForTheCodeResponseType",
			client: &DefaultResponseModeClient{
				DefaultClient: &DefaultClient{ID: "app", RedirectURIs: []string{"https://client.example.com/cb"}, Scopes: []string{"foo"}, ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow}},
				ResponseModes: []ResponseModeType{ResponseModeJWT},
			},
			redirect: "https://client.example.com/cb",
			mode:     consts.ResponseModeFormPost,
			scope:    "bar",
			err:      ErrInvalidScope,
			expected: ResponseModeQueryJWT,
		},
		{
			name: "ShouldKeepARegisteredResponseMode",
			client: &DefaultResponseModeClient{
				DefaultClient: &DefaultClient{ID: "app", RedirectURIs: []string{"https://client.example.com/cb"}, Scopes: []string{"foo"}, ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow}},
				ResponseModes: []ResponseModeType{ResponseModeQuery, ResponseModeFormPost},
			},
			redirect: "https://client.example.com/cb",
			mode:     consts.ResponseModeFormPost,
			scope:    "bar",
			err:      ErrInvalidScope,
			expected: ResponseModeFormPost,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := storage.NewMemoryStore()
			store.Clients["app"] = tc.client

			provider := &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy, EnforcePKCE: false, AllowInsecureRedirectURIForPublicClients: true}}

			query := url.Values{
				consts.FormParameterClientID:     {"app"},
				consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow},
				consts.FormParameterRedirectURI:  {tc.redirect},
				consts.FormParameterScope:        {tc.scope},
				consts.FormParameterState:        {"strong-enough-state"},
			}

			if tc.mode != "" {
				query.Set(consts.FormParameterResponseMode, tc.mode)
			}

			r := &http.Request{Header: http.Header{}, Method: http.MethodGet, URL: &url.URL{RawQuery: query.Encode()}}

			ar, err := provider.NewAuthorizeRequest(context.Background(), r)

			if tc.err == nil {
				require.NoError(t, ErrorToDebugRFC6749Error(err))
			} else {
				require.ErrorIs(t, err, tc.err)
			}

			if tc.noURI {
				assert.Nil(t, ar.GetRedirectURI())
				assert.False(t, ar.IsRedirectURIValid())

				return
			}

			assert.Equal(t, tc.expected, ar.GetResponseMode())
		})
	}
}
