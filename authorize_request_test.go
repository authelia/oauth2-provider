// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthorizeRequestURLRegression(t *testing.T) {
	require.Nil(t, NewAuthorizeRequest().RedirectURI)
}

func TestAuthorizeRequest(t *testing.T) {
	var urlparse = func(rawurl string) *url.URL {
		u, _ := url.Parse(rawurl)
		return u
	}

	testCases := []struct {
		name         string
		ar           *AuthorizeRequest
		isRedirValid bool
	}{
		{
			name:         "ShouldRejectAnEmptyRequest",
			ar:           NewAuthorizeRequest(),
			isRedirValid: false,
		},
		{
			name: "ShouldRejectARedirectURIWithNoClient",
			ar: &AuthorizeRequest{
				RedirectURI: urlparse("https://foobar"),
			},
			isRedirValid: false,
		},
		{
			name: "ShouldRejectARedirectURIAgainstAnEmptyRegisteredURI",
			ar: &AuthorizeRequest{
				RedirectURI: urlparse("https://foobar"),
				Request: Request{
					Client: &DefaultClient{RedirectURIs: []string{""}},
				},
			},
			isRedirValid: false,
		},
		{
			name: "ShouldRejectAnEmptyRedirectURI",
			ar: &AuthorizeRequest{
				Request: Request{
					Client: &DefaultClient{RedirectURIs: []string{""}},
				},
				RedirectURI: urlparse(""),
			},
			isRedirValid: false,
		},
		{
			name: "ShouldRejectAnEmptyRedirectURIWithAnEmptyRegisteredURI",
			ar: &AuthorizeRequest{
				Request: Request{
					Client: &DefaultClient{RedirectURIs: []string{""}},
				},
				RedirectURI: urlparse(""),
			},
			isRedirValid: false,
		},
		{
			name: "ShouldRejectARegisteredRedirectURIWithAFragment",
			ar: &AuthorizeRequest{
				RedirectURI: urlparse("https://foobar.com#123"),
				Request: Request{
					Client: &DefaultClient{RedirectURIs: []string{"https://foobar.com#123"}},
				},
			},
			isRedirValid: false,
		},
		{
			name: "ShouldRejectARequestedRedirectURIWithAFragment",
			ar: &AuthorizeRequest{
				Request: Request{
					Client: &DefaultClient{RedirectURIs: []string{"https://foobar.com"}},
				},
				RedirectURI: urlparse("https://foobar.com#123"),
			},
			isRedirValid: false,
		},
		{
			name: "ShouldAcceptAMatchingRedirectURI",
			ar: &AuthorizeRequest{
				Request: Request{
					Client:         &DefaultClient{RedirectURIs: []string{"https://foobar.com/cb"}},
					RequestedAt:    time.Now().UTC(),
					RequestedScope: []string{"foo", "bar"},
				},
				RedirectURI:   urlparse("https://foobar.com/cb"),
				ResponseTypes: []string{"foo", "bar"},
				State:         "foobar",
			},
			isRedirValid: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.ar.Client, tc.ar.GetClient())
			assert.Equal(t, tc.ar.RedirectURI, tc.ar.GetRedirectURI())
			assert.Equal(t, tc.ar.RequestedAt, tc.ar.GetRequestedAt())
			assert.Equal(t, tc.ar.ResponseTypes, tc.ar.GetResponseTypes())
			assert.Equal(t, tc.ar.RequestedScope, tc.ar.GetRequestedScopes())
			assert.Equal(t, tc.ar.State, tc.ar.GetState())
			assert.Equal(t, tc.isRedirValid, tc.ar.IsRedirectURIValid())

			tc.ar.GrantScope("foo")
			tc.ar.SetSession(&DefaultSession{})
			tc.ar.SetRequestedScopes([]string{"foo"})

			assert.True(t, tc.ar.GetGrantedScopes().Has("foo"))
			assert.True(t, tc.ar.GetRequestedScopes().Has("foo"))
			assert.Equal(t, &DefaultSession{}, tc.ar.GetSession())
		})
	}
}
