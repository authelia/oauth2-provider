// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"bytes"
	"io"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestIsLocalhost(t *testing.T) {
	for k, c := range []struct {
		expect bool
		rawurl string
	}{
		{expect: false, rawurl: "https://foo.bar"},
		{expect: true, rawurl: "https://localhost"},
		{expect: true, rawurl: "https://localhost:1234"},
		{expect: true, rawurl: "https://127.0.0.1:1234"},
		{expect: true, rawurl: "https://127.0.0.1"},
		{expect: true, rawurl: "https://test.localhost:1234"},
		{expect: true, rawurl: "https://test.localhost"},
	} {
		u, _ := url.Parse(c.rawurl)
		assert.Equal(t, c.expect, oauth2.IsLocalhost(u), "case %d", k)
	}
}

// rfc6749 10.6.
// Authorization Code Redirection URI Manipulation
// The authorization server	MUST require public clients and SHOULD require confidential clients
// to register their redirection URIs.  If a redirection URI is provided
// in the request, the authorization server MUST validate it against the
// registered value.
//
// rfc6819 4.4.1.7.
// Threat: Authorization "code" Leakage through Counterfeit Client
// The authorization server may also enforce the usage and validation
// of pre-registered redirect URIs (see Section 5.2.3.5).
func TestDoesClientWhiteListRedirect(t *testing.T) {
	testCases := []struct {
		name          string
		client        oauth2.Client
		have          string
		expected      string
		expectedMatch bool
	}{
		{
			name:          "ShouldNotMatchClientWithEmptyURI",
			client:        &oauth2.DefaultClient{RedirectURIs: []string{""}},
			have:          "https://foo.com/cb",
			expected:      "",
			expectedMatch: false,
		},
		{
			name:          "ShouldMatchNativeAppRegistered",
			client:        &oauth2.DefaultClient{RedirectURIs: []string{"wta://auth"}},
			have:          "wta://auth",
			expected:      "wta://auth",
			expectedMatch: true,
		},
		{
			client:        &oauth2.DefaultClient{RedirectURIs: []string{"wta:///auth"}},
			have:          "wta:///auth",
			expected:      "wta:///auth",
			expectedMatch: true,
		},
		{
			client:        &oauth2.DefaultClient{RedirectURIs: []string{"wta://foo/auth"}},
			have:          "wta://foo/auth",
			expected:      "wta://foo/auth",
			expectedMatch: true,
		},
		{
			client:        &oauth2.DefaultClient{RedirectURIs: []string{"https://bar.com/cb"}},
			have:          "https://foo.com/cb",
			expectedMatch: false,
		},
		{
			client:        &oauth2.DefaultClient{RedirectURIs: []string{"https://bar.com/cb"}},
			have:          "",
			expectedMatch: true,
			expected:      "https://bar.com/cb",
		},
		{
			client:        &oauth2.DefaultClient{RedirectURIs: []string{""}},
			have:          "",
			expectedMatch: false,
		},
		{
			client:        &oauth2.DefaultClient{RedirectURIs: []string{"https://bar.com/cb"}},
			have:          "https://bar.com/cb",
			expectedMatch: true,
			expected:      "https://bar.com/cb",
		},
		{
			client:        &oauth2.DefaultClient{RedirectURIs: []string{"https://bar.com/cb"}},
			have:          "https://bar.com/cb123",
			expectedMatch: false,
		},
		{
			client:        &oauth2.DefaultClient{RedirectURIs: []string{"http://[::1]"}},
			have:          "http://[::1]:1024",
			expected:      "http://[::1]:1024",
			expectedMatch: true,
		},
		{
			client:        &oauth2.DefaultClient{RedirectURIs: []string{"http://[::1]"}},
			have:          "http://[::1]:1024/cb",
			expectedMatch: false,
		},
		{
			client:        &oauth2.DefaultClient{RedirectURIs: []string{"http://[::1]/cb"}},
			have:          "http://[::1]:1024/cb",
			expected:      "http://[::1]:1024/cb",
			expectedMatch: true,
		},
		{
			client:        &oauth2.DefaultClient{RedirectURIs: []string{"http://[::1]"}},
			have:          "http://foo.bar/bar",
			expectedMatch: false,
		},
		{
			client:        &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1"}},
			have:          "http://127.0.0.1:1024",
			expected:      "http://127.0.0.1:1024",
			expectedMatch: true,
		},
		{
			client:        &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1/cb"}},
			have:          "http://127.0.0.1:64000/cb",
			expected:      "http://127.0.0.1:64000/cb",
			expectedMatch: true,
		},
		{
			client:        &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1"}},
			have:          "http://127.0.0.1:64000/cb",
			expectedMatch: false,
		},
		{
			client:        &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1"}},
			have:          "http://127.0.0.1",
			expected:      "http://127.0.0.1",
			expectedMatch: true,
		},
		{
			client:        &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1/Cb"}},
			have:          "http://127.0.0.1:8080/Cb",
			expected:      "http://127.0.0.1:8080/Cb",
			expectedMatch: true,
		},
		{
			client:        &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1"}},
			have:          "http://foo.bar/bar",
			expectedMatch: false,
		},
		{
			client:        &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1"}},
			have:          ":/invalid.uri)bar",
			expectedMatch: false,
		},
		{
			client:        &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1:8080/cb"}},
			have:          "http://127.0.0.1:8080/Cb",
			expectedMatch: false,
		},
		{
			client:        &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1:8080/cb"}},
			have:          "http://127.0.0.1:8080/cb?foo=bar",
			expectedMatch: false,
		},
		{
			client:        &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1:8080/cb?foo=bar"}},
			have:          "http://127.0.0.1:8080/cb?foo=bar",
			expected:      "http://127.0.0.1:8080/cb?foo=bar",
			expectedMatch: true,
		},
		{
			client:        &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1:8080/cb?foo=bar"}},
			have:          "http://127.0.0.1:8080/cb?baz=bar&foo=bar",
			expectedMatch: false,
		},
		{
			client:        &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1:8080/cb?foo=bar&baz=bar"}},
			have:          "http://127.0.0.1:8080/cb?baz=bar&foo=bar",
			expectedMatch: false,
		},
		{
			client:        &oauth2.DefaultClient{RedirectURIs: []string{"https://www.authelia.com/cb"}},
			have:          "http://127.0.0.1:8080/cb",
			expectedMatch: false,
		},
		{
			client:        &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1:8080/cb"}},
			have:          "https://www.authelia.com/cb",
			expectedMatch: false,
		},
		{
			client:        &oauth2.DefaultClient{RedirectURIs: []string{"web+application://callback"}},
			have:          "web+application://callback",
			expectedMatch: true,
			expected:      "web+application://callback",
		},
		{
			client:        &oauth2.DefaultClient{RedirectURIs: []string{"https://google.com/?foo=bar%20foo+baz"}},
			have:          "https://google.com/?foo=bar%20foo+baz",
			expectedMatch: true,
			expected:      "https://google.com/?foo=bar%20foo+baz",
		},
	}

	for k, c := range []struct {
		client   oauth2.Client
		url      string
		isError  bool
		expected string
	}{
		{
			client:  &oauth2.DefaultClient{RedirectURIs: []string{""}},
			url:     "https://foo.com/cb",
			isError: true,
		},
		{
			client:   &oauth2.DefaultClient{RedirectURIs: []string{"wta://auth"}},
			url:      "wta://auth",
			expected: "wta://auth",
			isError:  false,
		},
		{
			client:   &oauth2.DefaultClient{RedirectURIs: []string{"wta:///auth"}},
			url:      "wta:///auth",
			expected: "wta:///auth",
			isError:  false,
		},
		{
			client:   &oauth2.DefaultClient{RedirectURIs: []string{"wta://foo/auth"}},
			url:      "wta://foo/auth",
			expected: "wta://foo/auth",
			isError:  false,
		},
		{
			client:  &oauth2.DefaultClient{RedirectURIs: []string{"https://bar.com/cb"}},
			url:     "https://foo.com/cb",
			isError: true,
		},
		{
			client:   &oauth2.DefaultClient{RedirectURIs: []string{"https://bar.com/cb"}},
			url:      "",
			isError:  false,
			expected: "https://bar.com/cb",
		},
		{
			client:  &oauth2.DefaultClient{RedirectURIs: []string{""}},
			url:     "",
			isError: true,
		},
		{
			client:   &oauth2.DefaultClient{RedirectURIs: []string{"https://bar.com/cb"}},
			url:      "https://bar.com/cb",
			isError:  false,
			expected: "https://bar.com/cb",
		},
		{
			client:  &oauth2.DefaultClient{RedirectURIs: []string{"https://bar.com/cb"}},
			url:     "https://bar.com/cb123",
			isError: true,
		},
		{
			client:   &oauth2.DefaultClient{RedirectURIs: []string{"http://[::1]"}},
			url:      "http://[::1]:1024",
			expected: "http://[::1]:1024",
			isError:  false,
		},
		{
			client:  &oauth2.DefaultClient{RedirectURIs: []string{"http://[::1]"}},
			url:     "http://[::1]:1024/cb",
			isError: true,
		},
		{
			client:   &oauth2.DefaultClient{RedirectURIs: []string{"http://[::1]/cb"}},
			url:      "http://[::1]:1024/cb",
			expected: "http://[::1]:1024/cb",
			isError:  false,
		},
		{
			client:  &oauth2.DefaultClient{RedirectURIs: []string{"http://[::1]"}},
			url:     "http://foo.bar/bar",
			isError: true,
		},
		{
			client:   &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1"}},
			url:      "http://127.0.0.1:1024",
			expected: "http://127.0.0.1:1024",
			isError:  false,
		},
		{
			client:   &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1/cb"}},
			url:      "http://127.0.0.1:64000/cb",
			expected: "http://127.0.0.1:64000/cb",
			isError:  false,
		},
		{
			client:  &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1"}},
			url:     "http://127.0.0.1:64000/cb",
			isError: true,
		},
		{
			client:   &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1"}},
			url:      "http://127.0.0.1",
			expected: "http://127.0.0.1",
			isError:  false,
		},
		{
			client:   &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1/Cb"}},
			url:      "http://127.0.0.1:8080/Cb",
			expected: "http://127.0.0.1:8080/Cb",
			isError:  false,
		},
		{
			client:  &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1"}},
			url:     "http://foo.bar/bar",
			isError: true,
		},
		{
			client:  &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1"}},
			url:     ":/invalid.uri)bar",
			isError: true,
		},
		{
			client:  &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1:8080/cb"}},
			url:     "http://127.0.0.1:8080/Cb",
			isError: true,
		},
		{
			client:  &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1:8080/cb"}},
			url:     "http://127.0.0.1:8080/cb?foo=bar",
			isError: true,
		},
		{
			client:   &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1:8080/cb?foo=bar"}},
			url:      "http://127.0.0.1:8080/cb?foo=bar",
			expected: "http://127.0.0.1:8080/cb?foo=bar",
			isError:  false,
		},
		{
			client:  &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1:8080/cb?foo=bar"}},
			url:     "http://127.0.0.1:8080/cb?baz=bar&foo=bar",
			isError: true,
		},
		{
			client:  &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1:8080/cb?foo=bar&baz=bar"}},
			url:     "http://127.0.0.1:8080/cb?baz=bar&foo=bar",
			isError: true,
		},
		{
			client:  &oauth2.DefaultClient{RedirectURIs: []string{"https://www.authelia.com/cb"}},
			url:     "http://127.0.0.1:8080/cb",
			isError: true,
		},
		{
			client:  &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1:8080/cb"}},
			url:     "https://www.authelia.com/cb",
			isError: true,
		},
		{
			client:   &oauth2.DefaultClient{RedirectURIs: []string{"web+application://callback"}},
			url:      "web+application://callback",
			isError:  false,
			expected: "web+application://callback",
		},
		{
			client:   &oauth2.DefaultClient{RedirectURIs: []string{"https://google.com/?foo=bar%20foo+baz"}},
			url:      "https://google.com/?foo=bar%20foo+baz",
			isError:  false,
			expected: "https://google.com/?foo=bar%20foo+baz",
		},
	} {
		redir, err := oauth2.MatchRedirectURIWithClientRedirectURIs(c.url, c.client)
		assert.Equal(t, c.isError, err != nil, "%d: %+v", k, c)
		if err == nil {
			require.NotNil(t, redir, "%d", k)
			assert.Equal(t, c.expected, redir.String(), "%d", k)
		}
	}
}

func TestIsRedirectURISecure(t *testing.T) {
	testCases := []struct {
		name        string
		redirectURI *url.URL
		expected    bool
	}{
		{
			"ShouldConsiderHTTPInSecure",
			&url.URL{Scheme: "http", Host: "google.com", Path: "/callback"},
			false,
		},
		{
			"ShouldConsiderHTTPSSecure",
			&url.URL{Scheme: "https", Host: "google.com", Path: "/callback"},
			true,
		},
		{
			"ShouldNotConsiderHTTPWithHostSimilarToLocalHost",
			&url.URL{Scheme: "http", Host: "testlocalhost", Path: "/callback"},
			false,
		},
		{
			"ShouldConsiderLocalHostSecure",
			&url.URL{Scheme: "http", Host: "localhost", Path: "/callback"},
			true,
		},
		{
			"ShouldConsiderLocalHostSubDomainSecure",
			&url.URL{Scheme: "http", Host: "test.localhost", Path: "/callback"},
			true,
		},
		{
			"ShouldConsiderLocalHostIPv4Secure",
			&url.URL{Scheme: "http", Host: "127.0.0.1", Path: "/callback"},
			true,
		},
		{
			"ShouldConsiderLocalHostIPv6Secure",
			&url.URL{Scheme: "http", Host: "[::1]", Path: "/callback"},
			true,
		},
		{
			"ShouldConsiderLocalHostIPv4WithPortSecure",
			&url.URL{Scheme: "http", Host: "127.0.0.1:8080", Path: "/callback"},
			true,
		},
		{
			"ShouldConsiderLocalHostIPv6WithPortSecure",
			&url.URL{Scheme: "http", Host: "[::1]:8080", Path: "/callback"},
			true,
		},
		{
			"ShouldConsiderNativeAppSecure",
			&url.URL{Scheme: "wta", Host: "auth", Path: "/callback"},
			true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, oauth2.IsRedirectURISecure(t.Context(), tc.redirectURI))
		})
	}
}

func TestWriteAuthorizeFormPostResponse(t *testing.T) {
	for d, c := range []struct {
		parameters url.Values
		check      func(code string, state string, customParams url.Values, d int)
	}{
		{
			parameters: url.Values{consts.FormParameterAuthorizationCode: {"lshr755nsg39fgur"}, consts.FormParameterState: {"924659540232"}},
			check: func(code string, state string, customParams url.Values, d int) {
				assert.Equal(t, "lshr755nsg39fgur", code, "case %d", d)
				assert.Equal(t, "924659540232", state, "case %d", d)
			},
		},
		{
			parameters: url.Values{consts.FormParameterAuthorizationCode: {"lshr75*ns-39f+ur"}, consts.FormParameterState: {"9a:* <&)"}},
			check: func(code string, state string, customParams url.Values, d int) {
				assert.Equal(t, "lshr75*ns-39f+ur", code, "case %d", d)
				assert.Equal(t, "9a:* <&)", state, "case %d", d)
			},
		},
		{
			parameters: url.Values{consts.FormParameterAuthorizationCode: {"1234"}, "custom": {"test2", "test3"}},
			check: func(code string, state string, customParams url.Values, d int) {
				assert.Equal(t, "1234", code, "case %d", d)
				assert.Equal(t, []string{"test2", "test3"}, customParams["custom"], "case %d", d)
			},
		},
		{
			parameters: url.Values{consts.FormParameterAuthorizationCode: {"1234"}, "custom": {"<b>Bold</b>"}},
			check: func(code string, state string, customParams url.Values, d int) {
				assert.Equal(t, "1234", code, "case %d", d)
				assert.Equal(t, "<b>Bold</b>", customParams.Get("custom"), "case %d", d)
			},
		},
	} {
		var responseBuffer bytes.Buffer

		redirectURL := "https://localhost:8080/cb"
		oauth2.DefaultFormPostResponseWriter(&responseBuffer, oauth2.DefaultFormPostTemplate, redirectURL, c.parameters)
		code, state, _, _, customParams, _, err := internal.ParseFormPostResponse(redirectURL, io.NopCloser(bytes.NewReader(responseBuffer.Bytes())))
		assert.NoError(t, err, "case %d", d)
		c.check(code, state, customParams, d)
	}
}

func TestIsRedirectURISecureStrict(t *testing.T) {
	for d, c := range []struct {
		u   string
		err bool
	}{
		{u: "http://google.com", err: true},
		{u: "https://google.com", err: false},
		{u: "http://localhost", err: false},
		{u: "http://test.localhost", err: false},
		{u: "http://127.0.0.1/", err: false},
		{u: "http://[::1]/", err: false},
		{u: "http://127.0.0.1:8080/", err: false},
		{u: "http://[::1]:8080/", err: false},
		{u: "http://testlocalhost", err: true},
		{u: "wta://auth", err: true},
	} {
		uu, err := url.Parse(c.u)
		require.NoError(t, err)
		assert.Equal(t, !c.err, oauth2.IsRedirectURISecureStrict(uu), "case %d", d)
	}
}

func ParseURLFragment(fragment string) url.Values {
	r := url.Values{}
	kvs := strings.Split(fragment, "&")
	for _, kv := range kvs {
		kva := strings.Split(kv, "=")
		r.Add(kva[0], kva[1])
	}
	return r
}
