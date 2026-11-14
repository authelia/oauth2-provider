// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/internal/consts"
)

func TestIsMatchingNativeAppLoopbackURI(t *testing.T) {
	testCases := []struct {
		name            string
		uri, registered *url.URL
		expected        bool
	}{
		{
			"ShouldHandleHTTPSRequested",
			MustParseURI(t, "https://127.0.0.1"),
			MustParseURI(t, "http://127.0.0.1"),
			false,
		},
		{
			"ShouldHandleHTTPSRegistered",
			MustParseURI(t, "http://127.0.0.1"),
			MustParseURI(t, "https://127.0.0.1"),
			false,
		},
		{
			"ShouldHandleNonLoopbackRequested",
			MustParseURI(t, "http://google.com"),
			MustParseURI(t, "http://127.0.0.1"),
			false,
		},
		{
			"ShouldHandleNonLoopbackRegistered",
			MustParseURI(t, "http://127.0.0.1"),
			MustParseURI(t, "http://google.com"),
			false,
		},
		{
			"ShouldHandleDifferentLoopbacks",
			MustParseURI(t, "http://127.0.0.1"),
			MustParseURI(t, "http://127.0.0.2"),
			false,
		},
		{
			"ShouldHandleDifferentPaths",
			MustParseURI(t, "http://127.0.0.1/1234"),
			MustParseURI(t, "http://127.0.0.1/abc"),
			false,
		},
		{
			"ShouldHandleDifferentPorts",
			MustParseURI(t, "http://127.0.0.1:1234"),
			MustParseURI(t, "http://127.0.0.1"),
			true,
		},
		{
			"ShouldHandleLocalhostDifferentPorts",
			MustParseURI(t, "http://localhost:1234/cb"),
			MustParseURI(t, "http://localhost/cb"),
			true,
		},
		{
			"ShouldHandleLocalhostSubdomain",
			MustParseURI(t, "http://app.localhost:1234/cb"),
			MustParseURI(t, "http://app.localhost/cb"),
			false,
		},
		{
			"ShouldHandleDifferentFragments",
			MustParseURI(t, "http://127.0.0.1:1234/cb#a"),
			MustParseURI(t, "http://127.0.0.1/cb"),
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, isMatchingLoopbackURI(tc.uri, tc.registered))
		})
	}
}

func TestValidateRedirectURISecurity(t *testing.T) {
	strict := func(_ context.Context, uri *url.URL) bool { return IsRedirectURISecureStrict(uri) }
	permissive := func(_ context.Context, uri *url.URL) bool { return true }

	testCases := []struct {
		name            string
		uri             string
		public          bool
		applicationType string
		allow           bool
		nilClient       bool
		checker         func(context.Context, *url.URL) bool
		err             bool
	}{
		{name: "ShouldAllowHTTPSConfidential", uri: "https://client.example.com/cb"},
		{name: "ShouldAllowHTTPSPublic", uri: "https://client.example.com/cb", public: true},
		{name: "ShouldAllowHTTPSLocalhostConfidential", uri: "https://localhost:8443/cb"},
		{name: "ShouldAllowHTTPSConfidentialWeb", uri: "https://client.example.com/cb", applicationType: consts.ApplicationTypeWeb},
		{name: "ShouldAllowCustomSchemeConfidential", uri: "com.example.app:/cb"},
		{name: "ShouldRejectLoopbackConfidential", uri: "http://127.0.0.1:8080/cb", err: true},
		{name: "ShouldRejectLocalhostConfidential", uri: "http://localhost:8080/cb", err: true},
		{name: "ShouldRejectLocalhostConfidentialWeb", uri: "http://localhost/cb", applicationType: consts.ApplicationTypeWeb, err: true},
		{name: "ShouldRejectLocalhostPublicWeb", uri: "http://localhost/cb", public: true, applicationType: consts.ApplicationTypeWeb, err: true},
		{name: "ShouldRejectLocalhostConfidentialNoApplicationType", uri: "http://localhost/cb", applicationType: "unset", err: true},
		{name: "ShouldRejectLoopbackNilClient", uri: "http://127.0.0.1:8080/cb", nilClient: true, err: true},
		{name: "ShouldAllowLoopbackPublic", uri: "http://127.0.0.1:8080/cb", public: true},
		{name: "ShouldAllowLoopbackConfidentialNative", uri: "http://127.0.0.1:8080/cb", applicationType: consts.ApplicationTypeNative},
		{name: "ShouldAllowIPv6LoopbackPublicNative", uri: "http://[::1]:8080/cb", public: true, applicationType: consts.ApplicationTypeNative},
		{name: "ShouldAllowLocalhostConfidentialNative", uri: "http://localhost:8080/cb", applicationType: consts.ApplicationTypeNative},
		{name: "ShouldRejectHTTPConfidential", uri: "http://client.example.com/cb", err: true},
		{name: "ShouldRejectHTTPPublic", uri: "http://client.example.com/cb", public: true, err: true},
		{name: "ShouldRejectHTTPConfidentialNative", uri: "http://client.example.com/cb", applicationType: consts.ApplicationTypeNative, err: true},
		{name: "ShouldRejectHTTPConfidentialWhenPublicClientsAllowed", uri: "http://client.example.com/cb", allow: true, err: true},
		{name: "ShouldAllowHTTPPublicWhenPublicClientsAllowed", uri: "http://client.example.com/cb", public: true, allow: true},
		{name: "ShouldAllowLocalhostPublicWebWhenPublicClientsAllowed", uri: "http://localhost/cb", public: true, applicationType: consts.ApplicationTypeWeb, allow: true},
		{name: "ShouldRejectCustomSchemeWithStrictChecker", uri: "com.example.app:/cb", public: true, checker: strict, err: true},
		{name: "ShouldAllowCustomSchemeWithStrictCheckerWhenPublicClientsAllowed", uri: "com.example.app:/cb", public: true, allow: true, checker: strict},
		{name: "ShouldAllowLocalhostConfidentialWithStrictChecker", uri: "http://localhost/cb", checker: strict},
		{name: "ShouldAllowLocalhostConfidentialWebWithIsRedirectURISecureChecker", uri: "http://localhost/cb", applicationType: consts.ApplicationTypeWeb, checker: IsRedirectURISecure},
		{name: "ShouldAllowHTTPConfidentialWithPermissiveChecker", uri: "http://client.example.com/cb", checker: permissive},
		{name: "ShouldAllowNoRedirectURI"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{RedirectSecureChecker: tc.checker, AllowInsecureRedirectURIForPublicClients: tc.allow}

			var uri *url.URL

			if tc.uri != "" {
				uri = MustParseURI(t, tc.uri)
			}

			var client Client = &DefaultClient{ID: "client", Public: tc.public}

			switch {
			case tc.nilClient:
				client = nil
			case tc.applicationType == "unset":
				client = &DefaultRegisteredClient{DefaultClient: client.(*DefaultClient)}
			case tc.applicationType != "":
				client = &DefaultRegisteredClient{DefaultClient: client.(*DefaultClient), ApplicationType: tc.applicationType}
			}

			err := ValidateRedirectURISecurity(t.Context(), config, client, uri)

			if tc.err {
				require.ErrorIs(t, err, ErrInvalidRequest)
				assert.Equal(t, "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Redirect URL is using an insecure protocol, http is only allowed for native clients using a loopback redirect URI, for example: http://127.0.0.1:8080/callback.", ErrorToRFC6749Error(err).GetDescription())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestOriginURIComparisonStrategyCompare(t *testing.T) {
	testCases := []struct {
		name       string
		uri        string
		registered string
		expected   bool
	}{
		{name: "ShouldIgnoreThePortOfABareLoopbackOrigin", uri: "http://127.0.0.1:1024/cb", registered: "http://127.0.0.1", expected: true},
		{name: "ShouldIgnoreThePortOfABareIPv6LoopbackOrigin", uri: "http://[::1]:1024", registered: "http://[::1]", expected: true},
		{name: "ShouldCompareThePortOfABareOrigin", uri: "https://example.com:8443/cb", registered: "https://example.com"},
		{name: "ShouldCompareAPathRegistrationExactly", uri: "http://127.0.0.1:1024/cb", registered: "http://127.0.0.1/cb"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, OriginURIComparisonStrategy{}.Compare(&uriPair{uri: MustParseURI(t, tc.uri), registeredURI: MustParseURI(t, tc.registered)}))
		})
	}
}

func MustParseURI(t *testing.T, uri string) *url.URL {
	t.Helper()

	u, err := url.Parse(uri)
	require.NoError(t, err)

	return u
}
