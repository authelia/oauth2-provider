// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestIsLocalhost(t *testing.T) {
	testCases := []struct {
		name     string
		have     string
		expected bool
	}{
		{
			"ShouldNotMatchFooBar",
			"https://foo.bar",
			false,
		},
		{
			"ShouldMatchLocalHost",
			"https://localhost",
			true,
		},
		{
			"ShouldMatchLocalHostWithPort",
			"https://localhost:1234",
			true,
		},
		{
			"ShouldMatchIPv4Loopback",
			"https://127.0.0.1",
			true,
		},
		{
			"ShouldMatchIPv4LoopbackWithPort",
			"https://127.0.0.1:1234",
			true,
		},
		{
			"ShouldMatchIPv6Loopback",
			"https://[::1]",
			true,
		},
		{
			"ShouldMatchIPv6LoopbackWithPort",
			"https://[::1]:1234",
			true,
		},
		{
			"ShouldMatchLocalHostSubDomain",
			"https://test.localhost",
			true,
		},
		{
			"ShouldMatchLocalHostSubDomainWithPort",
			"https://test.localhost:1234",
			true,
		},
		{
			"ShouldMatchUpperCaseLocalHost",
			"https://LOCALHOST",
			true,
		},
		{
			"ShouldMatchMixedCaseLocalHostSubDomain",
			"https://test.LocalHost",
			true,
		},
		{
			"ShouldMatchFullyQualifiedLocalHost",
			"https://localhost.",
			true,
		},
		{
			"ShouldMatchShorthandIPv4Loopback",
			"https://127.1",
			true,
		},
		{
			"ShouldMatchThreePartIPv4Loopback",
			"https://127.0.1:1234",
			true,
		},
		{
			"ShouldMatchHexadecimalIPv4Loopback",
			"https://0x7f.0.0.1",
			true,
		},
		{
			"ShouldMatchOctalIPv4Loopback",
			"https://0177.0.0.1",
			true,
		},
		{
			"ShouldMatchIntegerIPv4Loopback",
			"https://2130706433",
			true,
		},
		{
			"ShouldMatchFullyQualifiedIPv4Loopback",
			"https://127.0.0.1.",
			true,
		},
		{
			"ShouldNotMatchShorthandNonLoopback",
			"https://128.1",
			false,
		},
		{
			"ShouldNotMatchOutOfRangeIPv4",
			"https://127.256.0.0.1",
			false,
		},
		{
			"ShouldNotMatchNumericLabelDomain",
			"https://127.example.com",
			false,
		},
		{
			"ShouldNotMatchLocalHostPrefix",
			"https://localhost.example.com",
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			u, _ := url.Parse(tc.have)
			assert.Equal(t, tc.expected, oauth2.IsLocalhost(u))
		})
	}
}

func TestClientRedirectURIMatchingStrategies(t *testing.T) {
	testCases := []struct {
		name     string
		client   oauth2.Client
		url      string
		expected string
		error    string
	}{
		{
			name:   "ShouldReturnErrorWhenOnlyRedirectURIIsAnEmptyString",
			client: &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{""}}},
			url:    "https://foo.com/cb",
			error:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value 'https://foo.com/cb'.",
		},
		{
			name:     "ShouldMatchOnlyExactNativeAppRedirectURI",
			client:   &oauth2.DefaultClient{RedirectURIs: []string{"wta://auth"}},
			url:      "wta://auth",
			expected: "wta://auth",
		},
		{
			name:     "ShouldMatchOnExactNativeAppRedirectURIWithOnlyPath",
			client:   &oauth2.DefaultClient{RedirectURIs: []string{"wta:///auth"}},
			url:      "wta:///auth",
			expected: "wta:///auth",
		},
		{
			name:     "ShouldMatchOnExactNativeAppRedirectURIWithHostAndPath",
			client:   &oauth2.DefaultClient{RedirectURIs: []string{"wta://foo/auth"}},
			url:      "wta://foo/auth",
			expected: "wta://foo/auth",
		},
		{
			name:   "ShouldErrorOnNoMatchingRedirectURI",
			client: &oauth2.DefaultClient{RedirectURIs: []string{"https://bar.com/cb"}},
			url:    "https://foo.com/cb",
			error:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value 'https://foo.com/cb'.",
		},
		{
			name:     "ShouldReturnSingleRedirectURIOnEmptyString",
			client:   &oauth2.DefaultClient{RedirectURIs: []string{"https://bar.com/cb"}},
			url:      "",
			expected: "https://bar.com/cb",
		},
		{
			name:   "ShouldErrorOnEmptyStringWhenNoValidRedirectURIs",
			client: &oauth2.DefaultClient{RedirectURIs: []string{""}},
			url:    "",
			error:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value '' because the only registered 'redirect_uri' is not a valid value.",
		},
		{
			name:     "ShouldReturnRedirectURIWhenNormalRedirectURIMatches",
			client:   &oauth2.DefaultClient{RedirectURIs: []string{"https://bar.com/cb"}},
			url:      "https://bar.com/cb",
			expected: "https://bar.com/cb",
		},
		{
			name:   "ShouldErrorOnRedirectNotMatchingPath",
			client: &oauth2.DefaultClient{RedirectURIs: []string{"https://bar.com/cb"}},
			url:    "https://bar.com/cb123",
			error:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value 'https://bar.com/cb123'.",
		},
		{
			name:     "ShouldReturnMatchOnIPv6LoopbackRedirectURIWithUnregisteredPort",
			client:   &oauth2.DefaultClient{Public: true, RedirectURIs: []string{"http://[::1]"}},
			url:      "http://[::1]:1024",
			expected: "http://[::1]:1024",
		},
		{
			name:   "ShouldErrorOnIPv6LoopbackRedirectURIWithUnregisteredPath",
			client: &oauth2.DefaultClient{RedirectURIs: []string{"http://[::1]"}},
			url:    "http://[::1]:1024/cb",
			error:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value 'http://[::1]:1024/cb'.",
		},
		{
			name:     "ShouldReturnMatchOnIPv6LoopbackRedirectURIWithUnregisteredPortAndRegisteredPath",
			client:   &oauth2.DefaultClient{Public: true, RedirectURIs: []string{"http://[::1]/cb"}},
			url:      "http://[::1]:1024/cb",
			expected: "http://[::1]:1024/cb",
		},
		{
			name:   "ShouldErrorOnIPv6LoopbackComparedToNonLoopback",
			client: &oauth2.DefaultClient{RedirectURIs: []string{"http://[::1]"}},
			url:    "http://foo.bar/bar",
			error:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value 'http://foo.bar/bar'.",
		},
		{
			name:     "ShouldReturnMatchOnIPv4LoopbackRedirectURIWithUnregisteredPort",
			client:   &oauth2.DefaultClient{Public: true, RedirectURIs: []string{"http://127.0.0.1"}},
			url:      "http://127.0.0.1:1024",
			expected: "http://127.0.0.1:1024",
		},
		{
			name:   "ShouldErrorOnIPv4LoopbackRedirectURIWithUnregisteredPath",
			client: &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1"}},
			url:    "http://127.0.0.1:64000/cb",
			error:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value 'http://127.0.0.1:64000/cb'.",
		},
		{
			name:     "ShouldReturnMatchOnIPv4LoopbackRedirectURIWithUnregisteredPortAndRegisteredPath",
			client:   &oauth2.DefaultClient{Public: true, RedirectURIs: []string{"http://127.0.0.1/cb"}},
			url:      "http://127.0.0.1:64000/cb",
			expected: "http://127.0.0.1:64000/cb",
		},
		{
			name:     "ShouldReturnMatchOnIPv4LoopbackExactMatch",
			client:   &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1"}},
			url:      "http://127.0.0.1",
			expected: "http://127.0.0.1",
		},
		{
			name:     "ShouldReturnMatchOnIPv4LoopbackExactMatchWithPath",
			client:   &oauth2.DefaultClient{Public: true, RedirectURIs: []string{"http://127.0.0.1/Cb"}},
			url:      "http://127.0.0.1:8080/Cb",
			expected: "http://127.0.0.1:8080/Cb",
		},
		{
			name:   "ShouldErrorOnIPv4LoopbackComparedToNonLoopback",
			client: &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1"}},
			url:    "http://foo.bar/bar",
			error:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value 'http://foo.bar/bar'.",
		},
		{
			name:   "ShouldErrorOnInvalidRedirectURIRequested",
			client: &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1"}},
			url:    ":/invalid.uri)bar",
			error:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value ':/invalid.uri)bar'.",
		},
		{
			name:   "ShouldErrorOnRedirectURIPathCaseMismatch",
			client: &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1:8080/cb"}},
			url:    "http://127.0.0.1:8080/Cb",
			error:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value 'http://127.0.0.1:8080/Cb'.",
		},
		{
			name:   "ShouldErrorOnRedirectURIQueryMismatch",
			client: &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1:8080/cb"}},
			url:    "http://127.0.0.1:8080/cb?foo=bar",
			error:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value 'http://127.0.0.1:8080/cb?foo=bar'.",
		},
		{
			name:     "ShouldMatchEqualQuery",
			client:   &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1:8080/cb?foo=bar"}},
			url:      "http://127.0.0.1:8080/cb?foo=bar",
			expected: "http://127.0.0.1:8080/cb?foo=bar",
		},
		{
			name:   "ShouldErrorOnQueryPartialMismatch",
			client: &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1:8080/cb?foo=bar"}},
			url:    "http://127.0.0.1:8080/cb?baz=bar&foo=bar",
			error:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value 'http://127.0.0.1:8080/cb?baz=bar&foo=bar'.",
		},
		{
			name:   "ShouldErrorOnQueryOrderMismatch",
			client: &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1:8080/cb?foo=bar&baz=bar"}},
			url:    "http://127.0.0.1:8080/cb?baz=bar&foo=bar",
			error:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value 'http://127.0.0.1:8080/cb?baz=bar&foo=bar'.",
		},
		{
			name:   "ShouldErrorOnNonLoopbackComparedToIPv4Loopback",
			client: &oauth2.DefaultClient{RedirectURIs: []string{"https://www.authelia.com/cb"}},
			url:    "http://127.0.0.1:8080/cb",
			error:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value 'http://127.0.0.1:8080/cb'.",
		},
		{
			name:     "ShouldMatchNativeAppCustomCallback",
			client:   &oauth2.DefaultClient{RedirectURIs: []string{"web+application://callback"}},
			url:      "web+application://callback",
			expected: "web+application://callback",
		},
		{
			name:     "ShouldMatchExactQuery",
			client:   &oauth2.DefaultClient{RedirectURIs: []string{"https://google.com/?foo=bar%20foo+baz"}},
			url:      "https://google.com/?foo=bar%20foo+baz",
			expected: "https://google.com/?foo=bar%20foo+baz",
		},
		{
			name:   "ShouldReturnErrorWhenOnlyRedirectURIIsAnEmptyStringRedirectURIOriginStrategy",
			client: &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{""}}},
			url:    "https://foo.com/cb",
			error:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value 'https://foo.com/cb'.",
		},
		{
			name:     "ShouldMatchOnlyExactNativeAppRedirectURIRedirectURIOriginStrategy",
			client:   &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"wta://auth"}}},
			url:      "wta://auth",
			expected: "wta://auth",
		},
		{
			name:     "ShouldMatchOnExactNativeAppRedirectURIWithOnlyPathRedirectURIOriginStrategy",
			client:   &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"wta:///auth"}}},
			url:      "wta:///auth",
			expected: "wta:///auth",
		},
		{
			name:     "ShouldMatchOnExactNativeAppRedirectURIWithHostAndPathRedirectURIOriginStrategy",
			client:   &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"wta://foo/auth"}}},
			url:      "wta://foo/auth",
			expected: "wta://foo/auth",
		},
		{
			name:   "ShouldErrorOnNoMatchingRedirectURIRedirectURIOriginStrategy",
			client: &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"https://bar.com/cb"}}},
			url:    "https://foo.com/cb",
			error:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value 'https://foo.com/cb'.",
		},
		{
			name:     "ShouldReturnSingleRedirectURIOnEmptyStringRedirectURIOriginStrategy",
			client:   &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"https://bar.com/cb"}}},
			url:      "",
			expected: "https://bar.com/cb",
		},
		{
			name:   "ShouldErrorOnEmptyStringWhenNoValidRedirectURIsRedirectURIOriginStrategy",
			client: &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{""}}},
			url:    "",
			error:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value '' because the only registered 'redirect_uri' is not a valid value.",
		},
		{
			name:     "ShouldReturnRedirectURIWhenNormalRedirectURIMatchesRedirectURIOriginStrategy",
			client:   &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"https://bar.com/cb"}}},
			url:      "https://bar.com/cb",
			expected: "https://bar.com/cb",
		},
		{
			name:   "ShouldErrorOnRedirectNotMatchingPathRedirectURIOriginStrategy",
			client: &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"https://bar.com/cb"}}},
			url:    "https://bar.com/cb123",
			error:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value 'https://bar.com/cb123'.",
		},
		{
			name:     "ShouldReturnMatchOnIPv6LoopbackRedirectURIWithUnregisteredPortRedirectURIOriginStrategy",
			client:   &originClient{DefaultClient: &oauth2.DefaultClient{Public: true, RedirectURIs: []string{"http://[::1]"}}},
			url:      "http://[::1]:1024",
			expected: "http://[::1]:1024",
		},
		{
			name:   "ShouldErrorOnConfidentialClientIPv6LoopbackRedirectURIWithUnregisteredPortRedirectURIOriginStrategy",
			client: &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"http://[::1]"}}},
			url:    "http://[::1]:1024",
			error:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value 'http://[::1]:1024'.",
		},
		{
			name:     "ShouldMatchOnIPv6LoopbackRedirectURIWithPathWhenRegistrationHasNoPathRedirectURIOriginStrategy",
			client:   &originClient{DefaultClient: &oauth2.DefaultClient{Public: true, RedirectURIs: []string{"http://[::1]"}}},
			url:      "http://[::1]:1024/cb",
			expected: "http://[::1]:1024/cb",
		},
		{
			name:   "ShouldErrorOnConfidentialClientIPv6LoopbackRedirectURIWithPathWhenRegistrationHasNoPathRedirectURIOriginStrategy",
			client: &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"http://[::1]"}}},
			url:    "http://[::1]:1024/cb",
			error:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value 'http://[::1]:1024/cb'.",
		},
		{
			name:     "ShouldReturnMatchOnIPv6LoopbackRedirectURIWithUnregisteredPortAndRegisteredPathRedirectURIOriginStrategy",
			client:   &originClient{DefaultClient: &oauth2.DefaultClient{Public: true, RedirectURIs: []string{"http://[::1]/cb"}}},
			url:      "http://[::1]:1024/cb",
			expected: "http://[::1]:1024/cb",
		},
		{
			name:   "ShouldErrorOnIPv6LoopbackComparedToNonLoopbackRedirectURIOriginStrategy",
			client: &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"http://[::1]"}}},
			url:    "http://foo.bar/bar",
			error:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value 'http://foo.bar/bar'.",
		},
		{
			name:     "ShouldReturnMatchOnIPv4LoopbackRedirectURIWithUnregisteredPortRedirectURIOriginStrategy",
			client:   &originClient{DefaultClient: &oauth2.DefaultClient{Public: true, RedirectURIs: []string{"http://127.0.0.1"}}},
			url:      "http://127.0.0.1:1024",
			expected: "http://127.0.0.1:1024",
		},
		{
			name:   "ShouldErrorOnConfidentialClientIPv4LoopbackRedirectURIWithUnregisteredPortRedirectURIOriginStrategy",
			client: &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1"}}},
			url:    "http://127.0.0.1:1024",
			error:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value 'http://127.0.0.1:1024'.",
		},
		{
			name:     "ShouldNotErrorOnIPv4LoopbackRedirectURIWithNoRegisteredPathRedirectURIOriginStrategy",
			client:   &originClient{DefaultClient: &oauth2.DefaultClient{Public: true, RedirectURIs: []string{"!@HN#!YUI@#B!@YIH%B!@J#$HK", "http://127.0.0.1"}}},
			url:      "http://127.0.0.1:64000/cb",
			expected: "http://127.0.0.1:64000/cb",
		},
		{
			name:   "ShouldErrorOnConfidentialClientIPv4LoopbackRedirectURIWithNoRegisteredPathRedirectURIOriginStrategy",
			client: &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"!@HN#!YUI@#B!@YIH%B!@J#$HK", "http://127.0.0.1"}}},
			url:    "http://127.0.0.1:64000/cb",
			error:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value 'http://127.0.0.1:64000/cb'.",
		},
		{
			name:   "ShouldErrorOnIPv4LoopbackRedirectURIWithUnregisteredPathRedirectURIOriginStrategy",
			client: &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1/"}}},
			url:    "http://127.0.0.1:64000/cb",
			error:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value 'http://127.0.0.1:64000/cb'.",
		},
		{
			name:     "ShouldReturnMatchOnIPv4LoopbackRedirectURIWithUnregisteredPortAndRegisteredPathRedirectURIOriginStrategy",
			client:   &originClient{DefaultClient: &oauth2.DefaultClient{Public: true, RedirectURIs: []string{"http://127.0.0.1/cb"}}},
			url:      "http://127.0.0.1:64000/cb",
			expected: "http://127.0.0.1:64000/cb",
		},
		{
			name:     "ShouldReturnMatchOnConfidentialClientIPv4LoopbackRedirectURIWithRegisteredPortRedirectURIOriginStrategy",
			client:   &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1:1024"}}},
			url:      "http://127.0.0.1:1024/cb",
			expected: "http://127.0.0.1:1024/cb",
		},
		{
			name:     "ShouldReturnMatchOnIPv4LoopbackExactMatchRedirectURIOriginStrategy",
			client:   &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1"}}},
			url:      "http://127.0.0.1",
			expected: "http://127.0.0.1",
		},
		{
			name:     "ShouldReturnMatchOnIPv4LoopbackExactMatchWithPathRedirectURIOriginStrategy",
			client:   &originClient{DefaultClient: &oauth2.DefaultClient{Public: true, RedirectURIs: []string{"http://127.0.0.1/Cb"}}},
			url:      "http://127.0.0.1:8080/Cb",
			expected: "http://127.0.0.1:8080/Cb",
		},
		{
			name:   "ShouldErrorOnIPv4LoopbackComparedToNonLoopbackRedirectURIOriginStrategy",
			client: &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1"}}},
			url:    "http://foo.bar/bar",
			error:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value 'http://foo.bar/bar'.",
		},
		{
			name:   "ShouldErrorOnInvalidRedirectURIRequestedRedirectURIOriginStrategy",
			client: &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1"}}},
			url:    ":/invalid.uri)bar",
			error:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value ':/invalid.uri)bar'.",
		},
		{
			name:   "ShouldErrorOnRedirectURIPathCaseMismatchRedirectURIOriginStrategy",
			client: &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1:8080/cb"}}},
			url:    "http://127.0.0.1:8080/Cb",
			error:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value 'http://127.0.0.1:8080/Cb'.",
		},
		{
			name:   "ShouldErrorOnRedirectURIQueryMismatchRedirectURIOriginStrategy",
			client: &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1:8080/cb"}}},
			url:    "http://127.0.0.1:8080/cb?foo=bar",
			error:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value 'http://127.0.0.1:8080/cb?foo=bar'.",
		},
		{
			name:     "ShouldMatchEqualQueryRedirectURIOriginStrategy",
			client:   &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1:8080/cb?foo=bar"}}},
			url:      "http://127.0.0.1:8080/cb?foo=bar",
			expected: "http://127.0.0.1:8080/cb?foo=bar",
		},
		{
			name:   "ShouldErrorOnQueryPartialMismatchRedirectURIOriginStrategy",
			client: &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1:8080/cb?foo=bar"}}},
			url:    "http://127.0.0.1:8080/cb?baz=bar&foo=bar",
			error:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value 'http://127.0.0.1:8080/cb?baz=bar&foo=bar'.",
		},
		{
			name:   "ShouldErrorOnQueryOrderMismatchRedirectURIOriginStrategy",
			client: &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1:8080/cb?foo=bar&baz=bar"}}},
			url:    "http://127.0.0.1:8080/cb?baz=bar&foo=bar",
			error:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value 'http://127.0.0.1:8080/cb?baz=bar&foo=bar'.",
		},
		{
			name:   "ShouldErrorOnNonLoopbackComparedToIPv4LoopbackRedirectURIOriginStrategy",
			client: &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"https://www.authelia.com/cb"}}},
			url:    "http://127.0.0.1:8080/cb",
			error:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value 'http://127.0.0.1:8080/cb'.",
		},
		{
			name:     "ShouldMatchNativeAppCustomCallbackRedirectURIOriginStrategy",
			client:   &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"web+application://callback"}}},
			url:      "web+application://callback",
			expected: "web+application://callback",
		},
		{
			name:     "ShouldMatchExactQueryRedirectURIOriginStrategy",
			client:   &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"https://google.com/?foo=bar%20foo+baz"}}},
			url:      "https://google.com/?foo=bar%20foo+baz",
			expected: "https://google.com/?foo=bar%20foo+baz",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			uri, err := oauth2.MatchRedirectURIWithClientRedirectURIs(tc.url, tc.client)

			if tc.error != "" {
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.error)
			} else {
				assert.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				require.NotNil(t, uri)
				assert.Equal(t, tc.expected, uri.String())
			}
		})
	}
}

func TestMatchRedirectURIWithClientRedirectURIsNativeAppLoopback(t *testing.T) {
	// RFC 8252 Section 7.3 and RFC 9700 Section 2.1.
	testCases := []struct {
		name            string
		public          bool
		declared        bool
		applicationType string
		registered      string
		requested       string
		match           bool
	}{
		{name: "ShouldMatchPublicIPv4LoopbackAnyPort", public: true, registered: "http://127.0.0.1/cb", requested: "http://127.0.0.1:51004/cb", match: true},
		{name: "ShouldMatchPublicIPv6LoopbackAnyPort", public: true, registered: "http://[::1]/cb", requested: "http://[::1]:51004/cb", match: true},
		{name: "ShouldMatchPublicLocalhostAnyPort", public: true, registered: "http://localhost/cb", requested: "http://localhost:51004/cb", match: true},
		{name: "ShouldMatchPublicLocalhostRegisteredPortDifferentPort", public: true, registered: "http://localhost:8080/cb", requested: "http://localhost:51004/cb", match: true},
		{name: "ShouldMatchPublicLocalhostRegisteredPortNoPort", public: true, registered: "http://localhost:8080/cb", requested: "http://localhost/cb", match: true},
		{name: "ShouldMatchPublicLocalhostWithQuery", public: true, registered: "http://localhost/cb?a=b", requested: "http://localhost:51004/cb?a=b", match: true},
		{name: "ShouldNotMatchConfidentialIPv4LoopbackAnyPort", registered: "http://127.0.0.1/cb", requested: "http://127.0.0.1:51004/cb"},
		{name: "ShouldNotMatchConfidentialIPv6LoopbackAnyPort", registered: "http://[::1]/cb", requested: "http://[::1]:51004/cb"},
		{name: "ShouldNotMatchConfidentialLocalhostAnyPort", registered: "http://localhost/cb", requested: "http://localhost:51004/cb"},
		{name: "ShouldMatchConfidentialLocalhostExact", registered: "http://localhost:51004/cb", requested: "http://localhost:51004/cb", match: true},
		{name: "ShouldNotMatchPublicIPv4LoopbackDifferentPath", public: true, registered: "http://127.0.0.1/cb", requested: "http://127.0.0.1:51004/other"},
		{name: "ShouldNotMatchPublicIPv6LoopbackDifferentPath", public: true, registered: "http://[::1]/cb", requested: "http://[::1]:51004/cb/"},
		{name: "ShouldNotMatchPublicLocalhostDifferentPath", public: true, registered: "http://localhost/cb", requested: "http://localhost:51004/Cb"},
		{name: "ShouldNotMatchPublicIPv4LoopbackEscapedPath", public: true, registered: "http://127.0.0.1/cb", requested: "http://127.0.0.1:51004/c%62"},
		{name: "ShouldNotMatchPublicLocalhostDifferentQuery", public: true, registered: "http://localhost/cb?a=b", requested: "http://localhost:51004/cb?a=c"},
		{name: "ShouldNotMatchPublicLocalhostAddedQuery", public: true, registered: "http://localhost/cb", requested: "http://localhost:51004/cb?a=b"},
		{name: "ShouldNotMatchPublicIPv4LoopbackAddedUserInfo", public: true, registered: "http://127.0.0.1/cb", requested: "http://user@127.0.0.1:51004/cb"},
		{name: "ShouldNotMatchPublicLocalhostHTTPS", public: true, registered: "https://localhost/cb", requested: "https://localhost:51004/cb"},
		{name: "ShouldNotMatchPublicLocalhostSubdomain", public: true, registered: "http://app.localhost/cb", requested: "http://app.localhost:51004/cb"},
		{name: "ShouldNotMatchPublicLocalhostAgainstIPv4Loopback", public: true, registered: "http://localhost/cb", requested: "http://127.0.0.1:51004/cb"},
		{name: "ShouldMatchConfidentialNativeIPv4LoopbackAnyPort", applicationType: consts.ApplicationTypeNative, registered: "http://127.0.0.1/cb", requested: "http://127.0.0.1:51004/cb", match: true},
		{name: "ShouldMatchConfidentialNativeIPv6LoopbackAnyPort", applicationType: consts.ApplicationTypeNative, registered: "http://[::1]/cb", requested: "http://[::1]:51004/cb", match: true},
		{name: "ShouldMatchConfidentialNativeLocalhostAnyPort", applicationType: consts.ApplicationTypeNative, registered: "http://localhost/cb", requested: "http://localhost:51004/cb", match: true},
		{name: "ShouldNotMatchConfidentialNativeLoopbackDifferentPath", applicationType: consts.ApplicationTypeNative, registered: "http://127.0.0.1/cb", requested: "http://127.0.0.1:51004/other"},
		{name: "ShouldNotMatchConfidentialNativeLocalhostHTTPS", applicationType: consts.ApplicationTypeNative, registered: "https://localhost/cb", requested: "https://localhost:51004/cb"},
		{name: "ShouldNotMatchConfidentialWebLoopbackAnyPort", applicationType: consts.ApplicationTypeWeb, registered: "http://127.0.0.1/cb", requested: "http://127.0.0.1:51004/cb"},
		{name: "ShouldNotMatchPublicWebLoopbackAnyPort", public: true, applicationType: consts.ApplicationTypeWeb, registered: "http://127.0.0.1/cb", requested: "http://127.0.0.1:51004/cb"},
		{name: "ShouldNotMatchPublicDefaultWebLoopbackAnyPort", public: true, declared: true, registered: "http://127.0.0.1/cb", requested: "http://127.0.0.1:51004/cb"},
		{name: "ShouldMatchPublicNativeLoopbackAnyPort", public: true, applicationType: consts.ApplicationTypeNative, registered: "http://127.0.0.1/cb", requested: "http://127.0.0.1:51004/cb", match: true},
		{name: "ShouldMatchPublicWebLoopbackExact", public: true, applicationType: consts.ApplicationTypeWeb, registered: "http://127.0.0.1:51004/cb", requested: "http://127.0.0.1:51004/cb", match: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var client oauth2.Client = &oauth2.DefaultClient{Public: tc.public, RedirectURIs: []string{tc.registered}}

			if tc.declared || tc.applicationType != "" {
				client = &oauth2.DefaultRegisteredClient{DefaultClient: client.(*oauth2.DefaultClient), ApplicationType: tc.applicationType}
			}

			uri, err := oauth2.MatchRedirectURIWithClientRedirectURIs(tc.requested, client)

			if tc.match {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
				assert.Equal(t, tc.requested, uri.String())
			} else {
				assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
			}
		})
	}
}

func TestIsNativeClient(t *testing.T) {
	testCases := []struct {
		name     string
		client   oauth2.Client
		expected bool
	}{
		{"ShouldBeNative", &oauth2.DefaultRegisteredClient{DefaultClient: &oauth2.DefaultClient{}, ApplicationType: consts.ApplicationTypeNative}, true},
		{"ShouldNotBeNativeForWeb", &oauth2.DefaultRegisteredClient{DefaultClient: &oauth2.DefaultClient{}, ApplicationType: consts.ApplicationTypeWeb}, false},
		{"ShouldNotBeNativeByDefault", &oauth2.DefaultRegisteredClient{DefaultClient: &oauth2.DefaultClient{}}, false},
		{"ShouldNotBeNativeWithoutAnApplicationType", &oauth2.DefaultClient{}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, oauth2.IsNativeClient(tc.client))
		})
	}
}

func TestIsMatchingRedirectURIShouldNotApplyLoopbackPortExemption(t *testing.T) {
	_, ok := oauth2.IsMatchingRedirectURI("http://127.0.0.1:51004/cb", []string{"http://127.0.0.1/cb"}, &oauth2.BestPracticeURIComparisonStrategy{})

	assert.False(t, ok)
}

func TestIsRedirectURISecure(t *testing.T) {
	testCases := []struct {
		name     string
		url      string
		expected bool
	}{
		{
			"ShouldReturnFalseHTTPScheme",
			"http://google.com",
			false,
		},
		{
			"ShouldReturnTrueHTTPSScheme",
			"https://google.com",
			true,
		},
		{
			"ShouldReturnTrueLocalHostHTTPScheme",
			"http://localhost",
			true,
		},
		{
			"ShouldReturnTrueLocalHostSubDomainHTTPScheme",
			"http://test.localhost",
			true,
		},
		{
			"ShouldReturnTrueIPv4Loopback",
			"http://127.0.0.1",
			true,
		},
		{
			"ShouldReturnTrueIPv4LoopbackWithPort",
			"http://127.0.0.1:1234",
			true,
		},
		{
			"ShouldReturnTrueIPv6Loopback",
			"http://[::1]",
			true,
		},
		{
			"ShouldReturnTrueIPv6LoopbackWithPort",
			"http://[::1]:1234",
			true,
		},
		{
			"ShouldReturnFalseNotActuallyLocalHost",
			"http://testlocalhost",
			false,
		},
		{
			"ShouldReturnTrueNativeApp",
			"wta://auth",
			true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			uri, err := url.Parse(tc.url)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, oauth2.IsRedirectURISecure(context.Background(), uri))
		})
	}
}

func TestIsRedirectURISecureStrict(t *testing.T) {
	testCases := []struct {
		name     string
		url      string
		expected bool
	}{
		{
			"ShouldFailHTTP",
			"http://google.com",
			false,
		},
		{
			"ShouldPassHTTPS",
			"https://google.com",
			true,
		},
		{
			"ShouldPassLocalHost",
			"http://localhost",
			true,
		},
		{
			"ShouldPassLocalHostSubDomain",
			"http://test.localhost",
			true,
		},
		{
			"ShouldPassIPv4Loopback",
			"http://127.0.0.1/",
			true,
		},
		{
			"ShouldPassIPv4LoopbackWithPort",
			"http://127.0.0.1:8080/",
			true,
		},
		{
			"ShouldPassIPv6Loopback",
			"http://[::1]/",
			true,
		},
		{
			"ShouldPassIPv6LoopbackWithPort",
			"http://[::1]:8080/",
			true,
		},
		{
			"ShouldFailNotActuallyLocalHost",
			"http://testlocalhost",
			false,
		},
		{
			"ShouldFailNativeApp",
			"wta://auth",
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			uri, err := url.Parse(tc.url)
			require.NoError(t, err)

			assert.Equal(t, tc.expected, oauth2.IsRedirectURISecureStrict(uri))
		})
	}
}

func TestIsPublicClientIdentityAssured(t *testing.T) {
	testCases := []struct {
		name     string
		url      string
		expected bool
	}{
		{"ShouldPassHTTPS", "https://app.example.com/callback", true},
		{"ShouldFailHTTP", "http://app.example.com/callback", false},
		{"ShouldFailLocalHost", "http://localhost:8080/callback", false},
		{"ShouldFailIPv4Loopback", "http://127.0.0.1:8080/callback", false},
		{"ShouldFailIPv6Loopback", "http://[::1]:8080/callback", false},
		{"ShouldFailHTTPSLocalHost", "https://localhost:8443/callback", false},
		{"ShouldFailHTTPSLocalHostSubDomain", "https://app.localhost/callback", false},
		{"ShouldFailHTTPSIPv4Loopback", "https://127.0.0.1:8443/callback", false},
		{"ShouldFailHTTPSIPv6Loopback", "https://[::1]:8443/callback", false},
		{"ShouldFailHTTPSUpperCaseLocalHost", "https://LOCALHOST:8443/callback", false},
		{"ShouldFailHTTPSShorthandIPv4Loopback", "https://127.1:8443/callback", false},
		{"ShouldFailPrivateUseScheme", "com.example.app:/callback", false},
		{"ShouldFailNoRedirectURI", "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			request := oauth2.NewAuthorizeRequest()

			if tc.url != "" {
				uri, err := url.Parse(tc.url)
				require.NoError(t, err)

				request.RedirectURI = uri
			}

			assert.Equal(t, tc.expected, oauth2.IsPublicClientIdentityAssured(t.Context(), request))

			config := &oauth2.Config{}

			assert.Equal(t, tc.expected, config.GetPublicClientIdentityChecker(t.Context())(t.Context(), request))
		})
	}
}

func ParseURLFragment(fragment string) url.Values {
	r := url.Values{}

	if fragment == "" {
		return r
	}

	kvs := strings.SplitSeq(fragment, "&")

	for kv := range kvs {
		kva := strings.Split(kv, "=")

		if len(kva) != 2 {
			continue
		}

		r.Add(kva[0], kva[1])
	}

	return r
}

type originClient struct {
	*oauth2.DefaultClient
}

func (c *originClient) GetRedirectURIComparisonStrategy() oauth2.URIComparisonStrategy {
	return &oauth2.OriginURIComparisonStrategy{}
}
