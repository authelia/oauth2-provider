package oauth2_test

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
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
			client:   &oauth2.DefaultClient{RedirectURIs: []string{"http://[::1]"}},
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
			client:   &oauth2.DefaultClient{RedirectURIs: []string{"http://[::1]/cb"}},
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
			client:   &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1"}},
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
			client:   &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1/cb"}},
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
			client:   &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1/Cb"}},
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
			client:   &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"http://[::1]"}}},
			url:      "http://[::1]:1024",
			expected: "http://[::1]:1024",
		},
		{
			name:     "ShouldMatchOnIPv6LoopbackRedirectURIWithPathWhenRegistrationHasNoPathRedirectURIOriginStrategy",
			client:   &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"http://[::1]"}}},
			url:      "http://[::1]:1024/cb",
			expected: "http://[::1]:1024/cb",
		},
		{
			name:     "ShouldReturnMatchOnIPv6LoopbackRedirectURIWithUnregisteredPortAndRegisteredPathRedirectURIOriginStrategy",
			client:   &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"http://[::1]/cb"}}},
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
			client:   &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1"}}},
			url:      "http://127.0.0.1:1024",
			expected: "http://127.0.0.1:1024",
		},
		{
			name:     "ShouldNotErrorOnIPv4LoopbackRedirectURIWithNoRegisteredPathRedirectURIOriginStrategy",
			client:   &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"!@HN#!YUI@#B!@YIH%B!@J#$HK", "http://127.0.0.1"}}},
			url:      "http://127.0.0.1:64000/cb",
			expected: "http://127.0.0.1:64000/cb",
		},
		{
			name:   "ShouldErrorOnIPv4LoopbackRedirectURIWithUnregisteredPathRedirectURIOriginStrategy",
			client: &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1/"}}},
			url:    "http://127.0.0.1:64000/cb",
			error:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value 'http://127.0.0.1:64000/cb'.",
		},
		{
			name:     "ShouldReturnMatchOnIPv4LoopbackRedirectURIWithUnregisteredPortAndRegisteredPathRedirectURIOriginStrategy",
			client:   &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1/cb"}}},
			url:      "http://127.0.0.1:64000/cb",
			expected: "http://127.0.0.1:64000/cb",
		},
		{
			name:     "ShouldReturnMatchOnIPv4LoopbackExactMatchRedirectURIOriginStrategy",
			client:   &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1"}}},
			url:      "http://127.0.0.1",
			expected: "http://127.0.0.1",
		},
		{
			name:     "ShouldReturnMatchOnIPv4LoopbackExactMatchWithPathRedirectURIOriginStrategy",
			client:   &originClient{DefaultClient: &oauth2.DefaultClient{RedirectURIs: []string{"http://127.0.0.1/Cb"}}},
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

func ParseURLFragment(fragment string) url.Values {
	r := url.Values{}

	if fragment == "" {
		return r
	}

	kvs := strings.Split(fragment, "&")
	for _, kv := range kvs {
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
