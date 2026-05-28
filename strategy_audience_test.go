// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/internal/consts"
)

func TestDefaultAudienceMatchingStrategy(t *testing.T) {
	const debugPrefix = "The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. "

	testCases := []struct {
		name     string
		haystack []string
		needle   []string
		expected string
	}{
		{
			name:     "ShouldPassEmptyHaystackAndNeedle",
			haystack: []string{},
			needle:   []string{},
		},
		{
			name:     "ShouldPassEmptyNeedle",
			haystack: []string{"http://foo/bar"},
			needle:   []string{},
		},
		{
			name:     "ShouldFailEmptyHaystack",
			haystack: []string{},
			needle:   []string{"http://foo/bar"},
			expected: debugPrefix + "Requested audience 'http://foo/bar' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldPassExactURL",
			haystack: []string{"https://cloud.authelia.com/api/users"},
			needle:   []string{"https://cloud.authelia.com/api/users"},
		},
		{
			name:     "ShouldFailNeedleHasTrailingSlash",
			haystack: []string{"https://cloud.authelia.com/api/users"},
			needle:   []string{"https://cloud.authelia.com/api/users/"},
			expected: debugPrefix + "Requested audience 'https://cloud.authelia.com/api/users/' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldFailHaystackHasTrailingSlash",
			haystack: []string{"https://cloud.authelia.com/api/users/"},
			needle:   []string{"https://cloud.authelia.com/api/users"},
			expected: debugPrefix + "Requested audience 'https://cloud.authelia.com/api/users' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldFailNeedleIsSubpathBecauseExactMatchOnly",
			haystack: []string{"https://cloud.authelia.com/api/users"},
			needle:   []string{"https://cloud.authelia.com/api/users/1234"},
			expected: debugPrefix + "Requested audience 'https://cloud.authelia.com/api/users/1234' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldFailWhenPathHasExtraSuffix",
			haystack: []string{"https://cloud.authelia.com/api/users"},
			needle:   []string{"https://cloud.authelia.com/api/users1234"},
			expected: debugPrefix + "Requested audience 'https://cloud.authelia.com/api/users1234' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldFailWhenSchemeMismatches",
			haystack: []string{"https://cloud.authelia.com/api/users"},
			needle:   []string{"http://cloud.authelia.com/api/users"},
			expected: debugPrefix + "Requested audience 'http://cloud.authelia.com/api/users' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldFailWhenPortMismatches",
			haystack: []string{"https://cloud.authelia.com/api/users"},
			needle:   []string{"https://cloud.authelia.com:8000/api/users"},
			expected: debugPrefix + "Requested audience 'https://cloud.authelia.com:8000/api/users' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldFailWhenHostMismatches",
			haystack: []string{"https://cloud.authelia.com/api/users"},
			needle:   []string{"https://cloud.ory.xyz/api/users"},
			expected: debugPrefix + "Requested audience 'https://cloud.ory.xyz/api/users' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldPassNonURIExactMatch",
			haystack: []string{"foobar"},
			needle:   []string{"foobar"},
		},
		{
			name:     "ShouldPassNonURIWithSpaceExactMatch",
			haystack: []string{"foo bar"},
			needle:   []string{"foo bar"},
		},
		{
			name:     "ShouldPassNeedleSubsetOfHaystack",
			haystack: []string{"zoo", "bar"},
			needle:   []string{"zoo"},
		},
		{
			name:     "ShouldFailNeedleNotInHaystack",
			haystack: []string{"zoo"},
			needle:   []string{"zoo", "bar"},
			expected: debugPrefix + "Requested audience 'bar' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldFailNonURITrailingSlashNeedle",
			haystack: []string{"foobar"},
			needle:   []string{"foobar/"},
			expected: debugPrefix + "Requested audience 'foobar/' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldFailNonURITrailingSlashHaystack",
			haystack: []string{"foobar/"},
			needle:   []string{"foobar"},
			expected: debugPrefix + "Requested audience 'foobar' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldPassLogicalNameLikeUUID",
			haystack: []string{"7c4b39f4-9c5b-4e6d-9b34-5a3f6e6c3f0b"},
			needle:   []string{"7c4b39f4-9c5b-4e6d-9b34-5a3f6e6c3f0b"},
		},
		{
			name:     "ShouldPassUnparseableNeedleWhenExactlyInHaystack",
			haystack: []string{"\x7f"},
			needle:   []string{"\x7f"},
		},
		{
			name:     "ShouldFailUnparseableNeedleMissingFromHaystack",
			haystack: []string{"https://example.com/api"},
			needle:   []string{"\x7f"},
			expected: debugPrefix + "Requested audience '\x7f' has not been whitelisted by the OAuth 2.0 Client.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := DefaultAudienceStrategy(tc.haystack, tc.needle)

			if tc.expected != "" {
				assert.EqualError(t, ErrorToDebugRFC6749Error(actual), tc.expected)

				return
			}

			require.NoError(t, ErrorToDebugRFC6749Error(actual))
		})
	}
}

func TestExactAudienceMatchingStrategy(t *testing.T) {
	testCases := []struct {
		name     string
		haystack []string
		needle   []string
		expected string
	}{
		{
			name:     "ShouldPassEmptyHaystackAndNeedle",
			haystack: []string{},
			needle:   []string{},
		},
		{
			name:     "ShouldPassEmptyNeedle",
			haystack: []string{"http://foo/bar"},
			needle:   []string{},
		},
		{
			name:     "ShouldFailEmptyHaystack",
			haystack: []string{},
			needle:   []string{"http://foo/bar"},
			expected: `The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. Requested audience 'http://foo/bar' has not been whitelisted by the OAuth 2.0 Client.`,
		},
		{
			name:     "ShouldPassExactURL",
			haystack: []string{"https://cloud.authelia.com/api/users"},
			needle:   []string{"https://cloud.authelia.com/api/users"},
		},
		{
			name:     "ShouldFailNeedleHasTrailingSlash",
			haystack: []string{"https://cloud.authelia.com/api/users"},
			needle:   []string{"https://cloud.authelia.com/api/users/"},
			expected: `The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. Requested audience 'https://cloud.authelia.com/api/users/' has not been whitelisted by the OAuth 2.0 Client.`,
		},
		{
			name:     "ShouldPassBothHaveTrailingSlash",
			haystack: []string{"https://cloud.authelia.com/api/users/"},
			needle:   []string{"https://cloud.authelia.com/api/users/"},
		},
		{
			name:     "ShouldFailHaystackHasTrailingSlash",
			haystack: []string{"https://cloud.authelia.com/api/users/"},
			needle:   []string{"https://cloud.authelia.com/api/users"},
			expected: `The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. Requested audience 'https://cloud.authelia.com/api/users' has not been whitelisted by the OAuth 2.0 Client.`,
		},
		{
			name:     "ShouldFailNeedleIsSubpath",
			haystack: []string{"https://cloud.authelia.com/api/users"},
			needle:   []string{"https://cloud.authelia.com/api/users/1234"},
			expected: `The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. Requested audience 'https://cloud.authelia.com/api/users/1234' has not been whitelisted by the OAuth 2.0 Client.`,
		},
		{
			name:     "ShouldFailMultipleNeedlesOnePartialMatch",
			haystack: []string{"https://cloud.authelia.com/api/users"},
			needle:   []string{"https://cloud.authelia.com/api/users", "https://cloud.authelia.com/api/users/", "https://cloud.authelia.com/api/users/1234"},
			expected: `The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. Requested audience 'https://cloud.authelia.com/api/users/' has not been whitelisted by the OAuth 2.0 Client.`,
		},
		{
			name:     "ShouldFailMultipleNeedlesAcrossHaystacks",
			haystack: []string{"https://cloud.authelia.com/api/users", "https://cloud.authelia.com/api/tenants"},
			needle:   []string{"https://cloud.authelia.com/api/users", "https://cloud.authelia.com/api/users/", "https://cloud.authelia.com/api/users/1234", "https://cloud.authelia.com/api/tenants"},
			expected: `The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. Requested audience 'https://cloud.authelia.com/api/users/' has not been whitelisted by the OAuth 2.0 Client.`,
		},
		{
			name:     "ShouldFailWhenPathHasExtraSuffix",
			haystack: []string{"https://cloud.authelia.com/api/users"},
			needle:   []string{"https://cloud.authelia.com/api/users1234"},
			expected: `The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. Requested audience 'https://cloud.authelia.com/api/users1234' has not been whitelisted by the OAuth 2.0 Client.`,
		},
		{
			name:     "ShouldFailWhenSchemeMismatches",
			haystack: []string{"https://cloud.authelia.com/api/users"},
			needle:   []string{"http://cloud.authelia.com/api/users"},
			expected: `The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. Requested audience 'http://cloud.authelia.com/api/users' has not been whitelisted by the OAuth 2.0 Client.`,
		},
		{
			name:     "ShouldPassNonURIExactMatch",
			haystack: []string{"foobar"},
			needle:   []string{"foobar"},
		},
		{
			name:     "ShouldPassNonURIWithSpaceExactMatch",
			haystack: []string{"foo bar"},
			needle:   []string{"foo bar"},
		},
		{
			name:     "ShouldPassNeedleSubsetOfHaystack",
			haystack: []string{"zoo", "bar"},
			needle:   []string{"zoo"},
		},
		{
			name:     "ShouldFailNeedleNotInHaystack",
			haystack: []string{"zoo"},
			needle:   []string{"zoo", "bar"},
			expected: `The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. Requested audience 'bar' has not been whitelisted by the OAuth 2.0 Client.`,
		},
		{
			name:     "ShouldFailNonURITrailingSlashNeedle",
			haystack: []string{"foobar"},
			needle:   []string{"foobar/"},
			expected: `The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. Requested audience 'foobar/' has not been whitelisted by the OAuth 2.0 Client.`,
		},
		{
			name:     "ShouldFailNonURITrailingSlashHaystack",
			haystack: []string{"foobar/"},
			needle:   []string{"foobar"},
			expected: `The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. Requested audience 'foobar' has not been whitelisted by the OAuth 2.0 Client.`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := ExactAudienceStrategy(tc.haystack, tc.needle)

			if tc.expected != "" {
				assert.EqualError(t, ErrorToDebugRFC6749Error(actual), tc.expected)

				return
			}

			require.NoError(t, ErrorToDebugRFC6749Error(actual))
		})
	}
}

func TestGetRequestedAudiences(t *testing.T) {
	testCases := []struct {
		name     string
		form     url.Values
		expected []string
	}{
		{
			name:     "ShouldReturnEmptyForMissingParameters",
			form:     url.Values{},
			expected: []string{},
		},
		{
			name:     "ShouldIgnoreResourceParameter",
			form:     url.Values{consts.FormParameterResource: {"https://api.example.com"}},
			expected: []string{},
		},
		{
			name:     "ShouldReturnSingleAudience",
			form:     url.Values{consts.FormParameterAudience: {"foo"}},
			expected: []string{"foo"},
		},
		{
			name:     "ShouldReturnRepeatedAudiences",
			form:     url.Values{consts.FormParameterAudience: {"foo", "bar"}},
			expected: []string{"foo", "bar"},
		},
		{
			name:     "ShouldSplitSpaceDelimitedAudience",
			form:     url.Values{consts.FormParameterAudience: {"foo bar"}},
			expected: []string{"foo", "bar"},
		},
		{
			name:     "ShouldAllowNonURIAudienceValues",
			form:     url.Values{consts.FormParameterAudience: {"my-service my-other-service"}},
			expected: []string{"my-service", "my-other-service"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := GetRequestedAudiences(tc.form)
			assert.Equal(t, tc.expected, actual)
		})
	}
}
