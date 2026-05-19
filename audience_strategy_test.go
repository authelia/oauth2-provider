// Copyright © 2023 Ory Corp
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
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Requested audience 'http://foo/bar' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldPassExactURL",
			haystack: []string{"https://cloud.authelia.com/api/users"},
			needle:   []string{"https://cloud.authelia.com/api/users"},
		},
		{
			name:     "ShouldPassNeedleHasTrailingSlash",
			haystack: []string{"https://cloud.authelia.com/api/users"},
			needle:   []string{"https://cloud.authelia.com/api/users/"},
		},
		{
			name:     "ShouldPassBothHaveTrailingSlash",
			haystack: []string{"https://cloud.authelia.com/api/users/"},
			needle:   []string{"https://cloud.authelia.com/api/users/"},
		},
		{
			name:     "ShouldPassHaystackHasTrailingSlash",
			haystack: []string{"https://cloud.authelia.com/api/users/"},
			needle:   []string{"https://cloud.authelia.com/api/users"},
		},
		{
			name:     "ShouldPassNeedleIsSubpath",
			haystack: []string{"https://cloud.authelia.com/api/users"},
			needle:   []string{"https://cloud.authelia.com/api/users/1234"},
		},
		{
			name:     "ShouldPassMultipleNeedlesUnderSingleHaystack",
			haystack: []string{"https://cloud.authelia.com/api/users"},
			needle:   []string{"https://cloud.authelia.com/api/users", "https://cloud.authelia.com/api/users/", "https://cloud.authelia.com/api/users/1234"},
		},
		{
			name:     "ShouldPassMultipleNeedlesAcrossHaystacks",
			haystack: []string{"https://cloud.authelia.com/api/users", "https://cloud.authelia.com/api/tenants"},
			needle:   []string{"https://cloud.authelia.com/api/users", "https://cloud.authelia.com/api/users/", "https://cloud.authelia.com/api/users/1234", "https://cloud.authelia.com/api/tenants"},
		},
		{
			name:     "ShouldFailWhenPathHasExtraSuffix",
			haystack: []string{"https://cloud.authelia.com/api/users"},
			needle:   []string{"https://cloud.authelia.com/api/users1234"},
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Requested audience 'https://cloud.authelia.com/api/users1234' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldFailWhenSchemeMismatches",
			haystack: []string{"https://cloud.authelia.com/api/users"},
			needle:   []string{"http://cloud.authelia.com/api/users"},
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Requested audience 'http://cloud.authelia.com/api/users' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldFailWhenPortMismatches",
			haystack: []string{"https://cloud.authelia.com/api/users"},
			needle:   []string{"https://cloud.authelia.com:8000/api/users"},
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Requested audience 'https://cloud.authelia.com:8000/api/users' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldFailWhenHostMismatches",
			haystack: []string{"https://cloud.authelia.com/api/users"},
			needle:   []string{"https://cloud.ory.xyz/api/users"},
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Requested audience 'https://cloud.ory.xyz/api/users' has not been whitelisted by the OAuth 2.0 Client.",
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
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Requested audience 'bar' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldPassNonURITrailingSlashNeedle",
			haystack: []string{"foobar"},
			needle:   []string{"foobar/"},
		},
		{
			name:     "ShouldPassNonURITrailingSlashHaystack",
			haystack: []string{"foobar/"},
			needle:   []string{"foobar"},
		},
		{
			name:     "ShouldFailNeedleIsUnparseableURL",
			haystack: []string{"https://example.com/api"},
			needle:   []string{"\x7f"},
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Unable to parse requested audience ''. parse '\\x7f': net/url: invalid control character in URL",
		},
		{
			name:     "ShouldFailHaystackIsUnparseableURL",
			haystack: []string{"\x7f"},
			needle:   []string{"https://example.com/api"},
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Unable to parse whitelisted audience ''. parse '\\x7f': net/url: invalid control character in URL",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := DefaultAudienceMatchingStrategy(tc.haystack, tc.needle)

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
			expected: `The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Requested audience 'http://foo/bar' has not been whitelisted by the OAuth 2.0 Client.`,
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
			expected: `The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Requested audience 'https://cloud.authelia.com/api/users/' has not been whitelisted by the OAuth 2.0 Client.`,
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
			expected: `The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Requested audience 'https://cloud.authelia.com/api/users' has not been whitelisted by the OAuth 2.0 Client.`,
		},
		{
			name:     "ShouldFailNeedleIsSubpath",
			haystack: []string{"https://cloud.authelia.com/api/users"},
			needle:   []string{"https://cloud.authelia.com/api/users/1234"},
			expected: `The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Requested audience 'https://cloud.authelia.com/api/users/1234' has not been whitelisted by the OAuth 2.0 Client.`,
		},
		{
			name:     "ShouldFailMultipleNeedlesOnePartialMatch",
			haystack: []string{"https://cloud.authelia.com/api/users"},
			needle:   []string{"https://cloud.authelia.com/api/users", "https://cloud.authelia.com/api/users/", "https://cloud.authelia.com/api/users/1234"},
			expected: `The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Requested audience 'https://cloud.authelia.com/api/users/' has not been whitelisted by the OAuth 2.0 Client.`,
		},
		{
			name:     "ShouldFailMultipleNeedlesAcrossHaystacks",
			haystack: []string{"https://cloud.authelia.com/api/users", "https://cloud.authelia.com/api/tenants"},
			needle:   []string{"https://cloud.authelia.com/api/users", "https://cloud.authelia.com/api/users/", "https://cloud.authelia.com/api/users/1234", "https://cloud.authelia.com/api/tenants"},
			expected: `The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Requested audience 'https://cloud.authelia.com/api/users/' has not been whitelisted by the OAuth 2.0 Client.`,
		},
		{
			name:     "ShouldFailWhenPathHasExtraSuffix",
			haystack: []string{"https://cloud.authelia.com/api/users"},
			needle:   []string{"https://cloud.authelia.com/api/users1234"},
			expected: `The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Requested audience 'https://cloud.authelia.com/api/users1234' has not been whitelisted by the OAuth 2.0 Client.`,
		},
		{
			name:     "ShouldFailWhenSchemeMismatches",
			haystack: []string{"https://cloud.authelia.com/api/users"},
			needle:   []string{"http://cloud.authelia.com/api/users"},
			expected: `The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Requested audience 'http://cloud.authelia.com/api/users' has not been whitelisted by the OAuth 2.0 Client.`,
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
			expected: `The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Requested audience 'bar' has not been whitelisted by the OAuth 2.0 Client.`,
		},
		{
			name:     "ShouldFailNonURITrailingSlashNeedle",
			haystack: []string{"foobar"},
			needle:   []string{"foobar/"},
			expected: `The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Requested audience 'foobar/' has not been whitelisted by the OAuth 2.0 Client.`,
		},
		{
			name:     "ShouldFailNonURITrailingSlashHaystack",
			haystack: []string{"foobar/"},
			needle:   []string{"foobar"},
			expected: `The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Requested audience 'foobar' has not been whitelisted by the OAuth 2.0 Client.`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := ExactAudienceMatchingStrategy(tc.haystack, tc.needle)

			if tc.expected != "" {
				assert.EqualError(t, ErrorToDebugRFC6749Error(actual), tc.expected)

				return
			}

			require.NoError(t, ErrorToDebugRFC6749Error(actual))
		})
	}
}

func TestGetAudiences(t *testing.T) {
	testCases := []struct {
		name     string
		form     url.Values
		expected []string
	}{
		{
			name:     "ShouldReturnEmptyForMissingAudienceParameter",
			form:     url.Values{},
			expected: []string{},
		},
		{
			name:     "ShouldSplitSingleSpaceDelimitedAudience",
			form:     url.Values{consts.FormParameterAudience: {"https://api.example.com https://api.other.com"}},
			expected: []string{"https://api.example.com", "https://api.other.com"},
		},
		{
			name:     "ShouldReturnSingleAudience",
			form:     url.Values{consts.FormParameterAudience: {"https://api.example.com"}},
			expected: []string{"https://api.example.com"},
		},
		{
			name:     "ShouldReturnRepeatedAudiences",
			form:     url.Values{consts.FormParameterAudience: {"https://api.example.com", "https://api.other.com"}},
			expected: []string{"https://api.example.com", "https://api.other.com"},
		},
		{
			name:     "ShouldFilterEmptyEntriesFromRepeatedAudiences",
			form:     url.Values{consts.FormParameterAudience: {"https://api.example.com", "", "https://api.other.com"}},
			expected: []string{"https://api.example.com", "https://api.other.com"},
		},
		{
			name:     "ShouldFilterEmptyEntriesFromSpaceDelimitedAudience",
			form:     url.Values{consts.FormParameterAudience: {"https://api.example.com  https://api.other.com"}},
			expected: []string{"https://api.example.com", "https://api.other.com"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := GetAudiences(tc.form)
			assert.Equal(t, tc.expected, actual)
		})
	}
}
