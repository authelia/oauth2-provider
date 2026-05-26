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
			expected: "The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. Requested audience 'http://foo/bar' has not been whitelisted by the OAuth 2.0 Client.",
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
			expected: "The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. Requested audience 'https://cloud.authelia.com/api/users1234' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldFailWhenSchemeMismatches",
			haystack: []string{"https://cloud.authelia.com/api/users"},
			needle:   []string{"http://cloud.authelia.com/api/users"},
			expected: "The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. Requested audience 'http://cloud.authelia.com/api/users' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldFailWhenPortMismatches",
			haystack: []string{"https://cloud.authelia.com/api/users"},
			needle:   []string{"https://cloud.authelia.com:8000/api/users"},
			expected: "The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. Requested audience 'https://cloud.authelia.com:8000/api/users' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldFailWhenHostMismatches",
			haystack: []string{"https://cloud.authelia.com/api/users"},
			needle:   []string{"https://cloud.ory.xyz/api/users"},
			expected: "The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. Requested audience 'https://cloud.ory.xyz/api/users' has not been whitelisted by the OAuth 2.0 Client.",
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
			expected: "The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. Requested audience 'bar' has not been whitelisted by the OAuth 2.0 Client.",
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
			expected: "The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. Unable to parse requested audience '\x7f'.",
		},
		{
			name:     "ShouldFailHaystackIsUnparseableURL",
			haystack: []string{"\x7f"},
			needle:   []string{"https://example.com/api"},
			expected: "The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. Unable to parse whitelisted audience '\x7f'.",
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
			actual := ExactAudienceMatchingStrategy(tc.haystack, tc.needle)

			if tc.expected != "" {
				assert.EqualError(t, ErrorToDebugRFC6749Error(actual), tc.expected)

				return
			}

			require.NoError(t, ErrorToDebugRFC6749Error(actual))
		})
	}
}

func TestGetRequestedResources(t *testing.T) {
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
			name:     "ShouldIgnoreAudienceParameter",
			form:     url.Values{consts.FormParameterAudience: {"https://api.example.com"}},
			expected: []string{},
		},
		{
			name:     "ShouldReturnSingleResource",
			form:     url.Values{consts.FormParameterResource: {"https://api.example.com"}},
			expected: []string{"https://api.example.com"},
		},
		{
			name:     "ShouldReturnRepeatedResources",
			form:     url.Values{consts.FormParameterResource: {"https://api.example.com", "https://api.other.com"}},
			expected: []string{"https://api.example.com", "https://api.other.com"},
		},
		{
			name:     "ShouldSplitSingleSpaceDelimitedResource",
			form:     url.Values{consts.FormParameterResource: {"https://api.example.com https://api.other.com"}},
			expected: []string{"https://api.example.com", "https://api.other.com"},
		},
		{
			name:     "ShouldReturnResourceWhenAudienceAlsoPresent",
			form:     url.Values{consts.FormParameterResource: {"https://api.example.com"}, consts.FormParameterAudience: {"https://api.other.com"}},
			expected: []string{"https://api.example.com"},
		},
		{
			name:     "ShouldReturnEmptyWhenAllEmpty",
			form:     url.Values{consts.FormParameterResource: {""}, consts.FormParameterAudience: {""}},
			expected: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := GetRequestedResources(tc.form)
			assert.Equal(t, tc.expected, actual)
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

func TestJoinGrantedAudienceAndResource(t *testing.T) {
	testCases := []struct {
		name     string
		audience Arguments
		resource Arguments
		expected Arguments
	}{
		{
			name:     "ShouldReturnNilWhenBothEmpty",
			audience: Arguments{},
			resource: Arguments{},
			expected: nil,
		},
		{
			name:     "ShouldReturnAudienceWhenResourceEmpty",
			audience: Arguments{"my-service"},
			resource: Arguments{},
			expected: Arguments{"my-service"},
		},
		{
			name:     "ShouldReturnResourceWhenAudienceEmpty",
			audience: Arguments{},
			resource: Arguments{"https://api.example.com"},
			expected: Arguments{"https://api.example.com"},
		},
		{
			name:     "ShouldConcatenateBoth",
			audience: Arguments{"my-service"},
			resource: Arguments{"https://api.example.com"},
			expected: Arguments{"my-service", "https://api.example.com"},
		},
		{
			name:     "ShouldDeduplicateOverlappingValues",
			audience: Arguments{"foo", "shared"},
			resource: Arguments{"shared", "bar"},
			expected: Arguments{"foo", "shared", "bar"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, JoinGrantedAudienceAndResource(tc.audience, tc.resource))
		})
	}
}

func TestGetResourcesParameter(t *testing.T) {
	testCases := []struct {
		name      string
		parameter string
		form      url.Values
		expected  []string
		ok        bool
	}{
		{
			name:      "ShouldReturnFalseWhenParameterMissing",
			parameter: consts.FormParameterResource,
			form:      url.Values{},
			expected:  []string{},
			ok:        false,
		},
		{
			name:      "ShouldReturnFalseForSingleEmptyValue",
			parameter: consts.FormParameterResource,
			form:      url.Values{consts.FormParameterResource: {""}},
			ok:        false,
		},
		{
			name:      "ShouldReturnFalseForAllEmptyRepeatedValues",
			parameter: consts.FormParameterResource,
			form:      url.Values{consts.FormParameterResource: {"", ""}},
			ok:        false,
		},
		{
			name:      "ShouldSplitSingleSpaceDelimitedValue",
			parameter: consts.FormParameterResource,
			form:      url.Values{consts.FormParameterResource: {"https://api.example.com https://api.other.com"}},
			expected:  []string{"https://api.example.com", "https://api.other.com"},
			ok:        true,
		},
		{
			name:      "ShouldReturnRepeatedValues",
			parameter: consts.FormParameterResource,
			form:      url.Values{consts.FormParameterResource: {"https://api.example.com", "https://api.other.com"}},
			expected:  []string{"https://api.example.com", "https://api.other.com"},
			ok:        true,
		},
		{
			name:      "ShouldFilterEmptyFromRepeatedValues",
			parameter: consts.FormParameterResource,
			form:      url.Values{consts.FormParameterResource: {"https://api.example.com", "", "https://api.other.com"}},
			expected:  []string{"https://api.example.com", "https://api.other.com"},
			ok:        true,
		},
		{
			name:      "ShouldReadAudienceParameter",
			parameter: consts.FormParameterAudience,
			form:      url.Values{consts.FormParameterAudience: {"https://api.example.com"}},
			expected:  []string{"https://api.example.com"},
			ok:        true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, ok := GetResourcesParameter(tc.parameter, tc.form)
			assert.Equal(t, tc.ok, ok)

			if tc.expected == nil {
				assert.Empty(t, actual)
			} else {
				assert.Equal(t, tc.expected, actual)
			}
		})
	}
}

func TestValidateResourceIndicators(t *testing.T) {
	testCases := []struct {
		name     string
		form     url.Values
		expected string
	}{
		{
			name: "ShouldPassEmptyForm",
			form: url.Values{},
		},
		{
			name: "ShouldPassOnlyAudienceSet",
			form: url.Values{consts.FormParameterAudience: {"https://api.example.com"}},
		},
		{
			name: "ShouldPassSingleAbsoluteResource",
			form: url.Values{consts.FormParameterResource: {"https://api.example.com"}},
		},
		{
			name: "ShouldPassMultipleAbsoluteResources",
			form: url.Values{consts.FormParameterResource: {"https://api.example.com", "https://api.other.com"}},
		},
		{
			name: "ShouldPassSpaceDelimitedAbsoluteResources",
			form: url.Values{consts.FormParameterResource: {"https://api.example.com https://api.other.com"}},
		},
		{
			name: "ShouldPassEmptyResourceValue",
			form: url.Values{consts.FormParameterResource: {""}},
		},
		{
			name: "ShouldPassWhenBothResourceAndAudienceSet",
			form: url.Values{consts.FormParameterResource: {"https://api.example.com"}, consts.FormParameterAudience: {"my-service"}},
		},
		{
			name: "ShouldNotValidateAudienceValuesAsURIs",
			form: url.Values{consts.FormParameterAudience: {"not a uri"}},
		},
		{
			name:     "ShouldFailRelativeResource",
			form:     url.Values{consts.FormParameterResource: {"/api/users"}},
			expected: "The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. The 'resource' parameter must contain resource indicators that are absolute URIs but '/api/users' is not absolute.",
		},
		{
			name:     "ShouldFailRelativeResourceWithoutScheme",
			form:     url.Values{consts.FormParameterResource: {"api.example.com/users"}},
			expected: "The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. The 'resource' parameter must contain resource indicators that are absolute URIs but 'api.example.com/users' is not absolute.",
		},
		{
			name:     "ShouldFailResourceWithFragment",
			form:     url.Values{consts.FormParameterResource: {"https://api.example.com/users#section"}},
			expected: "The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. The 'resource' parameter must contain resource indicators that do not contain a fragment but 'https://api.example.com/users#section' contains a fragment.",
		},
		{
			name:     "ShouldFailUnparseableResource",
			form:     url.Values{consts.FormParameterResource: {"\x7f"}},
			expected: "The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. Unable to parse resource indicator '\x7f' from the 'resource' parameter.",
		},
		{
			name:     "ShouldFailRelativeAmongstValidResources",
			form:     url.Values{consts.FormParameterResource: {"https://api.example.com", "/relative"}},
			expected: "The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. The 'resource' parameter must contain resource indicators that are absolute URIs but '/relative' is not absolute.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := ValidateResourceIndicators(tc.form)

			if tc.expected != "" {
				assert.EqualError(t, ErrorToDebugRFC6749Error(actual), tc.expected)

				return
			}

			require.NoError(t, ErrorToDebugRFC6749Error(actual))
		})
	}
}
