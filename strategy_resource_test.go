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

func TestDefaultResourceMatchingStrategy(t *testing.T) {
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
			haystack: []string{"https://foo/bar"},
			needle:   []string{},
		},
		{
			name:     "ShouldFailEmptyHaystack",
			haystack: []string{},
			needle:   []string{"https://foo/bar"},
			expected: debugPrefix + "Requested resource 'https://foo/bar' has not been whitelisted by the OAuth 2.0 Client.",
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
			expected: debugPrefix + "Requested resource 'https://cloud.authelia.com/api/users1234' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldFailWhenSchemeMismatches",
			haystack: []string{"https://cloud.authelia.com/api/users"},
			needle:   []string{"http://cloud.authelia.com/api/users"},
			expected: debugPrefix + "Requested resource 'http://cloud.authelia.com/api/users' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldFailWhenPortMismatches",
			haystack: []string{"https://cloud.authelia.com/api/users"},
			needle:   []string{"https://cloud.authelia.com:8000/api/users"},
			expected: debugPrefix + "Requested resource 'https://cloud.authelia.com:8000/api/users' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldFailWhenHostMismatches",
			haystack: []string{"https://cloud.authelia.com/api/users"},
			needle:   []string{"https://cloud.ory.xyz/api/users"},
			expected: debugPrefix + "Requested resource 'https://cloud.ory.xyz/api/users' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldFailWhenSinglePartialMatchInList",
			haystack: []string{"https://cloud.authelia.com/api/users"},
			needle:   []string{"https://cloud.authelia.com/api/users", "https://cloud.authelia.com/api/tenants"},
			expected: debugPrefix + "Requested resource 'https://cloud.authelia.com/api/tenants' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldFailNeedleIsUnparseableURL",
			haystack: []string{"https://example.com/api"},
			needle:   []string{"\x7f"},
			expected: debugPrefix + "Requested resource '\x7f' could not be parsed.",
		},
		{
			name:     "ShouldSkipUnparseableHaystackEntryAndKeepLookingForMatch",
			haystack: []string{"\x7f", "https://example.com/api"},
			needle:   []string{"https://example.com/api"},
		},
		{
			name:     "ShouldFailWhenAllHaystackEntriesUnparseableExceptOneMismatch",
			haystack: []string{"\x7f", "https://other.example.com/api"},
			needle:   []string{"https://example.com/api"},
			expected: debugPrefix + "Requested resource 'https://example.com/api' has not been whitelisted by the OAuth 2.0 Client.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := DefaultResourceStrategy(tc.haystack, tc.needle)

			if tc.expected != "" {
				assert.EqualError(t, ErrorToDebugRFC6749Error(actual), tc.expected)

				return
			}

			require.NoError(t, ErrorToDebugRFC6749Error(actual))
		})
	}
}

func TestIsMatchingResourceIndicator(t *testing.T) {
	mustParse := func(s string) *url.URL {
		u, err := url.Parse(s)
		require.NoError(t, err, "test bug: unparseable url %q", s)
		return u
	}

	testCases := []struct {
		name     string
		haystack string
		needle   string
		match    bool
	}{
		// Scheme / host equality
		{name: "ShouldMatchExactURLNoPath", haystack: "https://api.example.com", needle: "https://api.example.com", match: true},
		{name: "ShouldNotMatchSchemeMismatch", haystack: "https://api.example.com/api", needle: "http://api.example.com/api", match: false},
		{name: "ShouldNotMatchHostMismatch", haystack: "https://api.example.com/api", needle: "https://other.example.com/api", match: false},
		{name: "ShouldNotMatchPortMismatch", haystack: "https://api.example.com/api", needle: "https://api.example.com:8443/api", match: false},
		{name: "ShouldNotMatchHostnameCaseSensitivity",
			// url.Parse normalizes scheme to lowercase but preserves host case. This
			// asserts current behavior; if host normalization changes, update.
			haystack: "https://API.example.com/api", needle: "https://api.example.com/api", match: false,
		},
		{name: "ShouldMatchSchemeCaseInsensitivity",
			// url.Parse normalizes scheme to lowercase, so HTTPS and https are equivalent.
			haystack: "HTTPS://api.example.com/api", needle: "https://api.example.com/api", match: true,
		},

		// Path equality and trailing slash
		{name: "ShouldMatchExactPath", haystack: "https://api.example.com/users", needle: "https://api.example.com/users", match: true},
		{name: "ShouldMatchNeedleHasTrailingSlash", haystack: "https://api.example.com/users", needle: "https://api.example.com/users/", match: true},
		{name: "ShouldMatchHaystackHasTrailingSlash", haystack: "https://api.example.com/users/", needle: "https://api.example.com/users", match: true},
		{name: "ShouldMatchBothHaveTrailingSlash", haystack: "https://api.example.com/users/", needle: "https://api.example.com/users/", match: true},

		// Subpath rule
		{name: "ShouldMatchSingleSegmentSubpath", haystack: "https://api.example.com/users", needle: "https://api.example.com/users/123", match: true},
		{name: "ShouldMatchMultiSegmentSubpath", haystack: "https://api.example.com/users", needle: "https://api.example.com/users/123/posts/456", match: true},
		{name: "ShouldNotMatchPathPrefixWithoutSegmentBoundary", haystack: "https://api.example.com/users", needle: "https://api.example.com/users123", match: false},
		{name: "ShouldNotMatchPathPrefixWithoutSegmentBoundaryEvenWithSlashAfter", haystack: "https://api.example.com/users", needle: "https://api.example.com/users123/abc", match: false},
		{name: "ShouldNotMatchSiblingSegment", haystack: "https://api.example.com/users", needle: "https://api.example.com/tenants", match: false},
		{name: "ShouldNotMatchAncestorPath", haystack: "https://api.example.com/api/users", needle: "https://api.example.com/api", match: false},

		// Root and empty paths (current behavior — see notes below the table)
		{name: "ShouldMatchEmptyHaystackPathExactRoot",
			haystack: "https://api.example.com", needle: "https://api.example.com/", match: true,
		},
		{name: "ShouldMatchEmptyHaystackPathAnySubpath",
			// PERMISSIVE behavior: a haystack with no path grants any subpath under the same scheme+host.
			haystack: "https://api.example.com", needle: "https://api.example.com/anything", match: true,
		},
		{name: "ShouldMatchRootHaystackAnySubpath",
			// `/` is normalized to empty allowedPath, so `/` matches everything under scheme+host.
			haystack: "https://api.example.com/", needle: "https://api.example.com/anything/here", match: true,
		},
		{name: "ShouldMatchEmptyNeedleAndEmptyHaystack",
			haystack: "https://api.example.com", needle: "https://api.example.com", match: true,
		},

		// Query and fragment are ignored when matching paths
		{name: "ShouldMatchIgnoringNeedleQueryString",
			haystack: "https://api.example.com/users", needle: "https://api.example.com/users?token=foo", match: true,
		},
		{name: "ShouldMatchIgnoringNeedleFragment",
			haystack: "https://api.example.com/users", needle: "https://api.example.com/users#frag", match: true,
		},

		// Userinfo is part of url.URL.User, not Host — ignored in matching.
		{name: "ShouldMatchIgnoringUserinfo",
			haystack: "https://api.example.com/users", needle: "https://alice:secret@api.example.com/users", match: true,
		},

		// Case-sensitive path comparison
		{name: "ShouldNotMatchPathCaseDifference",
			haystack: "https://api.example.com/Users", needle: "https://api.example.com/users", match: false,
		},

		// Repeated slashes in needle path
		{name: "ShouldNotMatchDoubleSlashedSubpath",
			// "//1234" is not a valid subpath separator-wise; the prefix check
			// looks at allowedPath+"/" so this still matches because the prefix
			// up to allowedPath+"/" equals allowedPath+"/".
			haystack: "https://api.example.com/users", needle: "https://api.example.com/users//1234", match: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := IsMatchingResourceIndicator(mustParse(tc.haystack), mustParse(tc.needle))
			assert.Equal(t, tc.match, actual)
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
