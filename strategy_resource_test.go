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
	const (
		scopedResource   = "https://api.example.com/users?tenant=a"
		allowedResource  = "https://api.example.com/allowed"
		urnResource      = "urn:example:api"
		urnOtherResource = "urn:example:admin"
	)

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
		{name: "ShouldMatchExactURLNoPath", haystack: "https://api.example.com", needle: "https://api.example.com", match: true},
		{name: "ShouldNotMatchSchemeMismatch", haystack: "https://api.example.com/api", needle: "http://api.example.com/api", match: false},
		{name: "ShouldNotMatchHostMismatch", haystack: "https://api.example.com/api", needle: "https://other.example.com/api", match: false},
		{name: "ShouldNotMatchPortMismatch", haystack: "https://api.example.com/api", needle: "https://api.example.com:8443/api", match: false},
		{name: "ShouldNotMatchHostnameCaseSensitivity",
			haystack: "https://API.example.com/api", needle: "https://api.example.com/api", match: false,
		},
		{name: "ShouldMatchSchemeCaseInsensitivity",
			haystack: "HTTPS://api.example.com/api", needle: "https://api.example.com/api", match: true,
		},

		{name: "ShouldMatchExactPath", haystack: "https://api.example.com/users", needle: "https://api.example.com/users", match: true},
		{name: "ShouldMatchNeedleHasTrailingSlash", haystack: "https://api.example.com/users", needle: "https://api.example.com/users/", match: true},
		{name: "ShouldMatchHaystackHasTrailingSlash", haystack: "https://api.example.com/users/", needle: "https://api.example.com/users", match: true},
		{name: "ShouldMatchBothHaveTrailingSlash", haystack: "https://api.example.com/users/", needle: "https://api.example.com/users/", match: true},

		{name: "ShouldMatchSingleSegmentSubpath", haystack: "https://api.example.com/users", needle: "https://api.example.com/users/123", match: true},
		{name: "ShouldMatchMultiSegmentSubpath", haystack: "https://api.example.com/users", needle: "https://api.example.com/users/123/posts/456", match: true},
		{name: "ShouldNotMatchPathPrefixWithoutSegmentBoundary", haystack: "https://api.example.com/users", needle: "https://api.example.com/users123", match: false},
		{name: "ShouldNotMatchPathPrefixWithoutSegmentBoundaryEvenWithSlashAfter", haystack: "https://api.example.com/users", needle: "https://api.example.com/users123/abc", match: false},
		{name: "ShouldNotMatchSiblingSegment", haystack: "https://api.example.com/users", needle: "https://api.example.com/tenants", match: false},
		{name: "ShouldNotMatchAncestorPath", haystack: "https://api.example.com/api/users", needle: "https://api.example.com/api", match: false},

		{name: "ShouldMatchEmptyHaystackPathExactRoot",
			haystack: "https://api.example.com", needle: "https://api.example.com/", match: true,
		},
		{name: "ShouldMatchEmptyHaystackPathAnySubpath",
			haystack: "https://api.example.com", needle: "https://api.example.com/anything", match: true,
		},
		{name: "ShouldMatchRootHaystackAnySubpath",
			haystack: "https://api.example.com/", needle: "https://api.example.com/anything/here", match: true,
		},
		{name: "ShouldMatchEmptyNeedleAndEmptyHaystack",
			haystack: "https://api.example.com", needle: "https://api.example.com", match: true,
		},

		{name: "ShouldNotMatchNeedleQueryStringTheHaystackLacks",
			haystack: "https://api.example.com/users", needle: "https://api.example.com/users?token=foo", match: false,
		},
		{name: "ShouldMatchEqualQueryString",
			haystack: scopedResource, needle: scopedResource, match: true,
		},
		{name: "ShouldNotMatchDifferentQueryString",
			haystack: scopedResource, needle: "https://api.example.com/users?tenant=b", match: false,
		},
		{name: "ShouldNotMatchNeedleFragment",
			haystack: "https://api.example.com/users", needle: "https://api.example.com/users#frag", match: false,
		},

		{name: "ShouldNotMatchUserinfo",
			haystack: "https://api.example.com/users", needle: "https://alice@api.example.com/users", match: false,
		},

		{name: "ShouldNotMatchDotSegmentTraversal",
			haystack: allowedResource, needle: "https://api.example.com/allowed/../admin", match: false,
		},
		{name: "ShouldNotMatchEncodedDotSegmentTraversal",
			haystack: allowedResource, needle: "https://api.example.com/allowed/%2e%2e/admin", match: false,
		},
		{name: "ShouldNotMatchEncodedSlashTraversal",
			haystack: allowedResource, needle: "https://api.example.com/allowed/..%2Fadmin", match: false,
		},
		{name: "ShouldNotMatchSingleDotSegment",
			haystack: allowedResource, needle: "https://api.example.com/allowed/./x", match: false,
		},

		{name: "ShouldMatchEqualURN",
			haystack: urnResource, needle: urnResource, match: true,
		},
		{name: "ShouldNotMatchDifferentURN",
			haystack: urnResource, needle: urnOtherResource, match: false,
		},

		{name: "ShouldNotMatchPathCaseDifference",
			haystack: "https://api.example.com/Users", needle: "https://api.example.com/users", match: false,
		},

		{name: "ShouldNotMatchDoubleSlashedSubpath",
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
			name:     "ShouldFailResourceWithEmptyFragment",
			form:     url.Values{consts.FormParameterResource: {"https://api.example.com/users#"}},
			expected: "The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. The 'resource' parameter must contain resource indicators that do not contain a fragment but 'https://api.example.com/users#' contains a fragment.",
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

func TestGetResourceStrategyFallsBackToExactMatching(t *testing.T) {
	strategy := GetResourceStrategy(t.Context(), nilResourceStrategyProvider{}, &DefaultClient{})

	assert.NoError(t, strategy([]string{"https://api.example.com/users"}, []string{"https://api.example.com/users"}))
	assert.ErrorIs(t, strategy([]string{"https://api.example.com/users"}, []string{"https://api.example.com/users/123"}), ErrInvalidTarget)
}

type nilResourceStrategyProvider struct{}

func (nilResourceStrategyProvider) GetResourceStrategy(_ context.Context) ResourceStrategy {
	return nil
}

func TestWildcardResourceStrategy(t *testing.T) {
	const debugPrefix = "The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. "

	testCases := []struct {
		name     string
		haystack []string
		needle   []string
		expected string
	}{
		{
			name:     "ShouldPassEmptyNeedle",
			haystack: []string{"https://auth.example.com/*"},
			needle:   []string{},
		},
		{
			name:     "ShouldFailEmptyHaystack",
			haystack: []string{},
			needle:   []string{"https://auth.example.com/api"},
			expected: debugPrefix + "Requested resource 'https://auth.example.com/api' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldPassExactMatch",
			haystack: []string{"https://auth.example.com/api"},
			needle:   []string{"https://auth.example.com/api"},
		},
		{
			name:     "ShouldFailSubPathOfExactEntry",
			haystack: []string{"https://auth.example.com/api"},
			needle:   []string{"https://auth.example.com/api/v1"},
			expected: debugPrefix + "Requested resource 'https://auth.example.com/api/v1' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldPassRootWildcard",
			haystack: []string{"https://auth.example.com/*"},
			needle:   []string{"https://auth.example.com/api", "https://auth.example.com/", "https://auth.example.com/a/b?c=d"},
		},
		{
			name:     "ShouldPassNestedWildcard",
			haystack: []string{"https://auth.example.com/api/*"},
			needle:   []string{"https://auth.example.com/api/v1"},
		},
		{
			name:     "ShouldFailNestedWildcardOtherPath",
			haystack: []string{"https://auth.example.com/api/*"},
			needle:   []string{"https://auth.example.com/other"},
			expected: debugPrefix + "Requested resource 'https://auth.example.com/other' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldFailNestedWildcardWithoutTrailingSlash",
			haystack: []string{"https://auth.example.com/api/*"},
			needle:   []string{"https://auth.example.com/api"},
			expected: debugPrefix + "Requested resource 'https://auth.example.com/api' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldFailWhenOneNeedleUnmatched",
			haystack: []string{"https://auth.example.com/api/*", "https://other.example.com/"},
			needle:   []string{"https://auth.example.com/api/v1", "https://other.example.com/x"},
			expected: debugPrefix + "Requested resource 'https://other.example.com/x' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldFailWildcardInHost",
			haystack: []string{"https://auth.*"},
			needle:   []string{"https://auth.evil.com/"},
			expected: debugPrefix + "Requested resource 'https://auth.evil.com/' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldFailWildcardDirectlyAfterHost",
			haystack: []string{"https://auth.example.com*"},
			needle:   []string{"https://auth.example.com.evil.com/"},
			expected: debugPrefix + "Requested resource 'https://auth.example.com.evil.com/' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldFailWildcardNotFollowingSlash",
			haystack: []string{"https://auth.example.com/api*"},
			needle:   []string{"https://auth.example.com/api2"},
			expected: debugPrefix + "Requested resource 'https://auth.example.com/api2' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldFailWildcardWithoutHost",
			haystack: []string{"https:///*", "/*", "*", "urn:example:/*"},
			needle:   []string{"https:///api"},
			expected: debugPrefix + "Requested resource 'https:///api' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldFailWildcardInQuery",
			haystack: []string{"https://auth.example.com/api?x=/*"},
			needle:   []string{"https://auth.example.com/api?x=/y"},
			expected: debugPrefix + "Requested resource 'https://auth.example.com/api?x=/y' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldFailMultipleWildcards",
			haystack: []string{"https://auth.example.com/*/api/*"},
			needle:   []string{"https://auth.example.com/*/api/v1"},
			expected: debugPrefix + "Requested resource 'https://auth.example.com/*/api/v1' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldPassInvalidWildcardAsLiteral",
			haystack: []string{"https://auth.example.com/api*"},
			needle:   []string{"https://auth.example.com/api*"},
		},
		{
			name:     "ShouldFailWildcardNeedleWithDotSegment",
			haystack: []string{"https://auth.example.com/api/*"},
			needle:   []string{"https://auth.example.com/api/../admin"},
			expected: debugPrefix + "Requested resource 'https://auth.example.com/api/../admin' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldFailWildcardNeedleWithEncodedDotSegment",
			haystack: []string{"https://auth.example.com/api/*"},
			needle:   []string{"https://auth.example.com/api/%2e%2e/admin"},
			expected: debugPrefix + "Requested resource 'https://auth.example.com/api/%2e%2e/admin' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldFailWildcardNeedleWithEncodedSlash",
			haystack: []string{"https://auth.example.com/api/*"},
			needle:   []string{"https://auth.example.com/api/..%2fadmin"},
			expected: debugPrefix + "Requested resource 'https://auth.example.com/api/..%2fadmin' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldFailWildcardNeedleWithFragment",
			haystack: []string{"https://auth.example.com/api/*"},
			needle:   []string{"https://auth.example.com/api/v1#frag"},
			expected: debugPrefix + "Requested resource 'https://auth.example.com/api/v1#frag' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldFailWildcardNeedleUnparseable",
			haystack: []string{"https://auth.example.com/api/*"},
			needle:   []string{"https://auth.example.com/api/\x7f"},
			expected: debugPrefix + "Requested resource 'https://auth.example.com/api/\x7f' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:     "ShouldFailWildcardDifferentScheme",
			haystack: []string{"https://auth.example.com/*"},
			needle:   []string{"http://auth.example.com/api"},
			expected: debugPrefix + "Requested resource 'http://auth.example.com/api' has not been whitelisted by the OAuth 2.0 Client.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := WildcardResourceStrategy(tc.haystack, tc.needle)

			if tc.expected != "" {
				assert.EqualError(t, ErrorToDebugRFC6749Error(actual), tc.expected)

				return
			}

			require.NoError(t, ErrorToDebugRFC6749Error(actual))
		})
	}
}

func TestDefaultClientGetResource(t *testing.T) {
	client := &DefaultClient{Audience: []string{"api"}, Resource: []string{"https://auth.example.com/*"}}

	var c Client = client

	assert.Equal(t, Arguments{"https://auth.example.com/*"}, c.GetResource())
}

func TestValidateAudienceMatchesResourceAgainstClientResource(t *testing.T) {
	testCases := []struct {
		name     string
		client   *DefaultClient
		expected string
	}{
		{
			name:   "ShouldPassResourceRegisteredAsResource",
			client: &DefaultClient{Resource: []string{"https://auth.example.com/api"}},
		},
		{
			name:     "ShouldFailResourceRegisteredOnlyAsAudience",
			client:   &DefaultClient{Audience: []string{"https://auth.example.com/api"}},
			expected: "invalid_target",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &Fosite{Config: &Config{}}

			request := NewRequest()
			request.Client = tc.client
			request.Form = url.Values{consts.FormParameterResource: {"https://auth.example.com/api"}}

			err := provider.validateAudience(t.Context(), nil, request)

			if tc.expected != "" {
				assert.EqualError(t, err, tc.expected)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, Arguments{"https://auth.example.com/api"}, request.GetRequestedResource())
		})
	}
}
