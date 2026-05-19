// Copyright © 2026 Authelia
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"authelia.com/provider/oauth2/internal/consts"
)

func TestHierarchicScopeStrategy(t *testing.T) {
	testCases := []struct {
		name     string
		scopes   []string
		needle   string
		expected bool
	}{
		{
			name:   "ShouldNotMatchAnyNeedleAgainstEmptyScopes",
			scopes: []string{},
			needle: "foo.bar.baz",
		},
		{
			name:   "ShouldNotMatchTwoLevelNeedleAgainstEmptyScopes",
			scopes: []string{},
			needle: "foo.bar",
		},
		{
			name:   "ShouldNotMatchSingleNeedleAgainstEmptyScopes",
			scopes: []string{},
			needle: "foo",
		},
		{
			name:     "ShouldMatchDeeperNeedleUnderHierarchicScope",
			scopes:   []string{"foo.bar", "bar.baz", "baz.baz.1", "baz.baz.2", "baz.baz.3", "baz.baz.baz"},
			needle:   "foo.bar.baz",
			expected: true,
		},
		{
			name:     "ShouldMatchExactScope",
			scopes:   []string{"foo.bar", "bar.baz", "baz.baz.1", "baz.baz.2", "baz.baz.3", "baz.baz.baz"},
			needle:   "baz.baz.baz",
			expected: true,
		},
		{
			name:     "ShouldMatchExactTwoLevelScope",
			scopes:   []string{"foo.bar", "bar.baz", "baz.baz.1", "baz.baz.2", "baz.baz.3", "baz.baz.baz"},
			needle:   "foo.bar",
			expected: true,
		},
		{
			name:   "ShouldNotMatchParentOfScope",
			scopes: []string{"foo.bar", "bar.baz", "baz.baz.1", "baz.baz.2", "baz.baz.3", "baz.baz.baz"},
			needle: "foo",
		},
		{
			name:     "ShouldMatchAnotherExactTwoLevelScope",
			scopes:   []string{"foo.bar", "bar.baz", "baz.baz.1", "baz.baz.2", "baz.baz.3", "baz.baz.baz"},
			needle:   "bar.baz",
			expected: true,
		},
		{
			name:     "ShouldMatchDeeperNeedleUnderTwoLevelScope",
			scopes:   []string{"foo.bar", "bar.baz", "baz.baz.1", "baz.baz.2", "baz.baz.3", "baz.baz.baz"},
			needle:   "bar.baz.zad",
			expected: true,
		},
		{
			name:   "ShouldNotMatchBareNeedleNotPresent",
			scopes: []string{"foo.bar", "bar.baz", "baz.baz.1", "baz.baz.2", "baz.baz.3", "baz.baz.baz"},
			needle: "bar",
		},
		{
			name:   "ShouldNotMatchUnrelatedBareNeedle",
			scopes: []string{"foo.bar", "bar.baz", "baz.baz.1", "baz.baz.2", "baz.baz.3", "baz.baz.baz"},
			needle: "baz",
		},
		{
			name:     "ShouldMatchExactDelete",
			scopes:   []string{"authelia.key.create", "authelia.key.get", "authelia.key.delete", "authelia.key.update"},
			needle:   "authelia.key.delete",
			expected: true,
		},
		{
			name:     "ShouldMatchExactGet",
			scopes:   []string{"authelia.key.create", "authelia.key.get", "authelia.key.delete", "authelia.key.update"},
			needle:   "authelia.key.get",
			expected: true,
		},
		{
			name:     "ShouldMatchExactUpdate",
			scopes:   []string{"authelia.key.create", "authelia.key.get", "authelia.key.delete", "authelia.key.update"},
			needle:   "authelia.key.update",
			expected: true,
		},
		{
			name:   "ShouldNotMatchUnrelatedScope",
			scopes: []string{"authelia", consts.ScopeOpenID, consts.ScopeOffline},
			needle: "foo.bar",
		},
		{
			name:   "ShouldNotMatchUnrelatedSingleScope",
			scopes: []string{"authelia", consts.ScopeOpenID, consts.ScopeOffline},
			needle: "foo",
		},
		{
			name:     "ShouldMatchBareAutheliaScope",
			scopes:   []string{"authelia", consts.ScopeOpenID, consts.ScopeOffline},
			needle:   "authelia",
			expected: true,
		},
		{
			name:     "ShouldMatchAutheliaSubScope",
			scopes:   []string{"authelia", consts.ScopeOpenID, consts.ScopeOffline},
			needle:   "authelia.bar",
			expected: true,
		},
		{
			name:     "ShouldMatchOpenIDExactly",
			scopes:   []string{"authelia", consts.ScopeOpenID, consts.ScopeOffline},
			needle:   consts.ScopeOpenID,
			expected: true,
		},
		{
			name:     "ShouldMatchOpenIDSubScope",
			scopes:   []string{"authelia", consts.ScopeOpenID, consts.ScopeOffline},
			needle:   "openid.baz.bar",
			expected: true,
		},
		{
			name:     "ShouldMatchOfflineExactly",
			scopes:   []string{"authelia", consts.ScopeOpenID, consts.ScopeOffline},
			needle:   consts.ScopeOffline,
			expected: true,
		},
		{
			name:     "ShouldMatchOfflineSubScope",
			scopes:   []string{"authelia", consts.ScopeOpenID, consts.ScopeOffline},
			needle:   "offline.baz.bar.baz",
			expected: true,
		},
	}

	var strategy ScopeStrategy = HierarchicScopeStrategy

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := strategy(tc.scopes, tc.needle)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestWildcardScopeStrategy(t *testing.T) {
	testCases := []struct {
		name     string
		scopes   []string
		needle   string
		expected bool
	}{
		{
			name:   "ShouldNotMatchThreeLevelNeedleAgainstEmptyScopes",
			scopes: []string{},
			needle: "foo.bar.baz",
		},
		{
			name:   "ShouldNotMatchTwoLevelNeedleAgainstEmptyScopes",
			scopes: []string{},
			needle: "foo.bar",
		},
		{
			name:   "ShouldNotMatchEmptyNeedleWithStarScope",
			scopes: []string{"*"},
			needle: "",
		},
		{
			name:     "ShouldMatchAnySingleScopeWithStar",
			scopes:   []string{"*"},
			needle:   "asdf",
			expected: true,
		},
		{
			name:     "ShouldMatchTwoLevelNeedleWithStar",
			scopes:   []string{"*"},
			needle:   "asdf.asdf",
			expected: true,
		},
		{
			name:   "ShouldNotMatchStarLiteralAgainstFooScope",
			scopes: []string{"foo"},
			needle: "*",
		},
		{
			name:   "ShouldNotMatchFooStarPatternAgainstFooScope",
			scopes: []string{"foo"},
			needle: "foo.*",
		},
		{
			name:   "ShouldNotMatchPartialPrefixStarAgainstFooScope",
			scopes: []string{"foo"},
			needle: "fo*",
		},
		{
			name:     "ShouldMatchExactFooAgainstFooScope",
			scopes:   []string{"foo"},
			needle:   "foo",
			expected: true,
		},
		{
			name:   "ShouldNotMatchFooAgainstFooStarLiteralScope",
			scopes: []string{"foo*"},
			needle: "foo",
		},
		{
			name:   "ShouldNotMatchSuffixedNeedleAgainstFooStarLiteralScope",
			scopes: []string{"foo*"},
			needle: "fooa",
		},
		{
			name:   "ShouldNotMatchTruncatedNeedleAgainstFooStarLiteralScope",
			scopes: []string{"foo*"},
			needle: "fo",
		},
		{
			name:     "ShouldMatchExactFooStarAgainstFooStarLiteralScope",
			scopes:   []string{"foo*"},
			needle:   "foo*",
			expected: true,
		},
		{
			name:     "ShouldMatchFooBarAgainstFooStar",
			scopes:   []string{"foo.*"},
			needle:   "foo.bar",
			expected: true,
		},
		{
			name:     "ShouldMatchFooBazAgainstFooStar",
			scopes:   []string{"foo.*"},
			needle:   "foo.baz",
			expected: true,
		},
		{
			name:     "ShouldMatchFooBarBazAgainstFooStar",
			scopes:   []string{"foo.*"},
			needle:   "foo.bar.baz",
			expected: true,
		},
		{
			name:   "ShouldNotMatchFooAgainstFooStar",
			scopes: []string{"foo.*"},
			needle: "foo",
		},
		{
			name:     "ShouldMatchSelfAgainstFooStarBaz",
			scopes:   []string{"foo.*.baz"},
			needle:   "foo.*.baz",
			expected: true,
		},
		{
			name:     "ShouldMatchFooBarBazAgainstFooStarBaz",
			scopes:   []string{"foo.*.baz"},
			needle:   "foo.bar.baz",
			expected: true,
		},
		{
			name:   "ShouldNotMatchEmptyMiddleAgainstFooStarBaz",
			scopes: []string{"foo.*.baz"},
			needle: "foo..baz",
		},
		{
			name:   "ShouldNotMatchTwoLevelNeedleAgainstFooStarBaz",
			scopes: []string{"foo.*.baz"},
			needle: "foo.baz",
		},
		{
			name:   "ShouldNotMatchSingleAgainstFooStarBaz",
			scopes: []string{"foo.*.baz"},
			needle: "foo",
		},
		{
			name:   "ShouldNotMatchFooBarBarAgainstFooStarBaz",
			scopes: []string{"foo.*.baz"},
			needle: "foo.bar.bar",
		},
		{
			name:     "ShouldMatchFooBazBarBazAgainstFooStarBarStar",
			scopes:   []string{"foo.*.bar.*"},
			needle:   "foo.baz.bar.baz",
			expected: true,
		},
		{
			name:   "ShouldNotMatchFooBazBazBarBazAgainstFooStarBarStar",
			scopes: []string{"foo.*.bar.*"},
			needle: "foo.baz.baz.bar.baz",
		},
		{
			name:     "ShouldMatchFooBazBarBarBarAgainstFooStarBarStar",
			scopes:   []string{"foo.*.bar.*"},
			needle:   "foo.baz.bar.bar.bar",
			expected: true,
		},
		{
			name:   "ShouldNotMatchFooBazBarAgainstFooStarBarStar",
			scopes: []string{"foo.*.bar.*"},
			needle: "foo.baz.bar",
		},
		{
			name:     "ShouldMatchFooStarBarStarStarStarAgainstFooStarBarStar",
			scopes:   []string{"foo.*.bar.*"},
			needle:   "foo.*.bar.*.*.*",
			expected: true,
		},
		{
			name:     "ShouldMatchLongerNeedleAgainstFooStarBarStar",
			scopes:   []string{"foo.*.bar.*"},
			needle:   "foo.1.bar.1.2.3.4.5",
			expected: true,
		},
		{
			name:     "ShouldMatchFooBarBarAgainstFooStarBar",
			scopes:   []string{"foo.*.bar"},
			needle:   "foo.bar.bar",
			expected: true,
		},
		{
			name:   "ShouldNotMatchFooBarBarBarAgainstFooStarBar",
			scopes: []string{"foo.*.bar"},
			needle: "foo.bar.bar.bar",
		},
		{
			name:   "ShouldNotMatchFooEmptyBarAgainstFooStarBar",
			scopes: []string{"foo.*.bar"},
			needle: "foo..bar",
		},
		{
			name:   "ShouldNotMatchFooBarEmptyBarAgainstFooStarBar",
			scopes: []string{"foo.*.bar"},
			needle: "foo.bar..bar",
		},
		{
			name:   "ShouldNotMatchTooShortAgainstSixSegmentPattern",
			scopes: []string{"foo.*.bar.*.baz.*"},
			needle: "foo.*.*",
		},
		{
			name:   "ShouldNotMatchPartialAgainstSixSegmentPattern",
			scopes: []string{"foo.*.bar.*.baz.*"},
			needle: "foo.*.bar",
		},
		{
			name:   "ShouldNotMatchTooShortAlternateAgainstSixSegmentPattern",
			scopes: []string{"foo.*.bar.*.baz.*"},
			needle: "foo.baz.*",
		},
		{
			name:   "ShouldNotMatchThreeLevelAgainstSixSegmentPattern",
			scopes: []string{"foo.*.bar.*.baz.*"},
			needle: "foo.baz.bar",
		},
		{
			name:   "ShouldNotMatchPartialStarAgainstSixSegmentPattern",
			scopes: []string{"foo.*.bar.*.baz.*"},
			needle: "foo.b*.bar",
		},
		{
			name:     "ShouldMatchExactlySixSegmentsAgainstSixSegmentPattern",
			scopes:   []string{"foo.*.bar.*.baz.*"},
			needle:   "foo.bar.bar.baz.baz.baz",
			expected: true,
		},
		{
			name:     "ShouldMatchSevenSegmentsAgainstSixSegmentPattern",
			scopes:   []string{"foo.*.bar.*.baz.*"},
			needle:   "foo.bar.bar.baz.baz.baz.baz",
			expected: true,
		},
		{
			name:   "ShouldNotMatchFiveSegmentsAgainstSixSegmentPattern",
			scopes: []string{"foo.*.bar.*.baz.*"},
			needle: "foo.bar.bar.baz.baz",
		},
		{
			name:   "ShouldNotMatchWrongLiteralAgainstSixSegmentPattern",
			scopes: []string{"foo.*.bar.*.baz.*"},
			needle: "foo.bar.baz.baz.baz.bar",
		},
		{
			name:     "ShouldMatchHydraClientsAgainstMultipleScopes",
			scopes:   strings.Fields("hydra.* openid offline  hydra"),
			needle:   "hydra.clients",
			expected: true,
		},
		{
			name:     "ShouldMatchHydraClientsGetAgainstMultipleScopes",
			scopes:   strings.Fields("hydra.* openid offline  hydra"),
			needle:   "hydra.clients.get",
			expected: true,
		},
		{
			name:     "ShouldMatchBareHydraAgainstMultipleScopes",
			scopes:   strings.Fields("hydra.* openid offline  hydra"),
			needle:   "hydra",
			expected: true,
		},
		{
			name:     "ShouldMatchOfflineAgainstMultipleScopes",
			scopes:   strings.Fields("hydra.* openid offline  hydra"),
			needle:   consts.ScopeOffline,
			expected: true,
		},
		{
			name:     "ShouldMatchOpenIDAgainstMultipleScopes",
			scopes:   strings.Fields("hydra.* openid offline  hydra"),
			needle:   consts.ScopeOpenID,
			expected: true,
		},
	}

	var strategy ScopeStrategy = WildcardScopeStrategy

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := strategy(tc.scopes, tc.needle)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestExactScopeStrategy(t *testing.T) {
	testCases := []struct {
		name     string
		scopes   []string
		needle   string
		expected bool
	}{
		{
			name:     "ShouldMatchExactThreeLevelScope",
			scopes:   []string{"foo.bar.baz", "foo.bar"},
			needle:   "foo.bar.baz",
			expected: true,
		},
		{
			name:     "ShouldMatchExactTwoLevelScope",
			scopes:   []string{"foo.bar.baz", "foo.bar"},
			needle:   "foo.bar",
			expected: true,
		},
		{
			name:   "ShouldNotMatchDeeperNeedle",
			scopes: []string{"foo.bar.baz", "foo.bar"},
			needle: "foo.bar.baz.baz",
		},
		{
			name:   "ShouldNotMatchSiblingNeedle",
			scopes: []string{"foo.bar.baz", "foo.bar"},
			needle: "foo.bar.bar",
		},
		{
			name:   "ShouldNotMatchSuffixedThreeLevelNeedle",
			scopes: []string{"foo.bar.baz", "foo.bar"},
			needle: "foo.bar.baz1",
		},
		{
			name:   "ShouldNotMatchSuffixedTwoLevelNeedle",
			scopes: []string{"foo.bar.baz", "foo.bar"},
			needle: "foo.bar1",
		},
		{
			name:   "ShouldNotMatchAgainstEmptyScopes",
			scopes: []string{},
			needle: "foo",
		},
	}

	var strategy ScopeStrategy = ExactScopeStrategy

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := strategy(tc.scopes, tc.needle)
			assert.Equal(t, tc.expected, actual)
		})
	}
}
