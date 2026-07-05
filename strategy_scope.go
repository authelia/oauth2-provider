// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"slices"
	"strings"
)

// ScopeStrategy is a strategy for matching scopes.
type ScopeStrategy func(haystack []string, needle string) bool

// GetScopeStrategy resolves the ScopeStrategy to use for a request. If the client implements ScopeStrategyProvider
// and returns a non-nil strategy, the client's strategy is preferred over the global configuration. Otherwise the
// strategy from the provided config is used, falling back to ExactScopeStrategy when neither source supplies one.
func GetScopeStrategy(ctx context.Context, config ScopeStrategyProvider, client Client) (strategy ScopeStrategy) {
	if client != nil {
		if c, ok := client.(ScopeStrategyProvider); ok {
			strategy = c.GetScopeStrategy(ctx)
		}
	}

	if strategy == nil {
		strategy = config.GetScopeStrategy(ctx)

		if strategy == nil {
			strategy = ExactScopeStrategy
		}
	}

	return strategy
}

// HierarchicScopeStrategy is a ScopeStrategy that treats scopes as dot-delimited hierarchies, where a granted scope
// implicitly includes all of its sub-scopes. For example, granting "foo" matches a request for "foo.bar", but
// granting "foo.bar" does not match a request for "foo".
func HierarchicScopeStrategy(haystack []string, needle string) bool {
	for _, this := range haystack {
		if this == needle {
			return true
		}

		if len(this) > len(needle) {
			continue
		}

		needles := strings.Split(needle, ".")
		haystack := strings.Split(this, ".")
		haystackLen := len(haystack) - 1
		for k, needle := range needles {
			if haystackLen < k {
				return true
			}

			current := haystack[k]
			if current != needle {
				break
			}
		}
	}

	return false
}

// ExactScopeStrategy is a ScopeStrategy that requires a granted scope to match the requested scope exactly. No
// hierarchical or wildcard expansion is performed.
func ExactScopeStrategy(haystack []string, needle string) bool {
	return slices.Contains(haystack, needle)
}

// WildcardScopeStrategy is a ScopeStrategy that matches dot-delimited scopes where each granted segment may be the
// literal "*" wildcard, matching any non-empty value in the corresponding position of the requested scope. The number
// of segments in the matcher and the needle must be equal, except when the trailing matcher segment is "*", which
// also matches when the needle has additional segments.
func WildcardScopeStrategy(matchers []string, needle string) bool {
	needleParts := strings.Split(needle, ".")
	for _, matcher := range matchers {
		matcherParts := strings.Split(matcher, ".")

		if len(matcherParts) > len(needleParts) {
			continue
		}

		var noteq bool

		for k, c := range matcherParts {
			if k == len(matcherParts)-1 && len(matcherParts) != len(needleParts) {
				if c != "*" {
					noteq = true
					break
				}
			}

			if c == "*" && len(needleParts[k]) > 0 {
				continue
			} else if c != needleParts[k] {
				noteq = true
				break
			}
		}

		if !noteq {
			return true
		}
	}

	return false
}
