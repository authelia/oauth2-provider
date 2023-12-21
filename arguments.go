// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

type Arguments []string

// Matches performs an case-sensitive, out-of-order check that the items
// provided exist and equal all of the args in arguments.
func (r Arguments) Matches(items ...string) bool {
	if len(r) != len(items) {
		return false
	}

	found := make(map[string]bool)
	for _, item := range items {
		if !StringInSlice(item, r) {
			return false
		}
		found[item] = true
	}

	return len(found) == len(r)
}

// MatchesFold performs an case-insensitive, out-of-order check that the items
// provided exist and equal all of the args in arguments.
// Note:
//   - Providing a list that includes duplicate string-case items will return not
//     matched.
func (r Arguments) MatchesFold(items ...string) bool {
	if len(r) != len(items) {
		return false
	}

	found := make(map[string]bool)
	for _, item := range items {
		if !StringInSliceFold(item, r) {
			return false
		}
		found[item] = true
	}

	return len(found) == len(r)
}

// Has checks, in a case-sensitive manner, that all of the items
// provided exists in arguments.
func (r Arguments) Has(items ...string) bool {
	for _, item := range items {
		if !StringInSlice(item, r) {
			return false
		}
	}

	return true
}

// HasFold checks, in a case-insensitive manner, that all of the items
// provided exists in arguments.
func (r Arguments) HasFold(items ...string) bool {
	for _, item := range items {
		if !StringInSliceFold(item, r) {
			return false
		}
	}

	return true
}

// HasOneOf checks, in a case-sensitive manner, that one of the items
// provided exists in arguments.
func (r Arguments) HasOneOf(items ...string) bool {
	for _, item := range items {
		if StringInSlice(item, r) {
			return true
		}
	}

	return false
}

// HasOneOfFold checks, in a case-sensitive manner, that one of the items
// provided exists in arguments.
func (r Arguments) HasOneOfFold(items ...string) bool {
	for _, item := range items {
		if StringInSliceFold(item, r) {
			return true
		}
	}

	return false
}

// ExactOne checks, by string case, that a single argument equals the provided
// string.
func (r Arguments) ExactOne(name string) bool {
	return len(r) == 1 && r[0] == name
}

// MatchesExact checks, by order and string case, that the items provided equal
// those in arguments.
func (r Arguments) MatchesExact(items ...string) bool {
	if len(r) != len(items) {
		return false
	}

	for i, item := range items {
		if item != r[i] {
			return false
		}
	}

	return true
}
