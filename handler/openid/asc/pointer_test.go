// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package asc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePointer(t *testing.T) {
	testCases := []struct {
		name     string
		pointer  string
		expected []string
		invalid  bool
	}{
		{name: "ShouldParseWholeDocument", pointer: ""},
		{name: "ShouldParseSingleToken", pointer: "/email", expected: []string{"email"}},
		{name: "ShouldParseNestedTokens", pointer: "/verified_claims/claims/:adult", expected: []string{"verified_claims", "claims", ":adult"}},
		{name: "ShouldParseEmptyToken", pointer: "/", expected: []string{""}},
		{name: "ShouldUnescapeTilde", pointer: "/a~0b", expected: []string{"a~b"}},
		{name: "ShouldUnescapeSlash", pointer: "/a~1b", expected: []string{"a/b"}},
		{name: "ShouldUnescapeInOrder", pointer: "/~01", expected: []string{"~1"}},
		{name: "ShouldRejectMissingLeadingSlash", pointer: "email", invalid: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tokens, ok := parsePointer(tc.pointer)

			assert.Equal(t, !tc.invalid, ok)
			assert.Equal(t, tc.expected, tokens)
		})
	}
}

func TestResolve(t *testing.T) {
	document := map[string]any{
		"email":   "peter@example.com",
		"address": map[string]any{"postal_code": "EH1 1AA"},
		"list":    []any{"a", map[string]any{"b": true}},
		"null":    nil,
	}

	testCases := []struct {
		name     string
		pointer  string
		expected any
		missing  bool
	}{
		{name: "ShouldResolveWholeDocument", pointer: "", expected: document},
		{name: "ShouldResolveMember", pointer: "/email", expected: "peter@example.com"},
		{name: "ShouldResolveNestedMember", pointer: "/address/postal_code", expected: "EH1 1AA"},
		{name: "ShouldResolveArrayElement", pointer: "/list/0", expected: "a"},
		{name: "ShouldResolveThroughArray", pointer: "/list/1/b", expected: true},
		{name: "ShouldResolveNullMember", pointer: "/null", expected: nil},
		{name: "ShouldNotResolveMissingMember", pointer: "/phone", missing: true},
		{name: "ShouldNotResolveThroughScalar", pointer: "/email/domain", missing: true},
		{name: "ShouldNotResolveIndexOutOfRange", pointer: "/list/2", missing: true},
		{name: "ShouldNotResolveNegativeIndex", pointer: "/list/-1", missing: true},
		{name: "ShouldNotResolveLeadingZeroIndex", pointer: "/list/01", missing: true},
		{name: "ShouldNotResolveNonNumericIndex", pointer: "/list/first", missing: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tokens, ok := parsePointer(tc.pointer)
			require.True(t, ok)

			value, ok := resolve(document, tokens)

			assert.Equal(t, !tc.missing, ok)
			assert.Equal(t, tc.expected, value)
		})
	}
}

func TestOmit(t *testing.T) {
	testCases := []struct {
		name     string
		pointers []string
		expected map[string]any
	}{
		{name: "ShouldOmitMember", pointers: []string{"/email"}, expected: map[string]any{"address": map[string]any{"postal_code": "EH1 1AA", "country": "GB"}, "list": []any{"a", "b", "c"}}},
		{name: "ShouldOmitNestedMember", pointers: []string{"/address/postal_code"}, expected: map[string]any{"email": "peter@example.com", "address": map[string]any{"country": "GB"}, "list": []any{"a", "b", "c"}}},
		{name: "ShouldOmitArrayElement", pointers: []string{"/list/1"}, expected: map[string]any{"email": "peter@example.com", "address": map[string]any{"postal_code": "EH1 1AA", "country": "GB"}, "list": []any{"a", "c"}}},
		{name: "ShouldOmitSeveralArrayElementsInAscendingOrder", pointers: []string{"/list/0", "/list/1"}, expected: map[string]any{"email": "peter@example.com", "address": map[string]any{"postal_code": "EH1 1AA", "country": "GB"}, "list": []any{"c"}}},
		{name: "ShouldOmitSeveralArrayElementsInDescendingOrder", pointers: []string{"/list/2", "/list/0"}, expected: map[string]any{"email": "peter@example.com", "address": map[string]any{"postal_code": "EH1 1AA", "country": "GB"}, "list": []any{"b"}}},
		{name: "ShouldOmitEveryArrayElement", pointers: []string{"/list/0", "/list/1", "/list/2"}, expected: map[string]any{"email": "peter@example.com", "address": map[string]any{"postal_code": "EH1 1AA", "country": "GB"}, "list": []any{}}},
		{name: "ShouldOmitTheSameArrayElementOnce", pointers: []string{"/list/0", "/list/0"}, expected: map[string]any{"email": "peter@example.com", "address": map[string]any{"postal_code": "EH1 1AA", "country": "GB"}, "list": []any{"b", "c"}}},
		{name: "ShouldIgnoreMissingMember", pointers: []string{"/phone"}, expected: map[string]any{"email": "peter@example.com", "address": map[string]any{"postal_code": "EH1 1AA", "country": "GB"}, "list": []any{"a", "b", "c"}}},
		{name: "ShouldIgnoreMissingParent", pointers: []string{"/phone/number"}, expected: map[string]any{"email": "peter@example.com", "address": map[string]any{"postal_code": "EH1 1AA", "country": "GB"}, "list": []any{"a", "b", "c"}}},
		{name: "ShouldIgnoreIndexOutOfRange", pointers: []string{"/list/3"}, expected: map[string]any{"email": "peter@example.com", "address": map[string]any{"postal_code": "EH1 1AA", "country": "GB"}, "list": []any{"a", "b", "c"}}},
		{name: "ShouldIgnoreWholeDocument", pointers: []string{""}, expected: map[string]any{"email": "peter@example.com", "address": map[string]any{"postal_code": "EH1 1AA", "country": "GB"}, "list": []any{"a", "b", "c"}}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			document := map[string]any{
				"email":   "peter@example.com",
				"address": map[string]any{"postal_code": "EH1 1AA", "country": "GB"},
				"list":    []any{"a", "b", "c"},
			}

			for _, pointer := range tc.pointers {
				tokens, ok := parsePointer(pointer)
				require.True(t, ok)

				omit(document, tokens)
			}

			assert.Equal(t, tc.expected, compact(document))
		})
	}
}

func TestResolveOmittedArrayElement(t *testing.T) {
	document := map[string]any{"list": []any{"a", map[string]any{"b": true}, "c"}}

	omit(document, []string{"list", "1"})

	testCases := []struct {
		name     string
		tokens   []string
		expected any
		missing  bool
	}{
		{name: "ShouldNotResolveOmittedElement", tokens: []string{"list", "1"}, missing: true},
		{name: "ShouldNotResolveBelowOmittedElement", tokens: []string{"list", "1", "b"}, missing: true},
		{name: "ShouldResolveLaterElementByItsOriginalIndex", tokens: []string{"list", "2"}, expected: "c"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			value, ok := resolve(document, tc.tokens)

			assert.Equal(t, !tc.missing, ok)
			assert.Equal(t, tc.expected, value)
		})
	}
}
