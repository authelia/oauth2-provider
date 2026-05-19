// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStringInSlice(t *testing.T) {
	testCases := []struct {
		name     string
		needle   string
		haystack []string
		expected bool
	}{
		{
			name:     "ShouldFindFirstElement",
			needle:   "foo",
			haystack: []string{"foo", "bar"},
			expected: true,
		},
		{
			name:     "ShouldFindLastElement",
			needle:   "bar",
			haystack: []string{"foo", "bar"},
			expected: true,
		},
		{
			name:     "ShouldNotFindMissingElement",
			needle:   "baz",
			haystack: []string{"foo", "bar"},
			expected: false,
		},
		{
			name:     "ShouldNotFindInSingleElementHaystack",
			needle:   "foo",
			haystack: []string{"bar"},
			expected: false,
		},
		{
			name:     "ShouldFindSingleElement",
			needle:   "bar",
			haystack: []string{"bar"},
			expected: true,
		},
		{
			name:     "ShouldNotFindInEmptyHaystack",
			needle:   "foo",
			haystack: []string{},
			expected: false,
		},
		{
			name:     "ShouldNotFindInNilHaystack",
			needle:   "foo",
			haystack: nil,
			expected: false,
		},
		{
			name:     "ShouldNotMatchCaseInsensitive",
			needle:   "FOO",
			haystack: []string{"foo"},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := StringInSlice(tc.needle, tc.haystack)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestStringInSliceFold(t *testing.T) {
	testCases := []struct {
		name     string
		needle   string
		haystack []string
		expected bool
	}{
		{
			name:     "ShouldFindExactMatch",
			needle:   "foo",
			haystack: []string{"foo", "bar"},
			expected: true,
		},
		{
			name:     "ShouldFindCaseInsensitiveMatch",
			needle:   "FOO",
			haystack: []string{"foo", "bar"},
			expected: true,
		},
		{
			name:     "ShouldFindMixedCaseMatch",
			needle:   "FoO",
			haystack: []string{"fOo"},
			expected: true,
		},
		{
			name:     "ShouldNotFindMissingElement",
			needle:   "baz",
			haystack: []string{"foo", "bar"},
			expected: false,
		},
		{
			name:     "ShouldNotFindInEmptyHaystack",
			needle:   "foo",
			haystack: []string{},
			expected: false,
		},
		{
			name:     "ShouldNotFindInNilHaystack",
			needle:   "foo",
			haystack: nil,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := StringInSliceFold(tc.needle, tc.haystack)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestRemoveEmpty(t *testing.T) {
	testCases := []struct {
		name     string
		args     []string
		expected []string
	}{
		{
			name:     "ShouldReturnNilForNilInput",
			args:     nil,
			expected: nil,
		},
		{
			name:     "ShouldReturnNilForEmptyInput",
			args:     []string{},
			expected: nil,
		},
		{
			name:     "ShouldFilterEmptyStrings",
			args:     []string{"foo", "", "bar"},
			expected: []string{"foo", "bar"},
		},
		{
			name:     "ShouldFilterWhitespaceOnlyStrings",
			args:     []string{"foo", "   ", "bar"},
			expected: []string{"foo", "bar"},
		},
		{
			name:     "ShouldTrimSurroundingWhitespace",
			args:     []string{"  foo  ", "\tbar\n"},
			expected: []string{"foo", "bar"},
		},
		{
			name:     "ShouldReturnNilWhenAllAreEmpty",
			args:     []string{"", "  ", "\t"},
			expected: nil,
		},
		{
			name:     "ShouldPreserveOrder",
			args:     []string{"c", "a", "b"},
			expected: []string{"c", "a", "b"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := RemoveEmpty(tc.args)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestEscapeJSONString(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "ShouldHandleEmptyString",
			input:    "",
			expected: "",
		},
		{
			name:     "ShouldNotEscapePlainText",
			input:    "foobar",
			expected: "foobar",
		},
		{
			name:     "ShouldEscapeQuotationMark",
			input:    "foo\"bar",
			expected: "foo\\\"bar",
		},
		{
			name:     "ShouldEscapeReverseSolidus",
			input:    "foo\\bar",
			expected: "foo\\\\bar",
		},
		{
			name:     "ShouldEscapeControlCharacters",
			input:    "foo\n\tbar",
			expected: "foo\\u000a\\u0009bar",
		},
		{
			name:     "ShouldEscapeNullByte",
			input:    "foo\x00bar",
			expected: "foo\\u0000bar",
		},
		{
			name:     "ShouldEscapeBackslashBeforeControlCharacters",
			input:    "\\\n",
			expected: "\\\\\\u000a",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := EscapeJSONString(tc.input)
			assert.Equal(t, tc.expected, actual)

			var unmarshaled string
			require.NoError(t, json.Unmarshal([]byte(`"`+actual+`"`), &unmarshaled))
			assert.Equal(t, tc.input, unmarshaled)
		})
	}
}

func TestDeviceAuthorizeStatusToString(t *testing.T) {
	testCases := []struct {
		name     string
		status   DeviceAuthorizeStatus
		expected string
	}{
		{
			name:     "ShouldReturnApproved",
			status:   DeviceAuthorizeStatusApproved,
			expected: "Approved",
		},
		{
			name:     "ShouldReturnDenied",
			status:   DeviceAuthorizeStatusDenied,
			expected: "Denied",
		},
		{
			name:     "ShouldReturnNew",
			status:   DeviceAuthorizeStatusNew,
			expected: "New",
		},
		{
			name:     "ShouldReturnInvalidForUnknownStatus",
			status:   DeviceAuthorizeStatus(99),
			expected: "Invalid",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := DeviceAuthorizeStatusToString(tc.status)
			assert.Equal(t, tc.expected, actual)
		})
	}
}
