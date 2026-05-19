// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestArgumentsExactOne(t *testing.T) {
	testCases := []struct {
		name     string
		args     Arguments
		exact    string
		expected bool
	}{
		{
			name:     "ShouldMatchSingleElement",
			args:     Arguments{"foo"},
			exact:    "foo",
			expected: true,
		},
		{
			name:     "ShouldNotMatchFirstOfMultiple",
			args:     Arguments{"foo", "bar"},
			exact:    "foo",
			expected: false,
		},
		{
			name:     "ShouldNotMatchSecondOfMultiple",
			args:     Arguments{"foo", "bar"},
			exact:    "bar",
			expected: false,
		},
		{
			name:     "ShouldNotMatchMissingValue",
			args:     Arguments{"foo", "bar"},
			exact:    "baz",
			expected: false,
		},
		{
			name:     "ShouldNotMatchEmptyArguments",
			args:     Arguments{},
			exact:    "baz",
			expected: false,
		},
		{
			name:     "ShouldNotMatchConcatenatedString",
			args:     Arguments{"foo", "bar"},
			exact:    "foo bar",
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.args.ExactOne(tc.exact)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestArgumentsHas(t *testing.T) {
	testCases := []struct {
		name     string
		args     Arguments
		has      []string
		expected bool
	}{
		{
			name:     "ShouldMatchAllSameOrder",
			args:     Arguments{"foo", "bar"},
			has:      []string{"foo", "bar"},
			expected: true,
		},
		{
			name:     "ShouldMatchAllOutOfOrder",
			args:     Arguments{"foo", "bar"},
			has:      []string{"bar", "foo"},
			expected: true,
		},
		{
			name:     "ShouldMatchSubset",
			args:     Arguments{"bar", "foo"},
			has:      []string{"foo"},
			expected: true,
		},
		{
			name:     "ShouldNotMatchWithExtra",
			args:     Arguments{"foo", "bar"},
			has:      []string{"bar", "foo", "baz"},
			expected: false,
		},
		{
			name:     "ShouldMatchSingleFirst",
			args:     Arguments{"foo", "bar"},
			has:      []string{"foo"},
			expected: true,
		},
		{
			name:     "ShouldMatchSingleSecond",
			args:     Arguments{"foo", "bar"},
			has:      []string{"bar"},
			expected: true,
		},
		{
			name:     "ShouldNotMatchMissing",
			args:     Arguments{"foo", "bar"},
			has:      []string{"baz"},
			expected: false,
		},
		{
			name:     "ShouldNotMatchEmptyArguments",
			args:     Arguments{},
			has:      []string{"baz"},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.args.Has(tc.has...)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestArgumentsHasFold(t *testing.T) {
	testCases := []struct {
		name     string
		args     Arguments
		has      []string
		expected bool
	}{
		{
			name:     "ShouldMatchExactCase",
			args:     Arguments{"foo", "bar"},
			has:      []string{"foo", "bar"},
			expected: true,
		},
		{
			name:     "ShouldMatchDifferentCase",
			args:     Arguments{"foo", "bar"},
			has:      []string{"FOO", "BAR"},
			expected: true,
		},
		{
			name:     "ShouldMatchMixedCase",
			args:     Arguments{"fOo", "bAr"},
			has:      []string{"FoO", "BaR"},
			expected: true,
		},
		{
			name:     "ShouldNotMatchMissing",
			args:     Arguments{"foo"},
			has:      []string{"BAZ"},
			expected: false,
		},
		{
			name:     "ShouldNotMatchEmpty",
			args:     Arguments{},
			has:      []string{"foo"},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.args.HasFold(tc.has...)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestArgumentsMatches(t *testing.T) {
	testCases := []struct {
		name     string
		args     Arguments
		is       []string
		expected bool
	}{
		{
			name:     "ShouldMatchEmpty",
			args:     Arguments{},
			is:       []string{},
			expected: true,
		},
		{
			name:     "ShouldMatchSameOrder",
			args:     Arguments{"foo", "bar"},
			is:       []string{"foo", "bar"},
			expected: true,
		},
		{
			name:     "ShouldMatchSameOrderMixedCaseExact",
			args:     Arguments{"Foo", "Bar"},
			is:       []string{"Foo", "Bar"},
			expected: true,
		},
		{
			name:     "ShouldNotMatchDifferentLength",
			args:     Arguments{"foo", "foo"},
			is:       []string{"foo"},
			expected: false,
		},
		{
			name:     "ShouldNotMatchSameLengthDifferentValues",
			args:     Arguments{"foo", "foo"},
			is:       []string{"bar", "foo"},
			expected: false,
		},
		{
			name:     "ShouldNotMatchExtraValue",
			args:     Arguments{"foo", "bar"},
			is:       []string{"bar", "foo", "baz"},
			expected: false,
		},
		{
			name:     "ShouldNotMatchSubset",
			args:     Arguments{"foo", "bar"},
			is:       []string{"foo"},
			expected: false,
		},
		{
			name:     "ShouldNotMatchDuplicatesInQuery",
			args:     Arguments{"foo", "bar"},
			is:       []string{"bar", "bar"},
			expected: false,
		},
		{
			name:     "ShouldNotMatchSingleMissing",
			args:     Arguments{"foo", "bar"},
			is:       []string{"baz"},
			expected: false,
		},
		{
			name:     "ShouldNotMatchEmptyArguments",
			args:     Arguments{},
			is:       []string{"baz"},
			expected: false,
		},
		{
			name:     "ShouldMatchOutOfOrder",
			args:     Arguments{"foo", "bar"},
			is:       []string{"bar", "foo"},
			expected: true,
		},
		{
			name:     "ShouldNotMatchDifferentCase",
			args:     Arguments{"fOo", "bar"},
			is:       []string{"foo", "BaR"},
			expected: false,
		},
		{
			name:     "ShouldNotMatchDuplicatesWithDifferentCase",
			args:     Arguments{"foo", "bar"},
			is:       []string{"FOO", "FOO", "bar"},
			expected: false,
		},
		{
			name:     "ShouldNotMatchDuplicatesIdentical",
			args:     Arguments{"foo", "foo"},
			is:       []string{"foo", "foo"},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.args.Matches(tc.is...)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestArgumentsMatchesFold(t *testing.T) {
	testCases := []struct {
		name     string
		args     Arguments
		is       []string
		expected bool
	}{
		{
			name:     "ShouldMatchEmpty",
			args:     Arguments{},
			is:       []string{},
			expected: true,
		},
		{
			name:     "ShouldMatchSameCase",
			args:     Arguments{"foo", "bar"},
			is:       []string{"foo", "bar"},
			expected: true,
		},
		{
			name:     "ShouldMatchDifferentCase",
			args:     Arguments{"foo", "bar"},
			is:       []string{"FOO", "BAR"},
			expected: true,
		},
		{
			name:     "ShouldMatchOutOfOrderDifferentCase",
			args:     Arguments{"foo", "bar"},
			is:       []string{"BAR", "FOO"},
			expected: true,
		},
		{
			name:     "ShouldNotMatchDifferentLength",
			args:     Arguments{"foo", "bar"},
			is:       []string{"foo"},
			expected: false,
		},
		{
			name:     "ShouldNotMatchMissingValue",
			args:     Arguments{"foo", "bar"},
			is:       []string{"foo", "baz"},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.args.MatchesFold(tc.is...)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestArgumentsMatchesExact(t *testing.T) {
	testCases := []struct {
		name     string
		args     Arguments
		is       []string
		expected bool
	}{
		{
			name:     "ShouldMatchEmpty",
			args:     Arguments{},
			is:       []string{},
			expected: true,
		},
		{
			name:     "ShouldMatchSameOrder",
			args:     Arguments{"foo", "bar"},
			is:       []string{"foo", "bar"},
			expected: true,
		},
		{
			name:     "ShouldMatchSameOrderMixedCase",
			args:     Arguments{"Foo", "Bar"},
			is:       []string{"Foo", "Bar"},
			expected: true,
		},
		{
			name:     "ShouldNotMatchDifferentLength",
			args:     Arguments{"foo", "foo"},
			is:       []string{"foo"},
			expected: false,
		},
		{
			name:     "ShouldNotMatchSameLengthDifferentValues",
			args:     Arguments{"foo", "foo"},
			is:       []string{"bar", "foo"},
			expected: false,
		},
		{
			name:     "ShouldNotMatchExtraValue",
			args:     Arguments{"foo", "bar"},
			is:       []string{"bar", "foo", "baz"},
			expected: false,
		},
		{
			name:     "ShouldNotMatchSubset",
			args:     Arguments{"foo", "bar"},
			is:       []string{"foo"},
			expected: false,
		},
		{
			name:     "ShouldNotMatchDuplicatesInQuery",
			args:     Arguments{"foo", "bar"},
			is:       []string{"bar", "bar"},
			expected: false,
		},
		{
			name:     "ShouldNotMatchSingleMissing",
			args:     Arguments{"foo", "bar"},
			is:       []string{"baz"},
			expected: false,
		},
		{
			name:     "ShouldNotMatchEmptyArguments",
			args:     Arguments{},
			is:       []string{"baz"},
			expected: false,
		},
		{
			name:     "ShouldNotMatchOutOfOrder",
			args:     Arguments{"foo", "bar"},
			is:       []string{"bar", "foo"},
			expected: false,
		},
		{
			name:     "ShouldNotMatchDifferentCase",
			args:     Arguments{"fOo", "bar"},
			is:       []string{"foo", "BaR"},
			expected: false,
		},
		{
			name:     "ShouldMatchDuplicatesIdentical",
			args:     Arguments{"foo", "foo"},
			is:       []string{"foo", "foo"},
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.args.MatchesExact(tc.is...)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestArgumentsHasOneOf(t *testing.T) {
	testCases := []struct {
		name     string
		args     Arguments
		oneOf    []string
		expected bool
	}{
		{
			name:     "ShouldMatchSecondElement",
			args:     Arguments{"baz", "bar"},
			oneOf:    []string{"foo", "bar"},
			expected: true,
		},
		{
			name:     "ShouldMatchFirstElement",
			args:     Arguments{"foo", "baz"},
			oneOf:    []string{"foo", "bar"},
			expected: true,
		},
		{
			name:     "ShouldNotMatchNoOverlap",
			args:     Arguments{"baz"},
			oneOf:    []string{"foo", "bar"},
			expected: false,
		},
		{
			name:     "ShouldNotMatchEmpty",
			args:     Arguments{},
			oneOf:    []string{"foo"},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.args.HasOneOf(tc.oneOf...)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestArgumentsHasOneOfFold(t *testing.T) {
	testCases := []struct {
		name     string
		args     Arguments
		oneOf    []string
		expected bool
	}{
		{
			name:     "ShouldMatchExactCase",
			args:     Arguments{"foo", "bar"},
			oneOf:    []string{"bar"},
			expected: true,
		},
		{
			name:     "ShouldMatchDifferentCase",
			args:     Arguments{"foo", "bar"},
			oneOf:    []string{"BAR"},
			expected: true,
		},
		{
			name:     "ShouldNotMatchNoOverlap",
			args:     Arguments{"baz"},
			oneOf:    []string{"FOO", "BAR"},
			expected: false,
		},
		{
			name:     "ShouldNotMatchEmptyArguments",
			args:     Arguments{},
			oneOf:    []string{"foo"},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.args.HasOneOfFold(tc.oneOf...)
			assert.Equal(t, tc.expected, actual)
		})
	}
}
