// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package asc

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFunctionsApply(t *testing.T) {
	clock := func() time.Time {
		return time.Date(2026, time.October, 7, 12, 0, 0, 0, time.UTC)
	}

	unavailable := struct{}{}

	testCases := []struct {
		name     string
		function string
		input    any
		args     []any
		expected any
	}{
		{name: "ShouldCountYears", function: "years_ago", input: "2000-10-07", expected: float64(26)},
		{name: "ShouldCountYearsBeforeBirthday", function: "years_ago", input: "2000-10-08", expected: float64(25)},
		{name: "ShouldCountYearsWithReferenceDate", function: "years_ago", input: "2000-01-01", args: []any{"2018-01-01"}, expected: float64(18)},
		{name: "ShouldCountYearsFromDatetime", function: "years_ago", input: "2000-10-07T23:59:59Z", expected: float64(26)},
		{name: "ShouldCountYearsFromEpoch", function: "years_ago", input: json.Number("946684800"), expected: float64(26)},
		{name: "ShouldCountYearsOverArray", function: "years_ago", input: []any{"2000-10-07", "2010-10-07"}, expected: []any{float64(26), float64(16)}},
		{name: "ShouldNotCountYearsFromYearZero", function: "years_ago", input: "0000-01-01", expected: unavailable},
		{name: "ShouldNotCountYearsFromText", function: "years_ago", input: "yesterday", expected: unavailable},
		{name: "ShouldNotCountYearsFromBoolean", function: "years_ago", input: true, expected: unavailable},

		{name: "ShouldNotCountYearsFromHugeNumber", function: "years_ago", input: json.Number("1e300"), expected: unavailable},
		{name: "ShouldNotCountYearsFromHugeNegativeNumber", function: "years_ago", input: json.Number("-1e300"), expected: unavailable},
		{name: "ShouldNotCountYearsFromNaN", function: "years_ago", input: math.NaN(), expected: unavailable},
		{name: "ShouldNotCountYearsFromInfinity", function: "years_ago", input: math.Inf(1), expected: unavailable},
		{name: "ShouldNotCountYearsPastYear9999", function: "years_ago", input: json.Number("253402300800"), expected: unavailable},
		{name: "ShouldCountYearsAtEndOfYear9999", function: "years_ago", input: json.Number("253402300799"), expected: float64(-7974)},
		{name: "ShouldCountLeapDayBeforeAnniversary", function: "years_ago", input: "2000-02-29", args: []any{"2001-02-28"}, expected: float64(0)},
		{name: "ShouldCountLeapDayAfterAnniversary", function: "years_ago", input: "2000-02-29", args: []any{"2001-03-01"}, expected: float64(1)},

		{name: "ShouldEqualString", function: "eq", input: "USA", args: []any{"USA"}, expected: true},
		{name: "ShouldNotEqualString", function: "eq", input: "DEU", args: []any{"USA"}, expected: false},
		{name: "ShouldEqualNumber", function: "eq", input: json.Number("18"), args: []any{float64(18)}, expected: true},
		{name: "ShouldEqualDatetimeNumberAndDate", function: "eq", input: json.Number("946684800"), args: []any{"2000-01-01"}, expected: true},
		{name: "ShouldNotEqualDatetimeNumberAndOtherDate", function: "eq", input: json.Number("946684800"), args: []any{"2000-01-02"}, expected: false},
		{name: "ShouldNotEqualDateAndNumber", function: "eq", input: "2000-01-01", args: []any{float64(946684800)}, expected: unavailable},
		{name: "ShouldEqualBoolean", function: "eq", input: true, args: []any{true}, expected: true},
		{name: "ShouldNotEqualStringAndNumber", function: "eq", input: "18", args: []any{float64(18)}, expected: unavailable},
		{name: "ShouldNotEqualNumberAndString", function: "eq", input: json.Number("18"), args: []any{"18"}, expected: unavailable},
		{name: "ShouldNotEqualBooleanAndString", function: "eq", input: true, args: []any{"true"}, expected: unavailable},
		{name: "ShouldNotEqualStringAndBoolean", function: "eq", input: "true", args: []any{true}, expected: unavailable},
		{name: "ShouldEqualDateAndDatetimeIgnoringTime", function: "eq", input: "2020-01-01T15:04:05Z", args: []any{"2020-01-01"}, expected: true},
		{name: "ShouldNotEqualDatetimesWithDifferentTime", function: "eq", input: "2020-01-01T15:04:05Z", args: []any{"2020-01-01T00:00:00Z"}, expected: false},
		{name: "ShouldEqualOverArray", function: "eq", input: []any{"DEU", "USA"}, args: []any{"USA"}, expected: []any{false, true}},
		{name: "ShouldNotEqualObject", function: "eq", input: map[string]any{}, args: []any{"USA"}, expected: unavailable},

		{name: "ShouldContain", function: "contains", input: "EH1 1AA", args: []any{"H1"}, expected: true},
		{name: "ShouldNotContain", function: "contains", input: "EH1 1AA", args: []any{"G1"}, expected: false},
		{name: "ShouldStartWith", function: "starts_with", input: "EH1 1AA", args: []any{"EH1"}, expected: true},
		{name: "ShouldNotStartWith", function: "starts_with", input: "EH1 1AA", args: []any{"1AA"}, expected: false},
		{name: "ShouldEndWith", function: "ends_with", input: "EH1 1AA", args: []any{"1AA"}, expected: true},
		{name: "ShouldNotEndWith", function: "ends_with", input: "EH1 1AA", args: []any{"EH1"}, expected: false},
		{name: "ShouldNotContainInNumber", function: "contains", input: json.Number("12"), args: []any{"1"}, expected: unavailable},

		{name: "ShouldCompareGreaterThan", function: "gt", input: json.Number("19"), args: []any{float64(18)}, expected: true},
		{name: "ShouldCompareGreaterThanEqualValue", function: "gt", input: json.Number("18"), args: []any{float64(18)}, expected: false},
		{name: "ShouldCompareGreaterThanOrEqual", function: "gte", input: float64(18), args: []any{float64(18)}, expected: true},
		{name: "ShouldCompareLessThan", function: "lt", input: json.Number("17"), args: []any{float64(18)}, expected: true},
		{name: "ShouldCompareLessThanOrEqual", function: "lte", input: json.Number("19"), args: []any{float64(18)}, expected: false},
		{name: "ShouldCompareDates", function: "lt", input: "1999-12-31", args: []any{"2000-01-01"}, expected: true},
		{name: "ShouldCompareDateAndDatetimeIgnoringTime", function: "gt", input: "2000-01-01T23:00:00Z", args: []any{"2000-01-01"}, expected: false},
		{name: "ShouldCompareDatetimes", function: "gt", input: "2000-01-01T23:00:00Z", args: []any{"2000-01-01T22:00:00Z"}, expected: true},
		{name: "ShouldCompareOverArray", function: "gte", input: []any{json.Number("17"), json.Number("18")}, args: []any{float64(18)}, expected: []any{false, true}},
		{name: "ShouldCompareHugeNumber", function: "gt", input: json.Number("1e300"), args: []any{float64(5)}, expected: true},
		{name: "ShouldNotCompareHugeNumberToDate", function: "lt", input: json.Number("1e300"), args: []any{"2000-01-01"}, expected: unavailable},
		{name: "ShouldNotCompareText", function: "gt", input: "abc", args: []any{float64(1)}, expected: unavailable},
		{name: "ShouldNotCompareBoolean", function: "gt", input: true, args: []any{float64(1)}, expected: unavailable},
		{name: "ShouldNotCompareDateToNumber", function: "gte", input: "2000-01-01", args: []any{float64(18)}, expected: unavailable},
		{name: "ShouldNotCompareDatetimeToNumber", function: "lt", input: "2000-01-01T00:00:00Z", args: []any{float64(946684801)}, expected: unavailable},
		{name: "ShouldCompareDatetimeNumberToDate", function: "gte", input: json.Number("946684800"), args: []any{"2000-01-01"}, expected: true},
		{name: "ShouldCompareDatetimeNumberToDatetime", function: "gt", input: json.Number("946684800"), args: []any{"2000-01-01T00:00:00Z"}, expected: false},

		{name: "ShouldHashSHA256", function: "hash", input: "Jörg", args: []any{"sha-256"}, expected: "8e63741c42f7c08025339f1a380d98030a698aa04f1fa3c595dcb581632af452"},
		{name: "ShouldHashSHA512", function: "hash", input: "", args: []any{"sha-512"}, expected: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
		{name: "ShouldNotHashNumber", function: "hash", input: json.Number("1"), args: []any{"sha-256"}, expected: unavailable},

		{name: "ShouldEvaluateAny", function: "any", input: []any{false, true}, expected: true},
		{name: "ShouldEvaluateAnyOfNone", function: "any", input: []any{false, false}, expected: false},
		{name: "ShouldEvaluateAnyOfEmpty", function: "any", input: []any{}, expected: false},
		{name: "ShouldEvaluateAll", function: "all", input: []any{true, true}, expected: true},
		{name: "ShouldEvaluateAllWithFalse", function: "all", input: []any{true, false}, expected: false},
		{name: "ShouldEvaluateAllOfEmpty", function: "all", input: []any{}, expected: true},
		{name: "ShouldEvaluateNone", function: "none", input: []any{false, false}, expected: true},
		{name: "ShouldEvaluateNoneWithTrue", function: "none", input: []any{false, true}, expected: false},
		{name: "ShouldNotEvaluateAnyOfStrings", function: "any", input: []any{"true"}, expected: unavailable},
		{name: "ShouldNotEvaluateAnyOfScalar", function: "any", input: true, expected: unavailable},

		{name: "ShouldGetMember", function: "get", input: map[string]any{"country": "GB"}, args: []any{"country"}, expected: "GB"},
		{name: "ShouldNotGetMissingMember", function: "get", input: map[string]any{"country": "GB"}, args: []any{"region"}, expected: unavailable},
		{name: "ShouldNotGetFromArray", function: "get", input: []any{map[string]any{"country": "GB"}}, args: []any{"country"}, expected: unavailable},

		{name: "ShouldMatch", function: "match", input: "peter@company.com", args: []any{`@company\.com$`}, expected: true},
		{name: "ShouldMatchAnywhere", function: "match", input: "EH1 1AA", args: []any{"H1"}, expected: true},
		{name: "ShouldNotMatch", function: "match", input: "peter@example.com", args: []any{`@company\.com$`}, expected: false},
		{name: "ShouldMatchOverArray", function: "match", input: []any{"a1", "b"}, args: []any{`\d`}, expected: []any{true, false}},
		{name: "ShouldNotMatchNumber", function: "match", input: json.Number("1"), args: []any{`\d`}, expected: unavailable},
	}

	registry := functions(clock, unlimited)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			function, ok := registry[tc.function]
			require.True(t, ok)
			require.NoError(t, function.Validate(tc.args))

			output, ok := function.Apply(t.Context(), tc.input, tc.args)

			if tc.expected == unavailable {
				assert.False(t, ok)

				return
			}

			require.True(t, ok)
			assert.Equal(t, tc.expected, output)
		})
	}
}

func TestFunctionsValidate(t *testing.T) {
	testCases := []struct {
		name     string
		function string
		args     []any
		err      string
	}{
		{name: "ShouldAcceptYearsAgoWithoutArguments", function: "years_ago"},
		{name: "ShouldAcceptYearsAgoWithDate", function: "years_ago", args: []any{"2020-01-01"}},
		{name: "ShouldRejectYearsAgoWithDatetime", function: "years_ago", args: []any{"2020-01-01T00:00:00Z"}, err: "the argument must be a date"},
		{name: "ShouldRejectYearsAgoWithNumber", function: "years_ago", args: []any{float64(2020)}, err: "the argument must be a date"},
		{name: "ShouldRejectYearsAgoWithTwoArguments", function: "years_ago", args: []any{"2020-01-01", "2021-01-01"}, err: "expected at most 1 argument"},
		{name: "ShouldAcceptEqualityWithString", function: "eq", args: []any{"USA"}},
		{name: "ShouldAcceptEqualityWithNumber", function: "eq", args: []any{float64(1)}},
		{name: "ShouldAcceptEqualityWithBoolean", function: "eq", args: []any{true}},
		{name: "ShouldRejectEqualityWithObject", function: "eq", args: []any{map[string]any{}}, err: "the argument must be a string, number or boolean"},
		{name: "ShouldRejectEqualityWithoutArguments", function: "eq", err: "expected 1 argument"},
		{name: "ShouldRejectContainsWithNumber", function: "contains", args: []any{float64(1)}, err: "the argument must be a string"},
		{name: "ShouldRejectStartsWithWithoutArguments", function: "starts_with", err: "expected 1 argument"},
		{name: "ShouldRejectEndsWithWithTwoArguments", function: "ends_with", args: []any{"a", "b"}, err: "expected 1 argument"},
		{name: "ShouldAcceptComparisonWithNumber", function: "gte", args: []any{float64(18)}},
		{name: "ShouldAcceptComparisonWithHugeNumber", function: "gt", args: []any{float64(1e300)}},
		{name: "ShouldAcceptComparisonWithDate", function: "lt", args: []any{"2020-01-01"}},
		{name: "ShouldAcceptComparisonWithDatetime", function: "gt", args: []any{"2020-01-01T00:00:00Z"}},
		{name: "ShouldRejectComparisonWithText", function: "lte", args: []any{"eighteen"}, err: "the argument must be a number, date or datetime"},
		{name: "ShouldRejectComparisonWithBoolean", function: "gt", args: []any{true}, err: "the argument must be a number, date or datetime"},
		{name: "ShouldAcceptHashSHA256", function: "hash", args: []any{"sha-256"}},
		{name: "ShouldRejectHashMD5", function: "hash", args: []any{"md5"}, err: "the argument must be 'sha-256' or 'sha-512'"},
		{name: "ShouldRejectHashWithoutArguments", function: "hash", err: "expected 1 argument"},
		{name: "ShouldAcceptAny", function: "any"},
		{name: "ShouldRejectAllWithArgument", function: "all", args: []any{true}, err: "expected no arguments"},
		{name: "ShouldRejectNoneWithArgument", function: "none", args: []any{true}, err: "expected no arguments"},
		{name: "ShouldAcceptGet", function: "get", args: []any{"country"}},
		{name: "ShouldRejectGetWithNumber", function: "get", args: []any{float64(0)}, err: "the argument must be a string"},
		{name: "ShouldAcceptMatch", function: "match", args: []any{`^\d+$`}},
		{name: "ShouldRejectMatchWithLookahead", function: "match", args: []any{`(?=a)`}, err: "the argument must be a regular expression"},
		{name: "ShouldRejectMatchWithBackreference", function: "match", args: []any{`(a)\1`}, err: "the argument must be a regular expression"},
		{name: "ShouldAcceptMatchOfMaximumLength", function: "match", args: []any{strings.Repeat("a", 1000)}},
		{name: "ShouldRejectMatchOverMaximumLength", function: "match", args: []any{strings.Repeat("a", 1001)}, err: "the argument must be a regular expression of at most 1000 bytes"},
		{name: "ShouldRejectMatchWithNumber", function: "match", args: []any{float64(1)}, err: "the argument must be a string"},
	}

	registry := functions(time.Now, unlimited)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			function, ok := registry[tc.function]
			require.True(t, ok)

			err := function.Validate(tc.args)

			if tc.err == "" {
				assert.NoError(t, err)

				return
			}

			assert.EqualError(t, err, tc.err)
		})
	}
}

func TestFunctionsApplyWithoutValidation(t *testing.T) {
	argSets := [][]any{nil, {}, {map[string]any{}}, {"a", "b", "c"}}
	inputs := []any{"text", json.Number("5"), []any{"a", "b", "c"}, nil}

	registry := functions(time.Now, unlimited)
	assert.Len(t, registry, 15)

	for name, function := range registry {
		for i, args := range argSets {
			for j, input := range inputs {
				t.Run(fmt.Sprintf("%s/%d/%d", name, i, j), func(t *testing.T) {
					var ok bool

					require.NotPanics(t, func() {
						_, ok = function.Apply(t.Context(), input, args)
					})

					if function.Validate(args) != nil {
						assert.False(t, ok)
					}
				})
			}
		}
	}
}

func TestLimitedFunction(t *testing.T) {
	expired, cancel := context.WithCancel(t.Context())
	cancel()

	release := make(chan struct{})

	t.Cleanup(func() { close(release) })

	blocked := blockingFunction{release: release}
	ready := blockingFunction{}

	testCases := []struct {
		name     string
		ctx      context.Context
		function Function
		limit    time.Duration
		expected any
	}{
		{name: "ShouldReturnOutputWithinLimit", ctx: t.Context(), function: ready, limit: time.Minute, expected: "output"},
		{name: "ShouldReturnOutputWithoutLimit", ctx: t.Context(), function: ready, limit: -1, expected: "output"},
		{name: "ShouldBeUnavailablePastLimit", ctx: t.Context(), function: blocked, limit: time.Millisecond},
		{name: "ShouldBeUnavailableWhenContextIsDone", ctx: expired, function: ready, limit: time.Minute},
		{name: "ShouldIgnoreContextWithoutLimit", ctx: expired, function: ready, limit: -1, expected: "output"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output, ok := limited{Function: tc.function, limit: func() time.Duration { return tc.limit }}.Apply(tc.ctx, "input", nil)

			assert.Equal(t, tc.expected != nil, ok)
			assert.Equal(t, tc.expected, output)
		})
	}
}

func TestMatchFunctionTimeLimit(t *testing.T) {
	var limit time.Duration

	registry := functions(time.Now, func() time.Duration { return limit })

	expired, cancel := context.WithCancel(t.Context())
	cancel()

	limit = time.Minute

	output, ok := registry["match"].Apply(t.Context(), "EH1 1AA", []any{"H1"})
	assert.True(t, ok)
	assert.Equal(t, true, output)

	_, ok = registry["match"].Apply(expired, "EH1 1AA", []any{"H1"})
	assert.False(t, ok)

	assert.EqualError(t, registry["match"].Validate([]any{"("}), "the argument must be a regular expression")
}

func TestFunctionsRegistry(t *testing.T) {
	assert.Len(t, functions(time.Now, unlimited), 15)
}

func unlimited() time.Duration {
	return -1
}

type blockingFunction struct {
	release chan struct{}
}

func (blockingFunction) Validate(_ []any) error {
	return nil
}

func (f blockingFunction) Apply(_ context.Context, _ any, _ []any) (any, bool) {
	if f.release != nil {
		<-f.release
	}

	return "output", true
}
