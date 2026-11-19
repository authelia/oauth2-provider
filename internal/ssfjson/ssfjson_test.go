// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfjson

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseObject(t *testing.T) {
	testCases := []struct {
		name     string
		have     string
		expected map[string]json.RawMessage
		err      string
	}{
		{name: "ShouldParseEmptyObject", have: `{}`, expected: map[string]json.RawMessage{}},
		{
			name: "ShouldParseMembers",
			have: ` {"a":1,"b":"x","c":null,"d":{"a":1,"a":2}} `,
			expected: map[string]json.RawMessage{
				"a": json.RawMessage(`1`),
				"b": json.RawMessage(`"x"`),
				"c": json.RawMessage(`null`),
				"d": json.RawMessage(`{"a":1,"a":2}`),
			},
		},
		{
			name:     "ShouldKeepNamesExact",
			have:     `{"ack":1,"Ack":2}`,
			expected: map[string]json.RawMessage{"ack": json.RawMessage(`1`), "Ack": json.RawMessage(`2`)},
		},
		{name: "ShouldRejectRepeatedName", have: `{"a":1,"a":2}`, err: "a member name is repeated"},
		{name: "ShouldRejectArray", have: `[]`, err: "the value is not a JSON object"},
		{name: "ShouldRejectString", have: `"a"`, err: "the value is not a JSON object"},
		{name: "ShouldRejectNull", have: `null`, err: "the value is not a JSON object"},
		{name: "ShouldRejectEmpty", have: ``, err: "EOF"},
		{name: "ShouldRejectTruncated", have: `{"a":1`, err: "unexpected end of JSON input"},
		{name: "ShouldRejectMalformedValue", have: `{"a":x}`, err: "invalid character"},
		{name: "ShouldRejectTrailingObject", have: `{}{}`, err: "the value is followed by more data"},
		{name: "ShouldRejectTrailingData", have: `{} x`, err: "the value is followed by more data"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := ParseObject([]byte(tc.have))

			if tc.err != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.err)
				assert.Nil(t, actual)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestParseOrderedObject(t *testing.T) {
	testCases := []struct {
		name     string
		have     string
		expected []string
		err      string
	}{
		{name: "ShouldReturnNoNamesOfEmptyObject", have: `{}`},
		{name: "ShouldKeepTheOrderOfTheObject", have: `{"c":1,"a":"x","b":null,"":{}}`, expected: []string{"c", "a", "b", ""}},
		{name: "ShouldRejectRepeatedName", have: `{"a":1,"b":2,"a":3}`, err: "a member name is repeated"},
		{name: "ShouldRejectArray", have: `[]`, err: "the value is not a JSON object"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			names, members, err := ParseOrderedObject([]byte(tc.have))

			if tc.err != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.err)
				assert.Nil(t, names)
				assert.Nil(t, members)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, names)
			assert.Len(t, members, len(tc.expected))
		})
	}
}

func TestMember(t *testing.T) {
	members := map[string]json.RawMessage{
		"value": json.RawMessage(`"x"`),
		"null":  json.RawMessage(`null`),
		"empty": json.RawMessage(`""`),
	}

	testCases := []struct {
		name     string
		have     string
		expected json.RawMessage
		ok       bool
	}{
		{name: "ShouldReturnMember", have: "value", expected: json.RawMessage(`"x"`), ok: true},
		{name: "ShouldReturnEmptyStringMember", have: "empty", expected: json.RawMessage(`""`), ok: true},
		{name: "ShouldTreatNullAsAbsent", have: "null"},
		{name: "ShouldReportAbsentMember", have: "absent"},
		{name: "ShouldMatchNameExactly", have: "Value"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, ok := Member(members, tc.have)

			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.expected, actual)
		})
	}

	t.Run("ShouldReportAbsentMemberOfNilMap", func(t *testing.T) {
		actual, ok := Member(nil, "value")

		assert.False(t, ok)
		assert.Nil(t, actual)
	})
}

func TestParseString(t *testing.T) {
	testCases := []struct {
		name     string
		have     string
		expected string
		ok       bool
	}{
		{name: "ShouldParseString", have: `"abc"`, expected: "abc", ok: true},
		{name: "ShouldParseEmptyString", have: `""`, ok: true},
		{name: "ShouldParseEscapes", have: `"ab\n"`, expected: "ab\n", ok: true},
		{name: "ShouldRejectNull", have: `null`},
		{name: "ShouldRejectNumber", have: `1`},
		{name: "ShouldRejectBoolean", have: `true`},
		{name: "ShouldRejectObject", have: `{}`},
		{name: "ShouldRejectArray", have: `["a"]`},
		{name: "ShouldRejectUnterminatedString", have: `"abc`},
		{name: "ShouldRejectEmpty", have: ``},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, ok := ParseString(json.RawMessage(tc.have))

			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestIsNumber(t *testing.T) {
	testCases := []struct {
		name     string
		have     string
		expected bool
	}{
		{name: "ShouldAcceptInteger", have: `10`, expected: true},
		{name: "ShouldAcceptZero", have: `0`, expected: true},
		{name: "ShouldAcceptNegative", have: `-1`, expected: true},
		{name: "ShouldAcceptFraction", have: `1.5`, expected: true},
		{name: "ShouldRejectString", have: `"1"`},
		{name: "ShouldRejectNull", have: `null`},
		{name: "ShouldRejectBoolean", have: `true`},
		{name: "ShouldRejectObject", have: `{}`},
		{name: "ShouldRejectEmpty", have: ``},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, IsNumber(json.RawMessage(tc.have)))
		})
	}
}

func TestRetryAfter(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)

	testCases := []struct {
		name     string
		have     string
		expected time.Duration
	}{
		{name: "ShouldParseSeconds", have: "30", expected: 30 * time.Second},
		{name: "ShouldParseSecondsWithSurroundingSpace", have: " 30 ", expected: 30 * time.Second},
		{name: "ShouldParseZeroSeconds", have: "0"},
		{name: "ShouldParseBound", have: "300", expected: MaxRetryAfter},
		{name: "ShouldCapSeconds", have: "301", expected: MaxRetryAfter},
		{name: "ShouldCapSecondsBeyondInt64", have: "9223372036854775808", expected: MaxRetryAfter},
		{name: "ShouldCapSecondsBeyondUint64", have: "18446744073709551616", expected: MaxRetryAfter},
		{name: "ShouldIgnoreEmpty", have: ""},
		{name: "ShouldIgnoreSpace", have: "  "},
		{name: "ShouldIgnoreNegativeSeconds", have: "-30"},
		{name: "ShouldIgnoreNegativeSecondsBeyondInt64", have: "-9223372036854775809"},
		{name: "ShouldIgnoreSignedSeconds", have: "+30"},
		{name: "ShouldIgnoreSignedSecondsBeyondInt64", have: "+9223372036854775808"},
		{name: "ShouldIgnoreFraction", have: "1.5"},
		{name: "ShouldIgnoreNonASCIIDigits", have: "٣٠"},
		{name: "ShouldIgnoreWord", have: "soon"},
		{name: "ShouldParseDate", have: now.Add(time.Minute).Format(http.TimeFormat), expected: time.Minute},
		{name: "ShouldCapDate", have: now.Add(time.Hour).Format(http.TimeFormat), expected: MaxRetryAfter},
		{name: "ShouldIgnorePastDate", have: now.Add(-time.Minute).Format(http.TimeFormat)},
		{name: "ShouldIgnoreCurrentDate", have: now.Format(http.TimeFormat)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, RetryAfter(tc.have, now))
		})
	}
}
