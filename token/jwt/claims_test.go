// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToString(t *testing.T) {
	testCases := []struct {
		name     string
		have     any
		expected string
	}{
		{
			name:     "ShouldReturnStringFromString",
			have:     "foo",
			expected: "foo",
		},
		{
			name:     "ShouldReturnFirstElementFromStringSlice",
			have:     []string{"foo"},
			expected: "foo",
		},
		{
			name:     "ShouldReturnEmptyForInt",
			have:     1234,
			expected: "",
		},
		{
			name:     "ShouldReturnEmptyForNil",
			have:     nil,
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, ToString(tc.have))
		})
	}
}

func TestToTime(t *testing.T) {
	now := time.Now().UTC().Truncate(TimePrecision)

	testCases := []struct {
		name     string
		have     any
		expected time.Time
	}{
		{
			name:     "ShouldReturnZeroFromNil",
			have:     nil,
			expected: time.Time{},
		},
		{
			name:     "ShouldReturnZeroFromString",
			have:     "1234",
			expected: time.Time{},
		},
		{
			name:     "ShouldReturnSameTime",
			have:     now,
			expected: now,
		},
		{
			name:     "ShouldReturnFromUnixInt64",
			have:     now.Unix(),
			expected: now,
		},
		{
			name:     "ShouldReturnFromUnixFloat64",
			have:     float64(now.Unix()),
			expected: now,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, ToTime(tc.have))
		})
	}
}

func TestToStringSlice(t *testing.T) {
	testCases := []struct {
		name     string
		have     any
		expected []string
		ok       bool
	}{
		{
			name:     "ShouldReturnTrueForNil",
			have:     nil,
			expected: nil,
			ok:       true,
		},
		{
			name:     "ShouldReturnSingleStringSlice",
			have:     "foo",
			expected: []string{"foo"},
			ok:       true,
		},
		{
			name:     "ShouldReturnStringSliceAsIs",
			have:     []string{"foo", "bar"},
			expected: []string{"foo", "bar"},
			ok:       true,
		},
		{
			name:     "ShouldReturnAnySliceOfStrings",
			have:     []any{"foo", "bar"},
			expected: []string{"foo", "bar"},
			ok:       true,
		},
		{
			name:     "ShouldFailAnySliceContainingNonString",
			have:     []any{"foo", 1},
			expected: []string{"foo"},
			ok:       false,
		},
		{
			name:     "ShouldFailForUnsupportedType",
			have:     123,
			expected: nil,
			ok:       false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, ok := toStringSlice(tc.have)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestToInt64(t *testing.T) {
	testCases := []struct {
		name     string
		have     any
		expected int64
		ok       bool
	}{
		{
			name:     "ShouldConvertFloat64",
			have:     float64(123.7),
			expected: 123,
			ok:       true,
		},
		{
			name:     "ShouldConvertInt64",
			have:     int64(123),
			expected: 123,
			ok:       true,
		},
		{
			name:     "ShouldConvertInt32",
			have:     int32(123),
			expected: 123,
			ok:       true,
		},
		{
			name:     "ShouldConvertInt",
			have:     int(123),
			expected: 123,
			ok:       true,
		},
		{
			name:     "ShouldConvertJSONNumberInt",
			have:     json.Number("456"),
			expected: 456,
			ok:       true,
		},
		{
			name:     "ShouldConvertJSONNumberFloat",
			have:     json.Number("456.7"),
			expected: 456,
			ok:       true,
		},
		{
			name:     "ShouldFailJSONNumberInvalid",
			have:     json.Number("not-a-number"),
			expected: 0,
			ok:       false,
		},
		{
			name:     "ShouldFailUnsupportedType",
			have:     "string",
			expected: 0,
			ok:       false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, ok := toInt64(tc.have)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestToNumericDate(t *testing.T) {
	testCases := []struct {
		name     string
		have     any
		expected *NumericDate
		errType  error
	}{
		{
			name:     "ShouldReturnNilForNil",
			have:     nil,
			expected: nil,
		},
		{
			name:     "ShouldReturnNilForZeroFloat64",
			have:     float64(0),
			expected: nil,
		},
		{
			name:     "ShouldReturnDateForFloat64",
			have:     float64(1700000000),
			expected: NewNumericDate(time.Unix(1700000000, 0)),
		},
		{
			name:     "ShouldReturnNilForZeroInt64",
			have:     int64(0),
			expected: nil,
		},
		{
			name:     "ShouldReturnDateForInt64",
			have:     int64(1700000000),
			expected: NewNumericDate(time.Unix(1700000000, 0)),
		},
		{
			name:     "ShouldReturnNilForZeroInt32",
			have:     int32(0),
			expected: nil,
		},
		{
			name:     "ShouldReturnDateForInt32",
			have:     int32(1700000000),
			expected: NewNumericDate(time.Unix(1700000000, 0)),
		},
		{
			name:     "ShouldReturnNilForZeroInt",
			have:     int(0),
			expected: nil,
		},
		{
			name:     "ShouldReturnDateForInt",
			have:     int(1700000000),
			expected: NewNumericDate(time.Unix(1700000000, 0)),
		},
		{
			name:     "ShouldReturnDateForJSONNumber",
			have:     json.Number("1700000000"),
			expected: NewNumericDate(time.Unix(1700000000, 0)),
		},
		{
			name:    "ShouldErrorForUnsupportedType",
			have:    "string",
			errType: ErrInvalidType,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := toNumericDate(tc.have)

			if tc.errType != nil {
				require.Error(t, err)
				assert.True(t, errors.Is(err, tc.errType))
				assert.Nil(t, actual)

				return
			}

			require.NoError(t, err)

			if tc.expected == nil {
				assert.Nil(t, actual)

				return
			}

			require.NotNil(t, actual)
			assert.Equal(t, tc.expected.Unix(), actual.Unix())
		})
	}
}

func TestNumericDate_MarshalJSON(t *testing.T) {
	testCases := []struct {
		name      string
		input     time.Time
		precision time.Duration
		expected  string
	}{
		{
			name:      "ShouldEncodeUnixSeconds",
			input:     time.Unix(1700000000, 0),
			precision: time.Second,
			expected:  "1700000000",
		},
		{
			name:      "ShouldEncodeZeroEpoch",
			input:     time.Unix(0, 0),
			precision: time.Second,
			expected:  "0",
		},
		{
			name:      "ShouldEncodeWithSubSecondPrecision",
			input:     time.Unix(1700000000, 500000000),
			precision: time.Millisecond,
			expected:  "1700000000.500",
		},
	}

	original := TimePrecision
	t.Cleanup(func() { TimePrecision = original })

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			TimePrecision = tc.precision

			b, err := NewNumericDate(tc.input).MarshalJSON()
			require.NoError(t, err)
			assert.Equal(t, tc.expected, string(b))
		})
	}
}

func TestNumericDate_UnmarshalJSON(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected int64
		wantErr  string
	}{
		{
			name:     "ShouldDecodeUnixSeconds",
			input:    "1700000000",
			expected: 1700000000,
		},
		{
			name:     "ShouldDecodeFloatSeconds",
			input:    "1700000000.5",
			expected: 1700000000,
		},
		{
			name:    "ShouldErrorOnInvalidJSON",
			input:   "not-json",
			wantErr: "could not parse NumericDate",
		},
		{
			name:    "ShouldErrorOnNonNumericValue",
			input:   `"not-a-number"`,
			wantErr: "could not parse NumericDate",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var d NumericDate

			err := d.UnmarshalJSON([]byte(tc.input))

			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, d.Unix())
		})
	}
}

func TestNumericDate_Int64(t *testing.T) {
	testCases := []struct {
		name     string
		date     *NumericDate
		expected int64
	}{
		{
			name:     "ShouldReturnZeroForNilReceiver",
			date:     nil,
			expected: 0,
		},
		{
			name:     "ShouldReturnUnixSeconds",
			date:     NewNumericDate(time.Unix(1700000000, 0)),
			expected: 1700000000,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.date.Int64())
		})
	}
}

func TestClaimStrings_Valid(t *testing.T) {
	testCases := []struct {
		name     string
		strings  ClaimStrings
		cmp      string
		required bool
		expected bool
	}{
		{
			name:     "ShouldPassWhenEmptyAndNotRequired",
			strings:  ClaimStrings{},
			cmp:      "foo",
			required: false,
			expected: true,
		},
		{
			name:     "ShouldFailWhenEmptyAndRequired",
			strings:  ClaimStrings{},
			cmp:      "foo",
			required: true,
			expected: false,
		},
		{
			name:     "ShouldMatchExistingValue",
			strings:  ClaimStrings{"foo", "bar"},
			cmp:      "bar",
			required: true,
			expected: true,
		},
		{
			name:     "ShouldFailOnNoMatch",
			strings:  ClaimStrings{"foo", "bar"},
			cmp:      "baz",
			required: true,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.strings.Valid(tc.cmp, tc.required))
		})
	}
}

func TestClaimStrings_ValidAny(t *testing.T) {
	testCases := []struct {
		name     string
		strings  ClaimStrings
		cmp      ClaimStrings
		required bool
		expected bool
	}{
		{
			name:     "ShouldPassWhenEmptyAndNotRequired",
			strings:  ClaimStrings{},
			cmp:      ClaimStrings{"foo"},
			required: false,
			expected: true,
		},
		{
			name:     "ShouldFailWhenEmptyAndRequired",
			strings:  ClaimStrings{},
			cmp:      ClaimStrings{"foo"},
			required: true,
			expected: false,
		},
		{
			name:     "ShouldPassOnAnyMatch",
			strings:  ClaimStrings{"foo", "bar"},
			cmp:      ClaimStrings{"baz", "bar"},
			required: true,
			expected: true,
		},
		{
			name:     "ShouldFailOnNoMatch",
			strings:  ClaimStrings{"foo", "bar"},
			cmp:      ClaimStrings{"baz"},
			required: true,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.strings.ValidAny(tc.cmp, tc.required))
		})
	}
}

func TestClaimStrings_ValidAll(t *testing.T) {
	testCases := []struct {
		name     string
		strings  ClaimStrings
		cmp      ClaimStrings
		required bool
		expected bool
	}{
		{
			name:     "ShouldPassWhenEmptyAndNotRequired",
			strings:  ClaimStrings{},
			cmp:      ClaimStrings{"foo"},
			required: false,
			expected: true,
		},
		{
			name:     "ShouldFailWhenEmptyAndRequired",
			strings:  ClaimStrings{},
			cmp:      ClaimStrings{"foo"},
			required: true,
			expected: false,
		},
		{
			name:     "ShouldPassWhenAllMatch",
			strings:  ClaimStrings{"foo", "bar"},
			cmp:      ClaimStrings{"foo", "bar"},
			required: true,
			expected: true,
		},
		{
			name:     "ShouldFailWhenOneMissing",
			strings:  ClaimStrings{"foo"},
			cmp:      ClaimStrings{"foo", "bar"},
			required: true,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.strings.ValidAll(tc.cmp, tc.required))
		})
	}
}

func TestClaimStrings_UnmarshalJSON(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected ClaimStrings
		wantErr  error
	}{
		{
			name:     "ShouldDecodeSingleString",
			input:    `"foo"`,
			expected: ClaimStrings{"foo"},
		},
		{
			name:     "ShouldDecodeArrayOfStrings",
			input:    `["foo","bar"]`,
			expected: ClaimStrings{"foo", "bar"},
		},
		{
			name:     "ShouldDecodeNullToNil",
			input:    `null`,
			expected: nil,
		},
		{
			name:    "ShouldErrorOnArrayWithNonString",
			input:   `["foo",1]`,
			wantErr: ErrInvalidType,
		},
		{
			name:    "ShouldErrorOnNumberInput",
			input:   `123`,
			wantErr: ErrInvalidType,
		},
		{
			name:    "ShouldErrorOnInvalidJSON",
			input:   `not-json`,
			wantErr: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var s ClaimStrings

			err := s.UnmarshalJSON([]byte(tc.input))

			if tc.name == "ShouldErrorOnInvalidJSON" {
				require.Error(t, err)
				return
			}

			if tc.wantErr != nil {
				require.Error(t, err)
				assert.True(t, errors.Is(err, tc.wantErr))

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, s)
		})
	}
}

func TestClaimStrings_MarshalJSON(t *testing.T) {
	testCases := []struct {
		name          string
		strings       ClaimStrings
		singleAsArray bool
		expected      string
	}{
		{
			name:          "ShouldEncodeSingleAsScalarWhenSingleAsArrayDisabled",
			strings:       ClaimStrings{"foo"},
			singleAsArray: false,
			expected:      `"foo"`,
		},
		{
			name:          "ShouldEncodeSingleAsArrayWhenSingleAsArrayEnabled",
			strings:       ClaimStrings{"foo"},
			singleAsArray: true,
			expected:      `["foo"]`,
		},
		{
			name:          "ShouldEncodeMultipleAsArray",
			strings:       ClaimStrings{"foo", "bar"},
			singleAsArray: false,
			expected:      `["foo","bar"]`,
		},
	}

	original := MarshalSingleStringAsArray
	t.Cleanup(func() { MarshalSingleStringAsArray = original })

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			MarshalSingleStringAsArray = tc.singleAsArray

			b, err := tc.strings.MarshalJSON()
			require.NoError(t, err)
			assert.Equal(t, tc.expected, string(b))
		})
	}
}

func TestStringSliceFromMap(t *testing.T) {
	testCases := []struct {
		name     string
		have     any
		expected []string
		ok       bool
	}{
		{
			name:     "ShouldReturnTrueForNil",
			have:     nil,
			expected: nil,
			ok:       true,
		},
		{
			name:     "ShouldReturnStringSliceAsIs",
			have:     []string{"foo", "bar"},
			expected: []string{"foo", "bar"},
			ok:       true,
		},
		{
			name:     "ShouldWrapSingleString",
			have:     "foo",
			expected: []string{"foo"},
			ok:       true,
		},
		{
			name:     "ShouldConvertAnySliceOfStrings",
			have:     []any{"foo", "bar"},
			expected: []string{"foo", "bar"},
			ok:       true,
		},
		{
			name:     "ShouldFailAnySliceWithNonString",
			have:     []any{"foo", 1},
			expected: nil,
			ok:       false,
		},
		{
			name:     "ShouldFailForUnsupportedType",
			have:     123,
			expected: nil,
			ok:       false,
		},
		{
			name:     "ShouldReturnEmptyForEmptyAnySlice",
			have:     []any{},
			expected: nil,
			ok:       true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, ok := StringSliceFromMap(tc.have)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestCopy(t *testing.T) {
	t.Run("ShouldCopyMapToIndependentInstance", func(t *testing.T) {
		original := map[string]any{"a": 1, "b": "two"}
		copied := Copy(original)
		assert.Equal(t, original, copied)

		copied["a"] = 99
		assert.Equal(t, 1, original["a"], "mutating the copy must not affect the original")
	})

	t.Run("ShouldReturnEmptyMapForNilInput", func(t *testing.T) {
		copied := Copy(nil)
		assert.NotNil(t, copied)
		assert.Empty(t, copied)
	})
}

func TestFilter(t *testing.T) {
	testCases := []struct {
		name     string
		have     map[string]any
		filter   []string
		expected map[string]any
	}{
		{
			name:     "ShouldFilterNone",
			have:     map[string]any{"abc": 123},
			filter:   []string{},
			expected: map[string]any{"abc": 123},
		},
		{
			name:     "ShouldFilterNoneNil",
			have:     map[string]any{"abc": 123},
			filter:   []string{},
			expected: map[string]any{"abc": 123},
		},
		{
			name:     "ShouldFilterAll",
			have:     map[string]any{"abc": 123, "example": 123},
			filter:   []string{"abc", "example"},
			expected: map[string]any{},
		},
		{
			name:     "ShouldFilterSome",
			have:     map[string]any{"abc": 123, "example": 123},
			filter:   []string{"abc"},
			expected: map[string]any{"example": 123},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			have := Filter(tc.have, tc.filter...)
			assert.Equal(t, tc.expected, have)
		})
	}
}
