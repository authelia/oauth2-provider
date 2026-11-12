// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package claimvalue

import (
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSlice(t *testing.T) {
	testCases := []struct {
		name     string
		value    any
		expected []string
		ok       bool
	}{
		{"ShouldHandleNil", nil, nil, true},
		{"ShouldHandleString", "a", []string{"a"}, true},
		{"ShouldHandleStringSlice", []string{"a", "b"}, []string{"a", "b"}, true},
		{"ShouldHandleAnySlice", []any{"a", "b"}, []string{"a", "b"}, true},
		{"ShouldHandleEmptyAnySlice", []any{}, nil, true},
		{"ShouldRejectMixedAnySlice", []any{"a", 1}, nil, false},
		{"ShouldRejectNumber", 1.0, nil, false},
		{"ShouldRejectMap", map[string]any{}, nil, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, ok := Slice[string](tc.value)

			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestNumber(t *testing.T) {
	testCases := []struct {
		name    string
		value   any
		integer int64
		float   float64
		ok      bool
	}{
		{"ShouldHandleFloat64", 1.5, 1, 1.5, true},
		{"ShouldHandleFloat32", float32(2.5), 2, 2.5, true},
		{"ShouldHandleInt", 3, 3, 3, true},
		{"ShouldHandleInt8", int8(11), 11, 11, true},
		{"ShouldHandleInt16", int16(12), 12, 12, true},
		{"ShouldHandleInt32", int32(4), 4, 4, true},
		{"ShouldHandleInt64", int64(5), 5, 5, true},
		{"ShouldHandleUint", uint(6), 6, 6, true},
		{"ShouldHandleUint8", uint8(13), 13, 13, true},
		{"ShouldHandleUint16", uint16(14), 14, 14, true},
		{"ShouldHandleUint32", uint32(7), 7, 7, true},
		{"ShouldHandleUint64", uint64(8), 8, 8, true},
		{"ShouldHandleUintptr", uintptr(15), 15, 15, true},
		{"ShouldHandleJSONNumberInteger", json.Number("9"), 9, 9, true},
		{"ShouldHandleJSONNumberFraction", json.Number("10.5"), 10, 10.5, true},
		{"ShouldHandleJSONNumberExponent", json.Number("1e3"), 1000, 1000, true},
		{"ShouldRejectJSONNumberInvalid", json.Number("abc"), 0, 0, false},
		{"ShouldRejectJSONNumberOverflow", json.Number("1e400"), 0, 0, false},
		{"ShouldRejectString", "1", 0, 0, false},
		{"ShouldRejectNil", nil, 0, 0, false},
		{"ShouldRejectBool", true, 0, 0, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			integer, ok := Number[int64](tc.value)

			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.integer, integer)

			float, ok := Number[float64](tc.value)

			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.float, float)
		})
	}
}

func TestNumberShouldPassNaNThrough(t *testing.T) {
	number, ok := Number[float64](math.NaN())

	assert.True(t, ok)
	assert.True(t, math.IsNaN(number))
}

func TestTime(t *testing.T) {
	testCases := []struct {
		name     string
		value    any
		expected time.Time
		ok       bool
	}{
		{"ShouldTruncateFloat64Seconds", float64(1700000000.9), time.Unix(1700000000, 0).UTC(), true},
		{"ShouldHandleInt64Seconds", int64(1700000000), time.Unix(1700000000, 0).UTC(), true},
		{"ShouldHandleJSONNumber", json.Number("1700000000"), time.Unix(1700000000, 0).UTC(), true},
		{"ShouldHandleInt8Seconds", int8(100), time.Unix(100, 0).UTC(), true},
		{"ShouldHandleInt16Seconds", int16(1000), time.Unix(1000, 0).UTC(), true},
		{"ShouldHandleUint8Seconds", uint8(200), time.Unix(200, 0).UTC(), true},
		{"ShouldHandleUint16Seconds", uint16(2000), time.Unix(2000, 0).UTC(), true},
		{"ShouldHandleUintptrSeconds", uintptr(1700000000), time.Unix(1700000000, 0).UTC(), true},
		{"ShouldRejectStringSeconds", "1700000000", time.Time{}, false},
		{"ShouldRejectTime", time.Unix(1700000000, 0), time.Time{}, false},
		{"ShouldRejectMissing", nil, time.Time{}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, ok := Time(tc.value)

			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.expected, actual)
			assert.Equal(t, time.UTC, actual.Location())
		})
	}
}
