// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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
