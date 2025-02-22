// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestToString(t *testing.T) {
	assert.Equal(t, "foo", ToString("foo"))
	assert.Equal(t, "foo", ToString([]string{"foo"}))
	assert.Empty(t, ToString(1234))
	assert.Empty(t, ToString(nil))
}

func TestToTime(t *testing.T) {
	assert.Equal(t, time.Time{}, ToTime(nil))
	assert.Equal(t, time.Time{}, ToTime("1234"))

	now := time.Now().UTC().Truncate(TimePrecision)
	assert.Equal(t, now, ToTime(now))
	assert.Equal(t, now, ToTime(now.Unix()))
	assert.Equal(t, now, ToTime(float64(now.Unix())))
}

func TestFilter(t *testing.T) {
	testCases := []struct {
		name     string
		have     map[string]any
		filter   []string
		expected map[string]any
	}{
		{
			"ShouldFilterNone",
			map[string]any{"abc": 123},
			[]string{},
			map[string]any{"abc": 123},
		},
		{
			"ShouldFilterNoneNil",
			map[string]any{"abc": 123},
			[]string{},
			map[string]any{"abc": 123},
		},
		{
			"ShouldFilterAll",
			map[string]any{"abc": 123, "example": 123},
			[]string{"abc", "example"},
			map[string]any{},
		},
		{
			"ShouldFilterSome",
			map[string]any{"abc": 123, "example": 123},
			[]string{"abc"},
			map[string]any{"example": 123},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			have := Filter(tc.have, tc.filter...)
			assert.Equal(t, tc.expected, have)
		})
	}
}
