// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package iox

import (
	"errors"
	"math"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadLimited(t *testing.T) {
	testCases := []struct {
		name     string
		have     string
		limit    int64
		expected string
		large    bool
	}{
		{name: "ShouldReadBelowTheLimit", have: "abc", limit: 4, expected: "abc"},
		{name: "ShouldReadAtTheLimit", have: "abc", limit: 3, expected: "abc"},
		{name: "ShouldReportOverTheLimit", have: "abc", limit: 2, large: true},
		{name: "ShouldReadEmpty", have: "", limit: 2, expected: ""},
		{name: "ShouldReadAtTheLargestLimit", have: "abc", limit: math.MaxInt64, expected: "abc"},
		{name: "ShouldReadBelowTheLargestLimit", have: "abc", limit: math.MaxInt64 - 1, expected: "abc"},
		{name: "ShouldReadEmptyAtZero", have: "", limit: 0, expected: ""},
		{name: "ShouldReportOverZero", have: "a", limit: 0, large: true},
		{name: "ShouldReportNegativeLimit", have: "a", limit: -1, large: true},
		{name: "ShouldReportNegativeLimitWhenEmpty", have: "", limit: -1, large: true},
		{name: "ShouldReportSmallestLimit", have: "a", limit: math.MinInt64, large: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, large, err := ReadLimited(strings.NewReader(tc.have), tc.limit)

			require.NoError(t, err)
			assert.Equal(t, tc.large, large)

			if tc.large {
				assert.Nil(t, data)
			} else {
				assert.Equal(t, tc.expected, string(data))
			}
		})
	}

	t.Run("ShouldReturnReadError", func(t *testing.T) {
		failure := errors.New("failure")

		data, large, err := ReadLimited(iotest.ErrReader(failure), 4)

		assert.ErrorIs(t, err, failure)
		assert.False(t, large)
		assert.Nil(t, data)
	})
}
