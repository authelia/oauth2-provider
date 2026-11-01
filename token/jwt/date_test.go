// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNumericDateOutOfRangeSeconds(t *testing.T) {
	const limit = int64(1 << 62)

	testCases := []struct {
		name     string
		exp      any
		expected int64
		valid    bool
	}{
		{name: "ShouldKeepASecondsValue", exp: float64(time.Now().Add(time.Hour).Unix()), expected: time.Now().Add(time.Hour).Unix(), valid: true},
		{name: "ShouldLimitAFloatAboveTheRange", exp: 1e300, expected: limit, valid: true},
		{name: "ShouldLimitAnInt64AboveTheRange", exp: int64(math.MaxInt64), expected: limit, valid: true},
		{name: "ShouldLimitInfinity", exp: math.Inf(1), expected: limit, valid: true},
		{name: "ShouldLimitANumberAboveTheRange", exp: json.Number("1e300"), expected: limit, valid: true},
		{name: "ShouldLimitANumberTooLargeForAFloat", exp: json.Number("1e999"), expected: limit, valid: true},
		{name: "ShouldLimitAFloatBelowTheRange", exp: -1e300, expected: -limit},
		{name: "ShouldLimitAnInt64BelowTheRange", exp: int64(math.MinInt64), expected: -limit},
		{name: "ShouldLimitNegativeInfinity", exp: math.Inf(-1), expected: -limit},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims := MapClaims{ClaimExpirationTime: tc.exp}

			date, err := claims.GetExpirationTime()
			require.NoError(t, err)
			require.NotNil(t, date)

			assert.InDelta(t, tc.expected, date.Int64(), 1)
			assert.Equal(t, tc.valid, claims.VerifyExpirationTime(time.Now().Unix(), true))
			assert.Equal(t, tc.valid, date.After(time.Now()))

			if tc.valid {
				assert.NoError(t, claims.Valid())
			} else {
				assert.Error(t, claims.Valid())
			}
		})
	}
}
