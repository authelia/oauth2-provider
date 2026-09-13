// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/internal/consts"
)

func TestValidLifetime(t *testing.T) {
	date := func(t *testing.T, value int64) *NumericDate {
		d := &NumericDate{Time: time.Unix(value, 0)}

		require.Equal(t, value, d.Int64())

		return d
	}

	testCases := []struct {
		name     string
		nbf      *int64
		exp      *int64
		now      int64
		lifetime time.Duration
		expected bool
	}{
		{"ShouldPassWithoutNotBefore", nil, new(int64(math.MaxInt64)), 1000, time.Hour, true},
		{"ShouldPassDisabled", new(int64(math.MinInt64)), new(int64(math.MaxInt64)), 1000, 0, true},
		{"ShouldPassWithoutExpiry", new(int64(1000)), nil, 1000, time.Hour, true},
		{"ShouldPassNotBeforeAtLimit", new(int64(1000)), nil, 4600, time.Hour, true},
		{"ShouldFailNotBeforeBeyondLimit", new(int64(1000)), nil, 4601, time.Hour, false},
		{"ShouldPassExpiryAtLimit", new(int64(1000)), new(int64(4600)), 1000, time.Hour, true},
		{"ShouldFailExpiryBeyondLimit", new(int64(1000)), new(int64(4601)), 1000, time.Hour, false},
		{"ShouldFailMinimumNotBefore", new(int64(math.MinInt64)), nil, 1000, time.Hour, false},
		{"ShouldFailMinimumNotBeforeWithExpiry", new(int64(math.MinInt64)), new(int64(1300)), 1000, time.Hour, false},
		{"ShouldFailMaximumExpiry", new(int64(1000)), new(int64(math.MaxInt64)), 1000, time.Hour, false},
		{"ShouldFailMinimumNotBeforeMaximumExpiry", new(int64(math.MinInt64)), new(int64(math.MaxInt64)), math.MinInt64, time.Hour, false},
		{"ShouldPassMaximumNotBefore", new(int64(math.MaxInt64)), nil, 1000, time.Hour, true},
		{"ShouldPassExpiryBeforeNotBefore", new(int64(1000)), new(int64(math.MinInt64)), 1000, time.Hour, true},
		{"ShouldPassMaximumNowNotBeforeAtLimit", new(int64(math.MaxInt64 - 3600)), nil, math.MaxInt64, time.Hour, true},
		{"ShouldFailMaximumNowMinimumNotBefore", new(int64(math.MinInt64)), nil, math.MaxInt64, time.Hour, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var nbf, exp *NumericDate

			if tc.nbf != nil {
				nbf = date(t, *tc.nbf)
			}

			if tc.exp != nil {
				exp = date(t, *tc.exp)
			}

			assert.Equal(t, tc.expected, validLifetime(nbf, exp, tc.now, tc.lifetime))
		})
	}
}

func TestMapClaims_Valid_MaximumLifetimeMinimumNotBefore(t *testing.T) {
	claims := MapClaims{consts.ClaimNotBefore: float64(math.MinInt64), consts.ClaimExpirationTime: 1300}

	err := claims.Valid(ValidateTimeFunc(func() time.Time { return time.Unix(1000, 0) }), ValidateMaximumLifetime(time.Hour))

	var verr *ValidationError

	require.ErrorAs(t, err, &verr)
	assert.True(t, verr.Has(ValidationErrorLifetime))
}
