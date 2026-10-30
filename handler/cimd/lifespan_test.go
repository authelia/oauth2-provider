// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package cimd

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLifespan(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

	const (
		minimum  = 5 * time.Minute
		maximum  = 24 * time.Hour
		fallback = time.Hour
	)

	testCases := []struct {
		name     string
		header   map[string]string
		expected time.Duration
	}{
		{"ShouldUseFallbackWithoutHeaders", nil, fallback},
		{"ShouldUseMaxAge", map[string]string{"Cache-Control": "max-age=1800"}, 30 * time.Minute},
		{"ShouldUseMaxAgeAmongDirectives", map[string]string{"Cache-Control": "public, Max-Age=1800, must-revalidate"}, 30 * time.Minute},
		{"ShouldUseQuotedMaxAge", map[string]string{"Cache-Control": `max-age="1800"`}, 30 * time.Minute},
		{"ShouldSubtractAge", map[string]string{"Cache-Control": "max-age=1800", "Age": "600"}, 20 * time.Minute},
		{"ShouldRaiseShortMaxAgeToMinimum", map[string]string{"Cache-Control": "max-age=10"}, minimum},
		{"ShouldRaiseZeroMaxAgeToMinimum", map[string]string{"Cache-Control": "max-age=0"}, minimum},
		{"ShouldRaiseExhaustedMaxAgeToMinimum", map[string]string{"Cache-Control": "max-age=600", "Age": "900"}, minimum},
		{"ShouldLowerLongMaxAgeToMaximum", map[string]string{"Cache-Control": "max-age=31536000"}, maximum},
		{"ShouldLowerOverflowingMaxAgeToMaximum", map[string]string{"Cache-Control": "max-age=9223372036854775807"}, maximum},
		{"ShouldLowerOutOfRangeMaxAgeToMaximum", map[string]string{"Cache-Control": "max-age=99999999999999999999999"}, maximum},
		{"ShouldUseFallbackForNegativeMaxAge", map[string]string{"Cache-Control": "max-age=-5"}, fallback},
		{"ShouldUseFallbackForMalformedMaxAge", map[string]string{"Cache-Control": "max-age=soon"}, fallback},
		{"ShouldUseMinimumForNoStore", map[string]string{"Cache-Control": "no-store"}, minimum},
		{"ShouldUseMinimumForNoCache", map[string]string{"Cache-Control": "no-cache, max-age=1800"}, minimum},
		{"ShouldUseMinimumForPrivate", map[string]string{"Cache-Control": "private, max-age=1800"}, minimum},
		{"ShouldUseMinimumForQualifiedPrivate", map[string]string{"Cache-Control": `max-age=1800, private="set-cookie"`}, minimum},
		{"ShouldUseSharedMaxAge", map[string]string{"Cache-Control": "s-maxage=900"}, 15 * time.Minute},
		{"ShouldPreferSharedMaxAgeOverMaxAge", map[string]string{"Cache-Control": "max-age=1800, s-maxage=900"}, 15 * time.Minute},
		{"ShouldPreferSharedMaxAgeOverMaxAgeInAnyOrder", map[string]string{"Cache-Control": "S-MaxAge=900, max-age=1800"}, 15 * time.Minute},
		{"ShouldPreferSharedMaxAgeOverExpires", map[string]string{"Cache-Control": "s-maxage=900", "Expires": now.Add(2 * time.Hour).Format(http.TimeFormat)}, 15 * time.Minute},
		{"ShouldSubtractAgeFromSharedMaxAge", map[string]string{"Cache-Control": "s-maxage=1800", "Age": "600"}, 20 * time.Minute},
		{"ShouldRaiseZeroSharedMaxAgeToMinimum", map[string]string{"Cache-Control": "max-age=1800, s-maxage=0"}, minimum},
		{"ShouldLowerOverflowingSharedMaxAgeToMaximum", map[string]string{"Cache-Control": "s-maxage=99999999999999999999999"}, maximum},
		{"ShouldUseMaxAgeForMalformedSharedMaxAge", map[string]string{"Cache-Control": "max-age=1800, s-maxage=soon"}, 30 * time.Minute},
		{"ShouldUseExpires", map[string]string{"Expires": now.Add(2 * time.Hour).Format(http.TimeFormat)}, 2 * time.Hour},
		{"ShouldUseExpiresRelativeToDate", map[string]string{"Expires": now.Add(2 * time.Hour).Format(http.TimeFormat), "Date": now.Add(time.Hour).Format(http.TimeFormat)}, time.Hour},
		{"ShouldPreferMaxAgeOverExpires", map[string]string{"Cache-Control": "max-age=1800", "Expires": now.Add(2 * time.Hour).Format(http.TimeFormat)}, 30 * time.Minute},
		{"ShouldRaisePastExpiresToMinimum", map[string]string{"Expires": now.Add(-time.Hour).Format(http.TimeFormat)}, minimum},
		{"ShouldRaiseInvalidExpiresToMinimum", map[string]string{"Expires": "0"}, minimum},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			header := http.Header{}

			for name, value := range tc.header {
				header.Set(name, value)
			}

			assert.Equal(t, tc.expected, lifespan(header, now, minimum, maximum, fallback))
		})
	}
}
