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

func TestNewCachePolicy(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

	const (
		maximum  = 24 * time.Hour
		fallback = time.Hour
	)

	stored := func(lifespan time.Duration) cachePolicy {
		return cachePolicy{lifespan: lifespan, store: true}
	}

	revalidated := func(lifespan time.Duration) cachePolicy {
		return cachePolicy{lifespan: lifespan, store: true, revalidate: true}
	}

	testCases := []struct {
		name     string
		header   map[string][]string
		expected cachePolicy
	}{
		{"ShouldUseFallbackWithoutHeaders", nil, stored(fallback)},
		{"ShouldUseFallbackWithoutAnExpirationTime", map[string][]string{"Cache-Control": {"public"}}, stored(fallback)},
		{"ShouldUseMaxAge", map[string][]string{"Cache-Control": {"max-age=1800"}}, stored(30 * time.Minute)},
		{"ShouldUseMaxAgeAmongDirectives", map[string][]string{"Cache-Control": {"public, Max-Age=1800"}}, stored(30 * time.Minute)},
		{"ShouldUseQuotedMaxAge", map[string][]string{"Cache-Control": {`max-age="1800"`}}, stored(30 * time.Minute)},
		{"ShouldUseTheFirstMaxAge", map[string][]string{"Cache-Control": {"max-age=1800", "max-age=60"}}, stored(30 * time.Minute)},
		{"ShouldSubtractAge", map[string][]string{"Cache-Control": {"max-age=1800"}, "Age": {"600"}}, stored(20 * time.Minute)},
		{"ShouldKeepAShortMaxAge", map[string][]string{"Cache-Control": {"max-age=10"}}, stored(10 * time.Second)},
		{"ShouldHaveNoLifespanForAZeroMaxAge", map[string][]string{"Cache-Control": {"max-age=0"}}, stored(0)},
		{"ShouldHaveNoLifespanForAnExhaustedMaxAge", map[string][]string{"Cache-Control": {"max-age=600"}, "Age": {"900"}}, stored(0)},
		{"ShouldHaveNoLifespanForANegativeMaxAge", map[string][]string{"Cache-Control": {"max-age=-5"}}, stored(0)},
		{"ShouldHaveNoLifespanForAMalformedMaxAge", map[string][]string{"Cache-Control": {"max-age=soon"}}, stored(0)},
		{"ShouldLowerLongMaxAgeToMaximum", map[string][]string{"Cache-Control": {"max-age=31536000"}}, stored(maximum)},
		{"ShouldLowerOverflowingMaxAgeToMaximum", map[string][]string{"Cache-Control": {"max-age=9223372036854775807"}}, stored(maximum)},
		{"ShouldLowerOutOfRangeMaxAgeToMaximum", map[string][]string{"Cache-Control": {"max-age=99999999999999999999999"}}, stored(maximum)},
		{"ShouldNotStoreNoStore", map[string][]string{"Cache-Control": {"no-store, max-age=1800"}}, cachePolicy{lifespan: 30 * time.Minute}},
		{"ShouldNotStorePrivate", map[string][]string{"Cache-Control": {"private, max-age=1800"}}, cachePolicy{lifespan: 30 * time.Minute}},
		{"ShouldStoreQualifiedPrivate", map[string][]string{"Cache-Control": {`max-age=1800, private="set-cookie"`}}, stored(30 * time.Minute)},
		{"ShouldRevalidateNoCache", map[string][]string{"Cache-Control": {"no-cache, max-age=1800"}}, revalidated(0)},
		{"ShouldIgnoreQualifiedNoCache", map[string][]string{"Cache-Control": {`no-cache="set-cookie", max-age=1800`}}, stored(30 * time.Minute)},
		{"ShouldRevalidateMustRevalidate", map[string][]string{"Cache-Control": {"max-age=1800, must-revalidate"}}, revalidated(30 * time.Minute)},
		{"ShouldRevalidateProxyRevalidate", map[string][]string{"Cache-Control": {"max-age=1800, proxy-revalidate"}}, revalidated(30 * time.Minute)},
		{"ShouldUseSharedMaxAgeAndRevalidate", map[string][]string{"Cache-Control": {"s-maxage=900"}}, revalidated(15 * time.Minute)},
		{"ShouldPreferSharedMaxAgeOverMaxAge", map[string][]string{"Cache-Control": {"max-age=1800, s-maxage=900"}}, revalidated(15 * time.Minute)},
		{"ShouldPreferSharedMaxAgeOverMaxAgeInAnyOrder", map[string][]string{"Cache-Control": {"S-MaxAge=900, max-age=1800"}}, revalidated(15 * time.Minute)},
		{"ShouldPreferSharedMaxAgeOverExpires", map[string][]string{"Cache-Control": {"s-maxage=900"}, "Expires": {now.Add(2 * time.Hour).Format(http.TimeFormat)}}, revalidated(15 * time.Minute)},
		{"ShouldSubtractAgeFromSharedMaxAge", map[string][]string{"Cache-Control": {"s-maxage=1800"}, "Age": {"600"}}, revalidated(20 * time.Minute)},
		{"ShouldHaveNoLifespanForAZeroSharedMaxAge", map[string][]string{"Cache-Control": {"max-age=1800, s-maxage=0"}}, revalidated(0)},
		{"ShouldHaveNoLifespanForAMalformedSharedMaxAge", map[string][]string{"Cache-Control": {"max-age=1800, s-maxage=soon"}}, revalidated(0)},
		{"ShouldUseExpires", map[string][]string{"Expires": {now.Add(2 * time.Hour).Format(http.TimeFormat)}}, stored(2 * time.Hour)},
		{"ShouldUseExpiresRelativeToDate", map[string][]string{"Expires": {now.Add(2 * time.Hour).Format(http.TimeFormat)}, "Date": {now.Add(time.Hour).Format(http.TimeFormat)}}, stored(time.Hour)},
		{"ShouldPreferMaxAgeOverExpires", map[string][]string{"Cache-Control": {"max-age=1800"}, "Expires": {now.Add(2 * time.Hour).Format(http.TimeFormat)}}, stored(30 * time.Minute)},
		{"ShouldHaveNoLifespanForAPastExpires", map[string][]string{"Expires": {now.Add(-time.Hour).Format(http.TimeFormat)}}, stored(0)},
		{"ShouldHaveNoLifespanForAnInvalidExpires", map[string][]string{"Expires": {"0"}}, stored(0)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			header := http.Header{}

			for name, values := range tc.header {
				for _, value := range values {
					header.Add(name, value)
				}
			}

			assert.Equal(t, tc.expected, newCachePolicy(header, now, maximum, fallback))
		})
	}
}
