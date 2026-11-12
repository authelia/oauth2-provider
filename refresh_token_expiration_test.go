// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGetRefreshTokenEffectiveExpiry(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()

	session := func(expires, deadline time.Time) Session {
		s := &DefaultSession{ExpiryDeadline: deadline}

		if !expires.IsZero() {
			s.SetExpiresAt(RefreshToken, expires)
		}

		return s
	}

	testCases := []struct {
		name     string
		session  Session
		expected time.Time
	}{
		{"ShouldReturnZeroWithNeither", session(time.Time{}, time.Time{}), time.Time{}},
		{"ShouldReturnTheExpiryWithoutADeadline", session(now.Add(time.Hour), time.Time{}), now.Add(time.Hour)},
		{"ShouldReturnTheDeadlineWithoutAnExpiry", session(time.Time{}, now.Add(time.Hour)), now.Add(time.Hour)},
		{"ShouldReturnAnExpiryBeforeTheDeadline", session(now.Add(time.Minute), now.Add(time.Hour)), now.Add(time.Minute)},
		{"ShouldReturnADeadlineBeforeTheExpiry", session(now.Add(time.Hour), now.Add(time.Minute)), now.Add(time.Minute)},
		{"ShouldReturnTheExpiryWithoutADeadlineSession", &testNoDeadlineSession{Session: session(now.Add(time.Hour), now.Add(time.Minute))}, now.Add(time.Hour)},
		{"ShouldReturnZeroWithoutASession", nil, time.Time{}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, GetRefreshTokenEffectiveExpiry(tc.session))
		})
	}
}

func TestGetRefreshTokenExpirationParameters(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()

	session := func(expires, deadline time.Time) Session {
		s := &DefaultSession{ExpiryDeadline: deadline}

		if !expires.IsZero() {
			s.SetExpiresAt(RefreshToken, expires)
		}

		return s
	}

	day := 24 * time.Hour

	testCases := []struct {
		name     string
		session  Session
		expected map[string]int64
	}{
		// Section 6.3, day 0.
		{"ShouldReturnBothAtIssuance", session(now.Add(7*day), now.Add(10*day)), map[string]int64{"refresh_token_timeout": 604800, "authorization_expires_in": 864000}},
		// Section 6.3, day 7.
		{"ShouldReturnBothEqualWhenTheDeadlineBindsTheExpiry", session(now.Add(3*day), now.Add(3*day)), map[string]int64{"refresh_token_timeout": 259200, "authorization_expires_in": 259200}},
		{"ShouldReturnOnlyTheTimeoutWithoutADeadline", session(now.Add(7*day), time.Time{}), map[string]int64{"refresh_token_timeout": 604800}},
		{"ShouldReturnBothWithOnlyADeadline", session(time.Time{}, now.Add(3*day)), map[string]int64{"refresh_token_timeout": 259200, "authorization_expires_in": 259200}},
		{"ShouldReturnNothingWithNeither", session(time.Time{}, time.Time{}), map[string]int64{}},
		{"ShouldNotLetTheTimeoutExceedTheAuthorization", session(now.Add(time.Hour), now.Add(10*time.Minute)), map[string]int64{"refresh_token_timeout": 600, "authorization_expires_in": 600}},
		{"ShouldRoundDown", session(now.Add(1500*time.Millisecond), time.Time{}), map[string]int64{"refresh_token_timeout": 1}},
		{"ShouldNotReturnNegativeValues", session(now.Add(-time.Minute), now.Add(-time.Hour)), map[string]int64{"refresh_token_timeout": 0, "authorization_expires_in": 0}},
		{"ShouldReturnNothingWithoutASession", nil, map[string]int64{}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, GetRefreshTokenExpirationParameters(tc.session, now))
		})
	}
}

type testNoDeadlineSession struct {
	Session
}
