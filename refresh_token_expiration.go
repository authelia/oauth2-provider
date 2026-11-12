// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"time"

	"authelia.com/provider/oauth2/internal/consts"
)

// GetRefreshTokenEffectiveExpiry returns the time the refresh token of the session expires: the earlier of its own
// expiry and the deadline of the session when it is an ExpiryDeadlineSession, where a zero time on either side is
// absent. It returns the zero time when both are absent or the session is nil.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-refresh-token-expiration-03#section-5
func GetRefreshTokenEffectiveExpiry(session Session) (expires time.Time) {
	if session == nil {
		return time.Time{}
	}

	expires = session.GetExpiresAt(RefreshToken)

	bounded, ok := session.(ExpiryDeadlineSession)
	if !ok {
		return expires
	}

	if deadline := bounded.GetExpiryDeadline(); !deadline.IsZero() && (expires.IsZero() || deadline.Before(expires)) {
		return deadline
	}

	return expires
}

// GetRefreshTokenExpirationParameters returns the refresh_token_timeout and authorization_expires_in token response
// parameters for the session: the whole seconds, rounded down and never negative, until the effective expiry of the
// refresh token and until the expiry deadline of the session, each omitted when absent.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-refresh-token-expiration-03#section-6.1
func GetRefreshTokenExpirationParameters(session Session, now time.Time) (parameters map[string]int64) {
	parameters = map[string]int64{}

	if expires := GetRefreshTokenEffectiveExpiry(session); !expires.IsZero() {
		parameters[consts.AccessResponseRefreshTokenTimeout] = secondsUntil(expires, now)
	}

	if bounded, ok := session.(ExpiryDeadlineSession); ok {
		if deadline := bounded.GetExpiryDeadline(); !deadline.IsZero() {
			parameters[consts.AccessResponseAuthorizationExpiresIn] = secondsUntil(deadline, now)
		}
	}

	return parameters
}

func secondsUntil(t, now time.Time) (seconds int64) {
	if seconds = int64(t.Sub(now) / time.Second); seconds < 0 {
		return 0
	}

	return seconds
}
