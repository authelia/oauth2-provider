// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

// RefreshTokenMode is the kind of refresh token a grant carries.
type RefreshTokenMode string

const (
	// RefreshTokenModeNone is a grant without a refresh token.
	RefreshTokenModeNone RefreshTokenMode = ""

	// RefreshTokenModeOnline is a grant whose refresh token was issued without any of the refresh token scopes, which
	// only a RefreshTokenOnlineClient allowing online refresh tokens may be issued or redeem.
	RefreshTokenModeOnline RefreshTokenMode = "online"

	// RefreshTokenModeOffline is a grant whose refresh token was issued with one of the refresh token scopes, or while
	// no refresh token scopes are configured.
	RefreshTokenModeOffline RefreshTokenMode = "offline"
)

// RefreshTokenModeSession is a Session recording the RefreshTokenMode of its grant, which a token endpoint handler
// sets before the tokens of the grant are stored; see RecordRefreshTokenMode.
type RefreshTokenModeSession interface {
	// GetRefreshTokenMode returns the RefreshTokenMode of the grant.
	GetRefreshTokenMode() (mode RefreshTokenMode)

	// SetRefreshTokenMode sets the RefreshTokenMode of the grant.
	SetRefreshTokenMode(mode RefreshTokenMode)
}

// GetRefreshTokenModeForScopes returns RefreshTokenModeOffline when scopes is empty or granted has one of scopes,
// otherwise RefreshTokenModeOnline.
func GetRefreshTokenModeForScopes(scopes []string, granted Arguments) (mode RefreshTokenMode) {
	if len(scopes) == 0 || granted.HasOneOf(scopes...) {
		return RefreshTokenModeOffline
	}

	return RefreshTokenModeOnline
}

// IsRefreshTokenModeAllowed returns true when a refresh token of the mode may be issued to or redeemed by the client:
// always for RefreshTokenModeOffline, and for RefreshTokenModeOnline only when the client is a
// RefreshTokenOnlineClient allowing online refresh tokens.
func IsRefreshTokenModeAllowed(client Client, mode RefreshTokenMode) (allowed bool) {
	switch mode {
	case RefreshTokenModeOffline:
		return true
	case RefreshTokenModeOnline:
		c, ok := client.(RefreshTokenOnlineClient)

		return ok && c.GetAllowOnlineRefreshTokens()
	default:
		return false
	}
}

// RecordRefreshTokenMode sets the mode on the session when it is a RefreshTokenModeSession.
func RecordRefreshTokenMode(session Session, mode RefreshTokenMode) {
	if s, ok := session.(RefreshTokenModeSession); ok {
		s.SetRefreshTokenMode(mode)
	}
}
