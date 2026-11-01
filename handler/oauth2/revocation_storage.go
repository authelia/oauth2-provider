// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
)

// TokenRevocationStorage provides the storage implementation
// as specified in: https://datatracker.ietf.org/doc/html/rfc7009
type TokenRevocationStorage interface {
	RefreshTokenStorage
	AccessTokenStorage

	// RevokeRefreshToken revokes a refresh token, and SHOULD also revoke all access tokens based on the same
	// authorization grant. It MUST revoke the active refresh token of the grant identified by the request ID, including
	// when the token presented for revocation was already deactivated by RotateRefreshToken and that active refresh token
	// replaced it. A refresh token issued by rotation has the same request ID as the one it replaced.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc7009#section-2.1
	RevokeRefreshToken(ctx context.Context, requestID string) error

	// RevokeAccessToken revokes an access token as specified in:
	// https://datatracker.ietf.org/doc/html/rfc7009#section-2.1
	// If the token passed to the request
	// is an access token, the server MAY revoke the respective refresh
	// token as well.
	//
	// It MUST revoke every access token issued for the request ID, including those issued by rotating a refresh token,
	// which have the same request ID as the refresh token they were rotated from.
	RevokeAccessToken(ctx context.Context, requestID string) error
}
