// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"

	"authelia.com/provider/oauth2"
)

// CoreStorage is the composite storage required by the core OAuth 2.0 grant handlers.
type CoreStorage interface {
	AuthorizeCodeStorage
	AccessTokenStorage
	RefreshTokenStorage
}

// AuthorizeCodeStorage handles storage requests related to authorization codes.
type AuthorizeCodeStorage interface {
	// CreateAuthorizeCodeSession stores the authorization request for a given authorization code.
	CreateAuthorizeCodeSession(ctx context.Context, code string, request oauth2.Requester) (err error)

	// GetAuthorizeCodeSession hydrates the session based on the given code and returns the authorization request.
	// If the authorization code has been invalidated with `InvalidateAuthorizeCodeSession`, this
	// method should return the ErrInvalidatedAuthorizeCode error.
	//
	// Make sure to also return the oauth2.Requester value when returning the oauth2.ErrInvalidatedAuthorizeCode error!
	GetAuthorizeCodeSession(ctx context.Context, code string, session oauth2.Session) (request oauth2.Requester, err error)

	// InvalidateAuthorizeCodeSession is called when an authorize code is being used. The state of the authorization
	// code should be set to invalid and consecutive requests to GetAuthorizeCodeSession should return the
	// ErrInvalidatedAuthorizeCode error.
	InvalidateAuthorizeCodeSession(ctx context.Context, code string) (err error)
}

// AccessTokenStorage handles storage requests related to access tokens.
type AccessTokenStorage interface {
	// CreateAccessTokenSession stores the request for a given access token signature.
	CreateAccessTokenSession(ctx context.Context, signature string, request oauth2.Requester) (err error)

	// GetAccessTokenSession hydrates the session based on the given access token signature and returns the request.
	// This method should return the oauth2.ErrNotFound error if no session exists for the given signature.
	GetAccessTokenSession(ctx context.Context, signature string, session oauth2.Session) (request oauth2.Requester, err error)

	// DeleteAccessTokenSession removes the session stored against the given access token signature.
	DeleteAccessTokenSession(ctx context.Context, signature string) (err error)
}

// RefreshTokenStorage handles storage requests related to refresh tokens.
type RefreshTokenStorage interface {
	// CreateRefreshTokenSession stores the request for a given refresh token signature. The accessSignature is the
	// signature of the access token issued alongside this refresh token and allows the store to keep track of the
	// refresh/access token pair so both can be revoked together during rotation. It may be empty when no access token
	// was issued in the same operation.
	CreateRefreshTokenSession(ctx context.Context, signature string, accessSignature string, request oauth2.Requester) (err error)

	// GetRefreshTokenSession hydrates the session based on the given refresh token signature and returns the request.
	// This method should return the oauth2.ErrNotFound error if no session exists for the given signature, and the
	// oauth2.ErrInactiveToken error if the session exists but the refresh token has been deactivated by
	// RotateRefreshToken or revoked.
	//
	// Make sure to also return the oauth2.Requester value when returning the oauth2.ErrInactiveToken error! The refresh
	// token grant handler uses it to revoke every token derived from the same authorization grant when it detects that
	// a refresh token has been reused.
	GetRefreshTokenSession(ctx context.Context, signature string, session oauth2.Session) (request oauth2.Requester, err error)

	// DeleteRefreshTokenSession removes the session stored against the given refresh token signature.
	DeleteRefreshTokenSession(ctx context.Context, signature string) (err error)

	// RotateRefreshToken deactivates the refresh token with the given signature and revokes the access tokens
	// associated with the given request ID. Consecutive requests to GetRefreshTokenSession for that signature should
	// return the oauth2.ErrInactiveToken error.
	//
	// Implementations that support a refresh token grace period should instead mark the refresh token as expiring
	// after the grace period rather than deactivating it immediately, so that concurrent requests made by the same
	// client within that window continue to succeed.
	RotateRefreshToken(ctx context.Context, requestID string, signature string) (err error)
}
