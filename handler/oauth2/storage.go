// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"time"

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
	// ErrInvalidatedAuthorizeCode error. See storage.Transactional, which a store must implement for the revocation of a
	// replayed authorization code to be complete.
	//
	// It may return oauth2.ErrSerializationFailure when a concurrent transaction prevents it. GetAuthorizeCodeSession MUST
	// then return ErrInvalidatedAuthorizeCode, with the oauth2.Requester, if that transaction committed the invalidation,
	// when called with a context outside the transaction this request rolled back, so that the grant can be revoked.
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
	// RotateRefreshToken or revoked, or the deadline RefreshTokenGracePeriodStorage recorded for it has passed.
	//
	// Make sure to also return the oauth2.Requester value when returning the oauth2.ErrInactiveToken error! The refresh
	// token grant handler uses it to revoke every token derived from the same authorization grant when it detects that
	// a refresh token has been reused, and the token revocation handler does the same when a client revokes a rotated
	// refresh token. Without it the revocation of a rotated refresh token answers with success and revokes nothing.
	GetRefreshTokenSession(ctx context.Context, signature string, session oauth2.Session) (request oauth2.Requester, err error)

	// DeleteRefreshTokenSession removes the session stored against the given refresh token signature. The handlers do not
	// call it when revoking a grant, as a removed session cannot refuse a request which read it before it was rotated.
	DeleteRefreshTokenSession(ctx context.Context, signature string) (err error)

	// UpdateRefreshTokenSession replaces the request stored for the given refresh token signature while the refresh
	// token itself stays valid. The refresh token keeps its active state and the access token signature it is paired
	// with. It is called when a refresh token is redeemed without being rotated, so the stored session carries any
	// proof-of-possession binding the redemption re-bound the grant to, as RFC 8705 Section 4 and RFC 9449 Section 5
	// leave the binding of a refresh token to the authorization server. This method should return the
	// oauth2.ErrNotFound error if no session exists for the given signature.
	UpdateRefreshTokenSession(ctx context.Context, signature string, request oauth2.Requester) (err error)

	// RotateRefreshToken deactivates the refresh token with the given signature and revokes the access tokens
	// associated with the given request ID. Consecutive requests to GetRefreshTokenSession for that signature should
	// return the oauth2.ErrInactiveToken error. See storage.Transactional, which a store must implement for the revocation
	// of a replayed refresh token to be complete.
	//
	// This method should return the oauth2.ErrInactiveToken error when the refresh token was already deactivated, for
	// example by a concurrent request that rotated it first. The refresh token grant handler treats that as a reused
	// refresh token and revokes every token derived from the same authorization grant.
	//
	// This method MUST check the given signature and return the oauth2.ErrNotFound error when it does not exist rather
	// than succeed, as the check is what makes a refresh token single use. The refresh token grant handler answers that
	// as a revoked refresh token. A store which reports no rows affected as success would let a request which read the
	// refresh token before it was removed issue tokens after its grant was revoked.
	//
	// It may return oauth2.ErrSerializationFailure when a concurrent transaction prevents it. GetRefreshTokenSession MUST
	// then return oauth2.ErrInactiveToken if that transaction committed the rotation, when called with a context outside
	// the transaction this request rolled back, so that the grant can be revoked.
	//
	// A refresh token grace period is not applied by this method. A store which supports one implements
	// RefreshTokenGracePeriodStorage, and this method MUST then also deactivate a refresh token which is within its
	// grace period, and return the oauth2.ErrInactiveToken error for one whose grace period has ended.
	RotateRefreshToken(ctx context.Context, requestID string, signature string) (err error)
}

// RefreshTokenGracePeriodStorage is optionally implemented by a TokenRevocationStorage which supports a refresh token
// grace period. The refresh token grant handler rotates the refresh token with RotateRefreshToken, without a grace
// period, when the store does not implement it.
//
// See: https://datatracker.ietf.org/doc/html/rfc9700#section-4.14.2
type RefreshTokenGracePeriodStorage interface {
	// RotateRefreshTokenWithGracePeriod rotates the refresh token with the given signature as RotateRefreshToken does,
	// except the refresh token stays active until the given deadline. It is called in place of RotateRefreshToken when
	// a grace period applies to the request, with the same request ID, and has the same concurrency contract: it
	// returns the oauth2.ErrNotFound error when the signature does not exist, may return the
	// oauth2.ErrSerializationFailure error, and takes part in the transaction of a store which implements
	// storage.Transactional.
	//
	// The first call for a signature MUST record the deadline. A later call before the recorded deadline MUST succeed
	// and MUST NOT replace it, so that redeeming the refresh token again does not extend the grace period. This method,
	// RotateRefreshToken and GetRefreshTokenSession MUST return the oauth2.ErrInactiveToken error once the recorded
	// deadline has passed, and when the refresh token was deactivated by RotateRefreshToken or revoked. The refresh
	// token grant handler treats that as a reused refresh token and revokes every token derived from the same
	// authorization grant.
	//
	// It MUST only revoke the access token whose signature was given to CreateRefreshTokenSession alongside the
	// refresh token with the given signature. Every refresh token issued by redeeming a refresh token within its grace
	// period has the same request ID, so revoking the access tokens of the request ID would revoke the access token a
	// concurrent redemption was just issued.
	//
	// RevokeRefreshToken MUST deactivate every refresh token of the request ID, including each that is within its
	// grace period, and RevokeAccessToken every access token of the request ID.
	RotateRefreshTokenWithGracePeriod(ctx context.Context, requestID string, signature string, deadline time.Time) (err error)
}
