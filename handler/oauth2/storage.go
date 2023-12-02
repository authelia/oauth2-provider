// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"

	"github.com/authelia/goauth2"
)

type CoreStorage interface {
	AuthorizeCodeStorage
	AccessTokenStorage
	RefreshTokenStorage
}

// AuthorizeCodeStorage handles storage requests related to authorization codes.
type AuthorizeCodeStorage interface {
	// CreateAuthorizeCodeSession stores the authorization request for a given authorization code.
	CreateAuthorizeCodeSession(ctx context.Context, code string, request goauth2.Requester) (err error)

	// GetAuthorizeCodeSession hydrates the session based on the given code and returns the authorization request.
	// If the authorization code has been invalidated with `InvalidateAuthorizeCodeSession`, this
	// method should return the ErrInvalidatedAuthorizeCode error.
	//
	// Make sure to also return the goauth2.Requester value when returning the goauth2.ErrInvalidatedAuthorizeCode error!
	GetAuthorizeCodeSession(ctx context.Context, code string, session goauth2.Session) (request goauth2.Requester, err error)

	// InvalidateAuthorizeCodeSession is called when an authorize code is being used. The state of the authorization
	// code should be set to invalid and consecutive requests to GetAuthorizeCodeSession should return the
	// ErrInvalidatedAuthorizeCode error.
	InvalidateAuthorizeCodeSession(ctx context.Context, code string) (err error)
}

type AccessTokenStorage interface {
	CreateAccessTokenSession(ctx context.Context, signature string, request goauth2.Requester) (err error)

	GetAccessTokenSession(ctx context.Context, signature string, session goauth2.Session) (request goauth2.Requester, err error)

	DeleteAccessTokenSession(ctx context.Context, signature string) (err error)
}

type RefreshTokenStorage interface {
	CreateRefreshTokenSession(ctx context.Context, signature string, request goauth2.Requester) (err error)

	GetRefreshTokenSession(ctx context.Context, signature string, session goauth2.Session) (request goauth2.Requester, err error)

	DeleteRefreshTokenSession(ctx context.Context, signature string) (err error)
}
