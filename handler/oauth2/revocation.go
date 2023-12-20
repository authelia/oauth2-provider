// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/errorsx"
)

type TokenRevocationHandler struct {
	TokenRevocationStorage TokenRevocationStorage
	RefreshTokenStrategy   RefreshTokenStrategy
	AccessTokenStrategy    AccessTokenStrategy
}

// RevokeToken implements https://tools.ietf.org/html/rfc7009#section-2.1
// The token type hint indicates which token type check should be performed first.
func (r *TokenRevocationHandler) RevokeToken(ctx context.Context, token string, tokenType oauth2.TokenType, client oauth2.Client) error {
	discoveryFuncs := []func() (request oauth2.Requester, err error){
		func() (request oauth2.Requester, err error) {
			// Refresh token
			signature := r.RefreshTokenStrategy.RefreshTokenSignature(ctx, token)
			return r.TokenRevocationStorage.GetRefreshTokenSession(ctx, signature, nil)
		},
		func() (request oauth2.Requester, err error) {
			// Access token
			signature := r.AccessTokenStrategy.AccessTokenSignature(ctx, token)
			return r.TokenRevocationStorage.GetAccessTokenSession(ctx, signature, nil)
		},
	}

	// Token type hinting
	if tokenType == oauth2.AccessToken {
		discoveryFuncs[0], discoveryFuncs[1] = discoveryFuncs[1], discoveryFuncs[0]
	}

	var ar oauth2.Requester
	var err1, err2 error
	if ar, err1 = discoveryFuncs[0](); err1 != nil {
		ar, err2 = discoveryFuncs[1]()
	}
	// err2 can only be not nil if first err1 was not nil
	if err2 != nil {
		return storeErrorsToRevocationError(err1, err2)
	}

	if ar.GetClient().GetID() != client.GetID() {
		return errorsx.WithStack(oauth2.ErrUnauthorizedClient)
	}

	requestID := ar.GetID()
	err1 = r.TokenRevocationStorage.RevokeRefreshToken(ctx, requestID)
	err2 = r.TokenRevocationStorage.RevokeAccessToken(ctx, requestID)

	return storeErrorsToRevocationError(err1, err2)
}

func storeErrorsToRevocationError(err1, err2 error) error {
	// both errors are oauth2.ErrNotFound and oauth2.ErrInactiveToken or nil <=> the token is revoked
	if (errors.Is(err1, oauth2.ErrNotFound) || errors.Is(err1, oauth2.ErrInactiveToken) || err1 == nil) &&
		(errors.Is(err2, oauth2.ErrNotFound) || errors.Is(err2, oauth2.ErrInactiveToken) || err2 == nil) {
		return nil
	}

	// there was an unexpected error => the token may still exist and the client should retry later
	return errorsx.WithStack(oauth2.ErrTemporarilyUnavailable)
}
