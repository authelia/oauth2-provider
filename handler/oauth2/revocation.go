// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/errorsx"
)

type TokenRevocationHandler struct {
	TokenRevocationStorage TokenRevocationStorage
	RefreshTokenStrategy   RefreshTokenStrategy
	AccessTokenStrategy    AccessTokenStrategy
	Config                 interface {
		oauth2.RevokeRefreshTokensExplicitlyProvider
	}
}

// RevokeToken implements https://datatracker.ietf.org/doc/html/rfc7009#section-2.1
// The token type hint indicates which token type check should be performed first.
func (r *TokenRevocationHandler) RevokeToken(ctx context.Context, token string, tokenType oauth2.TokenType, client oauth2.Client) error {
	var handlers []RevocationTokenLookupFunc

	switch tokenType {
	case oauth2.AccessToken:
		handlers = []RevocationTokenLookupFunc{r.handleGetAccessTokenRequester, r.handleGetRefreshTokenRequester}
	case oauth2.RefreshToken:
		handlers = []RevocationTokenLookupFunc{r.handleGetRefreshTokenRequester, r.handleGetAccessTokenRequester}
	default:
		handlers = []RevocationTokenLookupFunc{r.handleGetRefreshTokenRequester, r.handleGetAccessTokenRequester}
	}

	//nolint:prealloc
	var (
		requester oauth2.Requester
		tt        oauth2.TokenType
		err       error
		errs      []error
	)

	for _, handler := range handlers {
		if requester, tt, err = handler(ctx, token); err == nil {
			break
		}

		errs = append(errs, err)
	}

	if len(errs) == len(handlers) {
		return r.handleErrors(errs)
	}

	if requester.GetClient().GetID() != client.GetID() {
		return errorsx.WithStack(oauth2.ErrUnauthorizedClient)
	}

	id := requester.GetID()

	errs = []error{}

	if !r.getRevokeRefreshTokensExplicitly(ctx, client) || tt == oauth2.RefreshToken {
		if err = r.TokenRevocationStorage.RevokeRefreshToken(ctx, id); err != nil {
			errs = append(errs, err)
		}
	}

	if err = r.TokenRevocationStorage.RevokeAccessToken(ctx, id); err != nil {
		errs = append(errs, err)
	}

	return r.handleErrors(errs)
}

type RevocationTokenLookupFunc func(ctx context.Context, token string) (requester oauth2.Requester, tokenType oauth2.TokenType, err error)

func (r *TokenRevocationHandler) getRevokeRefreshTokensExplicitly(ctx context.Context, client oauth2.Client) bool {
	var (
		c  oauth2.RevokeFlowRevokeRefreshTokensExplicitClient
		ok bool
	)

	if c, ok = client.(oauth2.RevokeFlowRevokeRefreshTokensExplicitClient); !ok {
		return r.Config.GetRevokeRefreshTokensExplicit(ctx)
	}

	if ok = c.GetRevokeRefreshTokensExplicit(ctx); ok || r.Config.GetEnforceRevokeFlowRevokeRefreshTokensExplicitClient(ctx) {
		return ok
	}

	return r.Config.GetRevokeRefreshTokensExplicit(ctx)
}

func (r *TokenRevocationHandler) handleGetRefreshTokenRequester(ctx context.Context, token string) (requester oauth2.Requester, tokenType oauth2.TokenType, err error) {
	signature := r.RefreshTokenStrategy.RefreshTokenSignature(ctx, token)

	requester, err = r.TokenRevocationStorage.GetRefreshTokenSession(ctx, signature, nil)

	return requester, consts.TokenTypeRefreshToken, err
}

func (r *TokenRevocationHandler) handleGetAccessTokenRequester(ctx context.Context, token string) (requester oauth2.Requester, tokenType oauth2.TokenType, err error) {
	signature := r.AccessTokenStrategy.AccessTokenSignature(ctx, token)

	requester, err = r.TokenRevocationStorage.GetAccessTokenSession(ctx, signature, nil)

	return requester, consts.TokenTypeAccessToken, err
}

func (r *TokenRevocationHandler) handleErrors(errs []error) (err error) {
	if len(errs) == 0 {
		return nil
	}

	for _, e := range errs {
		if !errors.Is(e, oauth2.ErrNotFound) && !errors.Is(e, oauth2.ErrInactiveToken) {
			return errorsx.WithStack(oauth2.ErrTemporarilyUnavailable)
		}
	}

	return nil
}
