// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
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
//
// The signature of a token is the key it is stored under, so presenting one does not show possession of the token. A
// token which is not intact is an invalid token, which RFC 7009 Section 2.2 answers with success and nothing revoked. An
// expired token is intact.
//
// A rotated refresh token presented by the client it was issued to revokes the grant, as RFC 7009 Section 2.1 permits and
// as the token endpoint does for a reused refresh token, so the tokens which replaced it do not outlive the revocation.
//
// See: https://datatracker.ietf.org/doc/html/rfc7009#section-2.2
// See: https://datatracker.ietf.org/doc/html/rfc9700#section-4.14.2
func (r *TokenRevocationHandler) RevokeToken(ctx context.Context, token string, tokenType oauth2.TokenType, client oauth2.Client) (err error) {
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
		request, inactive oauth2.Requester
		tt                oauth2.TokenType
		errs              []error
	)

	for _, handler := range handlers {
		if request, tt, err = handler(ctx, token); err == nil {
			break
		}

		if tt == oauth2.RefreshToken && request != nil && errors.Is(err, oauth2.ErrInactiveToken) {
			inactive = request
		}

		errs = append(errs, err)
	}

	if len(errs) == len(handlers) {
		if inactive == nil {
			return r.handleErrors(errs)
		}

		if err = r.RefreshTokenStrategy.ValidateRefreshToken(ctx, inactive, token); !IsIntactToken(err) {
			if !IsTokenRejection(err) {
				errs = append(errs, err)
			}

			return r.handleErrors(errs)
		}

		request, tt = inactive, oauth2.RefreshToken
	}

	if request.GetClient().GetID() != client.GetID() {
		return errorsx.WithStack(oauth2.ErrUnauthorizedClient)
	}

	id := request.GetID()

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

type RevocationTokenLookupFunc func(ctx context.Context, token string) (request oauth2.Requester, tokenType oauth2.TokenType, err error)

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

func (r *TokenRevocationHandler) handleGetRefreshTokenRequester(ctx context.Context, token string) (request oauth2.Requester, tokenType oauth2.TokenType, err error) {
	signature := r.RefreshTokenStrategy.RefreshTokenSignature(ctx, token)

	if request, err = r.TokenRevocationStorage.GetRefreshTokenSession(ctx, signature, nil); err != nil {
		return request, consts.TokenTypeRefreshToken, err
	}

	if err = validateRevokedToken(r.RefreshTokenStrategy.ValidateRefreshToken(ctx, request, token)); err != nil {
		return nil, consts.TokenTypeRefreshToken, err
	}

	return request, consts.TokenTypeRefreshToken, nil
}

func (r *TokenRevocationHandler) handleGetAccessTokenRequester(ctx context.Context, token string) (request oauth2.Requester, tokenType oauth2.TokenType, err error) {
	signature := r.AccessTokenStrategy.AccessTokenSignature(ctx, token)

	if request, err = r.TokenRevocationStorage.GetAccessTokenSession(ctx, signature, nil); err != nil {
		return request, consts.TokenTypeAccessToken, err
	}

	if err = validateRevokedToken(r.AccessTokenStrategy.ValidateAccessToken(ctx, request, token)); err != nil {
		return nil, consts.TokenTypeAccessToken, err
	}

	return request, consts.TokenTypeAccessToken, nil
}

func validateRevokedToken(err error) error {
	switch {
	case IsIntactToken(err):
		return nil
	case IsTokenRejection(err):
		return oauth2.ErrNotFound
	default:
		return err
	}
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

var (
	_ oauth2.RevocationHandler = (*TokenRevocationHandler)(nil)
)
