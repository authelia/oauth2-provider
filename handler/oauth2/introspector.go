// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/x/errorsx"
)

type coreValidatorConfigProvider interface {
	oauth2.ScopeStrategyProvider
	oauth2.DisableRefreshTokenValidationProvider
}

var _ oauth2.TokenIntrospector = (*CoreValidator)(nil)

type CoreValidator struct {
	CoreStrategy
	CoreStorage
	Config coreValidatorConfigProvider
}

func (c *CoreValidator) IntrospectToken(ctx context.Context, token string, tokenUseHint oauth2.TokenUse, requester oauth2.AccessRequester, scopes []string) (tokenUse oauth2.TokenUse, err error) {
	if len(token) == 0 {
		return "", oauth2.ErrRequestUnauthorized.WithDebugf("The request either had a malformed Authorization header or didn't include a bearer token.")
	}

	if c.Config.GetDisableRefreshTokenValidation(ctx) {
		if err = c.introspectAccessToken(ctx, token, requester, scopes); err != nil {
			return "", err
		}

		return oauth2.AccessToken, nil
	}

	if tokenUseHint == oauth2.RefreshToken {
		if err = c.introspectRefreshToken(ctx, token, requester, scopes); err == nil {
			return oauth2.RefreshToken, nil
		} else if err := c.introspectAccessToken(ctx, token, requester, scopes); err == nil {
			// The shadowing here is intentional, we should always return the Refresh Token Error as the token cannot be
			// introspected, and the provided hint was that the token should be an Refresh Token. By shadowing we leave the
			// original error from introspectRefreshToken intact.
			return oauth2.AccessToken, nil
		}

		return "", err
	}

	if err = c.introspectAccessToken(ctx, token, requester, scopes); err == nil {
		return oauth2.AccessToken, nil
	} else if err := c.introspectRefreshToken(ctx, token, requester, scopes); err == nil {
		// The shadowing here is intentional, we should always return the Access Token Error as the token cannot be
		// introspected, and the provided hint was that the token should be an Access Token. By shadowing we leave the
		// original error from introspectAccessToken intact.
		return oauth2.RefreshToken, nil
	}

	return "", err
}

func matchScopes(ss oauth2.ScopeStrategy, granted, scopes []string) error {
	for _, scope := range scopes {
		if scope == "" {
			continue
		}

		if !ss(granted, scope) {
			return errorsx.WithStack(oauth2.ErrInvalidScope.WithHintf("The request scope '%s' has not been granted or is not allowed to be requested.", scope))
		}
	}

	return nil
}

func (c *CoreValidator) introspectAccessToken(ctx context.Context, token string, requester oauth2.AccessRequester, scopes []string) (err error) {
	signature := c.AccessTokenSignature(ctx, token)

	var original oauth2.Requester

	if original, err = c.GetAccessTokenSession(ctx, signature, requester.GetSession()); err != nil {
		return errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithWrap(err).WithDebugError(err))
	}

	if err = c.ValidateAccessToken(ctx, original, token); err != nil {
		return err
	}

	if err = matchScopes(c.Config.GetScopeStrategy(ctx), original.GetGrantedScopes(), scopes); err != nil {
		return err
	}

	requester.Merge(original)

	return nil
}

func (c *CoreValidator) introspectRefreshToken(ctx context.Context, token string, requester oauth2.AccessRequester, scopes []string) (err error) {
	signature := c.RefreshTokenSignature(ctx, token)

	var original oauth2.Requester

	if original, err = c.GetRefreshTokenSession(ctx, signature, requester.GetSession()); err != nil {
		return errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithWrap(err).WithDebugError(err))
	}

	if err = c.ValidateRefreshToken(ctx, original, token); err != nil {
		return err
	}

	if err = matchScopes(c.Config.GetScopeStrategy(ctx), original.GetGrantedScopes(), scopes); err != nil {
		return err
	}

	requester.Merge(original)

	return nil
}
