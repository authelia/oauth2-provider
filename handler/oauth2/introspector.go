// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"errors"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/x/errorsx"
)

type CoreValidatorConfigProvider interface {
	oauth2.ScopeStrategyProvider
	oauth2.DisableRefreshTokenValidationProvider
}

type CoreValidator struct {
	CoreStrategy
	CoreStorage
	Config CoreValidatorConfigProvider
}

// IntrospectToken resolves and validates the token as an access token or a refresh token, trying the kind named by the
// hint first and the other kind second, and returns the kind it was accepted as. Only the access token path is tried
// when refresh token validation is disabled. When both paths fail a definite rejection is returned in preference to
// oauth2.ErrUnknownRequest.
func (c *CoreValidator) IntrospectToken(ctx context.Context, token string, tokenUseHint oauth2.TokenUse, request oauth2.AccessRequester, scopes []string) (use oauth2.TokenUse, err error) {
	if len(token) == 0 {
		return "", oauth2.ErrRequestUnauthorized.WithDebugf("The request either had a malformed Authorization header or didn't include a bearer token.")
	}

	if c.Config.GetDisableRefreshTokenValidation(ctx) {
		if err = c.introspectAccessToken(ctx, token, request, scopes); err != nil {
			return "", err
		}

		return oauth2.AccessToken, nil
	}

	if tokenUseHint == oauth2.RefreshToken {
		if err = c.introspectRefreshToken(ctx, token, request, scopes); err == nil {
			return oauth2.RefreshToken, nil
		} else if accessErr := c.introspectAccessToken(ctx, token, request, scopes); accessErr == nil {
			// The token is an access token despite the refresh token hint.
			return oauth2.AccessToken, nil
		} else {
			// A definite rejection from either path wins over ErrUnknownRequest.
			err = preferDefiniteIntrospectionError(err, accessErr)
		}

		return "", err
	}

	if err = c.introspectAccessToken(ctx, token, request, scopes); err == nil {
		return oauth2.AccessToken, nil
	} else if refreshErr := c.introspectRefreshToken(ctx, token, request, scopes); refreshErr == nil {
		// The token is a refresh token despite the access token hint or default.
		return oauth2.RefreshToken, nil
	} else {
		// See the symmetric comment above: prefer whichever error is a definite rejection over ErrUnknownRequest.
		err = preferDefiniteIntrospectionError(err, refreshErr)
	}

	return "", err
}

// preferDefiniteIntrospectionError chooses which of two introspection failures IntrospectToken should return when
// neither path succeeded. It returns secondary when primary is oauth2.ErrUnknownRequest and secondary is a definite
// rejection, otherwise primary, so a token one path recognised and rejected is not reported as merely unknown.
func preferDefiniteIntrospectionError(primary, secondary error) error {
	if errors.Is(primary, oauth2.ErrUnknownRequest) && !errors.Is(secondary, oauth2.ErrUnknownRequest) {
		return secondary
	}

	return primary
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

// clientRegistrationTokenFormatStrategy recognises an RFC 7591 / RFC 7592 client registration token by its format
// alone, without resolving it. HMACCoreStrategy implements it, and JWTProfileCoreStrategy inherits it by embedding
// that strategy; a CoreStrategy that does not implement it simply mints no distinguishable registration token format
// and so has nothing for isClientRegistrationToken to recognise.
type clientRegistrationTokenFormatStrategy interface {
	IsOpaqueClientRegistrationToken(ctx context.Context, tokenString string) (is bool)
}

// isClientRegistrationToken reports whether the configured CoreStrategy recognises token as an RFC 7591 / RFC 7592
// client registration token purely by its format - which, for a prefixed strategy, is exactly the case in which the
// access and refresh token signatures come back empty. See introspectAccessToken for why that distinction matters.
func (c *CoreValidator) isClientRegistrationToken(ctx context.Context, token string) (is bool) {
	strategy, ok := c.CoreStrategy.(clientRegistrationTokenFormatStrategy)

	return ok && strategy.IsOpaqueClientRegistrationToken(ctx, token)
}

// introspectAccessToken resolves and validates an access token for introspection.
//
// A session that is not found, or an empty signature on a token recognised as a client registration token, returns
// oauth2.ErrUnknownRequest so Fosite.IntrospectToken continues to the next oauth2.TokenIntrospector, which aborts on
// any other error. Every other failure MUST NOT be downgraded to ErrUnknownRequest.
func (c *CoreValidator) introspectAccessToken(ctx context.Context, token string, request oauth2.AccessRequester, scopes []string) (err error) {
	signature := c.AccessTokenSignature(ctx, token)

	if len(signature) == 0 {
		if c.isClientRegistrationToken(ctx, token) {
			return errorsx.WithStack(oauth2.ErrUnknownRequest)
		}

		return errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithWrap(oauth2.ErrNotFound).WithDebugError(oauth2.ErrNotFound))
	}

	var original oauth2.Requester

	if original, err = c.GetAccessTokenSession(ctx, signature, request.GetSession()); err != nil {
		if errors.Is(err, oauth2.ErrNotFound) {
			return errorsx.WithStack(oauth2.ErrUnknownRequest)
		}

		return errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithWrap(err).WithDebugError(err))
	}

	if err = c.ValidateAccessToken(ctx, original, token); err != nil {
		return err
	}

	if err = matchScopes(oauth2.GetScopeStrategy(ctx, c.Config, original.GetClient()), original.GetGrantedScopes(), scopes); err != nil {
		return err
	}

	request.Merge(original)

	return nil
}

// introspectRefreshToken resolves and validates a refresh token for introspection. See introspectAccessToken for why
// a not-found lookup, and an empty signature on a recognised client registration token, become
// oauth2.ErrUnknownRequest while every other failure keeps returning oauth2.ErrRequestUnauthorized; the same
// reasoning applies here. Both paths need the check: IntrospectToken calls each in turn and a definite rejection
// from either aborts the dispatch loop.
func (c *CoreValidator) introspectRefreshToken(ctx context.Context, token string, request oauth2.AccessRequester, scopes []string) (err error) {
	signature := c.RefreshTokenSignature(ctx, token)

	if len(signature) == 0 {
		if c.isClientRegistrationToken(ctx, token) {
			return errorsx.WithStack(oauth2.ErrUnknownRequest)
		}

		return errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithWrap(oauth2.ErrNotFound).WithDebugError(oauth2.ErrNotFound))
	}

	var original oauth2.Requester

	if original, err = c.GetRefreshTokenSession(ctx, signature, request.GetSession()); err != nil {
		if errors.Is(err, oauth2.ErrNotFound) {
			return errorsx.WithStack(oauth2.ErrUnknownRequest)
		}

		return errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithWrap(err).WithDebugError(err))
	}

	if err = c.ValidateRefreshToken(ctx, original, token); err != nil {
		return err
	}

	if err = matchScopes(oauth2.GetScopeStrategy(ctx, c.Config, original.GetClient()), original.GetGrantedScopes(), scopes); err != nil {
		return err
	}

	request.Merge(original)

	return nil
}

var (
	_ oauth2.TokenIntrospector = (*CoreValidator)(nil)
)
