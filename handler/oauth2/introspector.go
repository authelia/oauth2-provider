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
			// We should always return the Refresh Token Error as the token cannot be introspected, and the provided
			// hint was that the token should be a Refresh Token. By keeping err intact here we leave the original
			// error from introspectRefreshToken as the return value.
			return oauth2.AccessToken, nil
		} else {
			// Neither path recognised the token as its hinted kind. If introspectRefreshToken only failed because
			// the token was not found there (ErrUnknownRequest) while introspectAccessToken produced a definite
			// rejection (e.g. the token was found but expired), that definite rejection must win: the token was
			// recognised and rejected, not merely unrecognised. preferDefiniteIntrospectionError keeps
			// err as-is whenever it is already definite, or both errors are unknown.
			err = preferDefiniteIntrospectionError(err, accessErr)
		}

		return "", err
	}

	if err = c.introspectAccessToken(ctx, token, request, scopes); err == nil {
		return oauth2.AccessToken, nil
	} else if refreshErr := c.introspectRefreshToken(ctx, token, request, scopes); refreshErr == nil {
		// We should always return the Access Token Error as the token cannot be introspected, and the provided hint
		// was that the token should be an Access Token. By keeping err intact here we leave the original error from
		// introspectAccessToken as the return value.
		return oauth2.RefreshToken, nil
	} else {
		// See the symmetric comment above: prefer whichever error is a definite rejection over ErrUnknownRequest.
		err = preferDefiniteIntrospectionError(err, refreshErr)
	}

	return "", err
}

// preferDefiniteIntrospectionError chooses which of two introspection failures IntrospectToken should return when
// neither path succeeded. primary is the error from the path that matched the caller's hint (or the default path);
// secondary is the error from the other path.
//
// oauth2.ErrUnknownRequest means "this lookup found nothing", not "this token is invalid"; see introspectAccessToken.
// When primary is ErrUnknownRequest but secondary is a definite rejection, meaning the other path found the token and
// rejected it, returning primary would misreport a recognised-and-rejected token as merely unknown, and Fosite's
// dispatch loop treats ErrUnknownRequest as "not mine, try the next introspector" rather than aborting. Where both
// are definite or both unknown, primary is preserved.
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
// client registration token by its format alone, which for a prefixed strategy is the case in which the access and
// refresh token signatures come back empty. See introspectAccessToken for why that distinction matters.
func (c *CoreValidator) isClientRegistrationToken(ctx context.Context, token string) (is bool) {
	strategy, ok := c.CoreStrategy.(clientRegistrationTokenFormatStrategy)

	return ok && strategy.IsOpaqueClientRegistrationToken(ctx, token)
}

// introspectAccessToken resolves and validates an access token for introspection.
//
// A signature that fails to resolve to a stored session (oauth2.ErrNotFound from GetAccessTokenSession) becomes
// oauth2.ErrUnknownRequest rather than oauth2.ErrRequestUnauthorized. That distinction matters for composition:
// Fosite.IntrospectToken runs every registered oauth2.TokenIntrospector in turn and aborts the whole call on the
// first error that is not ErrUnknownRequest. Other token kinds, such as RFC 7591 / RFC 7592 client registration
// tokens which live in their own storage namespace, compute a signature like any other opaque token but are absent
// from access token storage, so reporting ErrUnknownRequest lets the dispatch loop move on to the introspector that
// owns the token.
//
// A prefixed strategy reaches the same conclusion one step earlier, since AccessTokenSignature returns an empty
// signature for a token carrying another kind's prefix. An empty signature is therefore only reported as
// ErrUnknownRequest when the strategy positively recognises the token as a client registration token, and stays
// ErrRequestUnauthorized otherwise, so a malformed credential is not reported as unrecognised. The loop aborts on a
// non-ErrUnknownRequest error from any introspector, so ordering the registration token introspector first is not an
// alternative to this check.
//
// Every other failure keeps returning ErrRequestUnauthorized. Downgrading an expired token, a scope mismatch, a
// signature validation failure, or a storage outage to ErrUnknownRequest would let a bad token fall through to other
// handlers and be reported as merely unrecognised.
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
