// SPDX-FileCopyrightText: 2026 Authelia
//
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

func (c *CoreValidator) IntrospectToken(ctx context.Context, token string, tokenUseHint oauth2.TokenUse, request oauth2.AccessRequester, scopes []string) (tokenUse oauth2.TokenUse, err error) {
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
		} else if err := c.introspectAccessToken(ctx, token, request, scopes); err == nil {
			// The shadowing here is intentional, we should always return the Refresh Token Error as the token cannot be
			// introspected, and the provided hint was that the token should be an Refresh Token. By shadowing we leave the
			// original error from introspectRefreshToken intact.
			return oauth2.AccessToken, nil
		}

		return "", err
	}

	if err = c.introspectAccessToken(ctx, token, request, scopes); err == nil {
		return oauth2.AccessToken, nil
	} else if err := c.introspectRefreshToken(ctx, token, request, scopes); err == nil {
		// The shadowing here is intentional, we should always return the Access Token Error as the token cannot be
		// introspected, and the provided hint was that the token should be an Access Token. By shadowing we leave the
		// original error from introspectAccessToken intact.
		return oauth2.RefreshToken, nil
	}

	return "", err
}

// isClientRegistrationSession reports whether a session backs an RFC 7591 / RFC 7592 client registration access
// token. Those tokens are ordinary access tokens living in ordinary access token storage, so nothing else
// distinguishes them here, and a token minted purely to onboard clients must never double as a bearer credential
// authenticating its holder as that client at the introspection endpoint (see
// Fosite.handleNewIntrospectionRequestClientAuthentication), nor as an introspectable or exchangeable token.
//
// The behaviour is expressed as a local one-method interface rather than by asserting to handler/rfc7591.Session
// because handler/rfc7591 imports this package; *rfc7591.DefaultSession satisfies it.
func isClientRegistrationSession(session oauth2.Session) (is bool) {
	registration, ok := session.(interface{ IsClientRegistration() bool })

	return ok && registration.IsClientRegistration()
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

func (c *CoreValidator) introspectAccessToken(ctx context.Context, token string, request oauth2.AccessRequester, scopes []string) (err error) {
	signature := c.AccessTokenSignature(ctx, token)

	if len(signature) == 0 {
		return errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithWrap(oauth2.ErrNotFound).WithDebugError(oauth2.ErrNotFound))
	}

	var original oauth2.Requester

	if original, err = c.GetAccessTokenSession(ctx, signature, request.GetSession()); err != nil {
		return errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithWrap(err).WithDebugError(err))
	}

	if isClientRegistrationSession(original.GetSession()) {
		return errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithDebug("The token is a client registration token which may only be presented at the client registration and client configuration endpoints."))
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

func (c *CoreValidator) introspectRefreshToken(ctx context.Context, token string, request oauth2.AccessRequester, scopes []string) (err error) {
	signature := c.RefreshTokenSignature(ctx, token)

	if len(signature) == 0 {
		return errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithWrap(oauth2.ErrNotFound).WithDebugError(oauth2.ErrNotFound))
	}

	var original oauth2.Requester

	if original, err = c.GetRefreshTokenSession(ctx, signature, request.GetSession()); err != nil {
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
