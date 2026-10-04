// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"slices"
	"strings"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/x/errorsx"
)

// ScopeCeilingConfig is the configuration CheckGrantableScopes depends on. It needs the scope strategy to compare
// with, and the registration scopes so it can refuse to grant any of them onward.
type ScopeCeilingConfig interface {
	oauth2.ScopeStrategyProvider
	oauth2.RFC7591ClientRegistrationConfigProvider
}

// CheckGrantableScopes enforces that the scopes requested in metadata are a subset of those the authenticated client
// registration token was itself granted. Every configured client registration scope, and any scope the configured
// oauth2.ScopeStrategy would match against one, is refused so that a registered client cannot obtain creation tokens of
// its own.
//
// A request with no authenticated requester has no ceiling to enforce; deployments wanting a ceiling require
// authentication on the endpoint. The comparison always uses the server's configured oauth2.ScopeStrategy, never a
// client-supplied one.
func CheckGrantableScopes(ctx context.Context, config ScopeCeilingConfig, authenticated oauth2.Requester, metadata *oauth2.ClientRegistrationMetadata) (err error) {
	if authenticated == nil || metadata == nil {
		return nil
	}

	requested := metadata.GetScopes()
	if len(requested) == 0 {
		return nil
	}

	var (
		grantable    = authenticated.GetGrantedScopes()
		registration = config.GetRFC7591ClientRegistrationScopes(ctx)
		strategy     = oauth2.GetScopeStrategy(ctx, config, nil)
		excess       []string
	)

	for _, scope := range requested {
		// No registration scope is ever grantable onward, even though every client creation token holds one of them.
		// Granting one would let the registered client obtain creation tokens of its own.
		if isRegistrationScope(ctx, config, registration, scope) || !strategy(grantable, scope) {
			excess = append(excess, scope)
		}
	}

	if len(excess) != 0 {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The request requested the scopes '%s' which the presented Client Registration Token is not permitted to grant.", strings.Join(excess, "', '")))
	}

	return nil
}

// ExcludeRegistrationScope removes every configured client registration scope from scopes, along with any scope the
// configured oauth2.ScopeStrategy would match against one when config provides it. Callers apply it to the scopes they
// hand to NewClientManagementToken as its ceiling, so a management token never carries a registration scope. The scopes
// the registered client is stored with are covered by ExcludeRegistrationScopeFromMetadata, which every registration
// path must also call.
func ExcludeRegistrationScope(ctx context.Context, config oauth2.RFC7591ClientRegistrationConfigProvider, scopes oauth2.Arguments) (filtered oauth2.Arguments) {
	registration := config.GetRFC7591ClientRegistrationScopes(ctx)

	for _, scope := range scopes {
		if !isRegistrationScope(ctx, config, registration, scope) {
			filtered = append(filtered, scope)
		}
	}

	return filtered
}

// ExcludeRegistrationScopeFromMetadata removes every configured client registration scope from the 'scope' a
// registration request asks for, so none can end up on the registered client itself, including on an unauthenticated
// registration endpoint where CheckGrantableScopes has no ceiling to enforce.
//
// Callers apply this after CheckGrantableScopes, never before: an authenticated request that asks for the registration
// scope must be rejected rather than silently stripped.
func ExcludeRegistrationScopeFromMetadata(ctx context.Context, config oauth2.RFC7591ClientRegistrationConfigProvider, metadata *oauth2.ClientRegistrationMetadata) {
	if metadata == nil || len(metadata.Scope) == 0 {
		return
	}

	metadata.Scope = strings.Join(ExcludeRegistrationScope(ctx, config, metadata.GetScopes()), " ")
}

// CheckGrantableAudience enforces that the audiences requested in metadata are a subset of those the authenticated
// client registration token was itself granted. The comparison always uses the server's configured audience strategy,
// never a client-supplied one, falling back to oauth2.DefaultAudienceStrategy. An empty ceiling rejects every requested
// audience.
func CheckGrantableAudience(ctx context.Context, config oauth2.AudienceStrategyProvider, authenticated oauth2.Requester, metadata *oauth2.ClientRegistrationMetadata) (err error) {
	if authenticated == nil || metadata == nil {
		return nil
	}

	if len(metadata.Audience) == 0 {
		return nil
	}

	if err = oauth2.GetAudienceStrategy(ctx, config, nil)(authenticated.GetGrantedAudience(), metadata.Audience); err != nil {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHint("The request requested an audience which the presented Client Registration Token is not permitted to grant.").WithWrap(err).WithDebugError(err))
	}

	return nil
}

// CheckGrantableResource enforces that the RFC 8707 resource indicators requested in metadata are within those the
// authenticated client registration token was itself granted. It mirrors CheckGrantableAudience, and passes no
// client to oauth2.GetResourceStrategy for the same reason.
func CheckGrantableResource(ctx context.Context, config oauth2.ResourceStrategyProvider, authenticated oauth2.Requester, metadata *oauth2.ClientRegistrationMetadata) (err error) {
	if authenticated == nil || metadata == nil {
		return nil
	}

	if len(metadata.Resource) == 0 {
		return nil
	}

	if err = oauth2.GetResourceStrategy(ctx, config, nil)(authenticated.GetGrantedResource(), metadata.Resource); err != nil {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHint("The request requested a resource which the presented Client Registration Token is not permitted to grant.").WithWrap(err).WithDebugError(err))
	}

	return nil
}

func isRegistrationScope(ctx context.Context, config any, registration []string, scope string) bool {
	if slices.Contains(registration, scope) {
		return true
	}

	provider, ok := config.(oauth2.ScopeStrategyProvider)
	if !ok {
		return false
	}

	strategy := oauth2.GetScopeStrategy(ctx, provider, nil)

	for _, value := range registration {
		if strategy([]string{scope}, value) {
			return true
		}
	}

	return false
}
