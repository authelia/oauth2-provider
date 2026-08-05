// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"strings"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/x/errorsx"
)

// ScopeCeilingConfig is the configuration CheckGrantableScopes depends on. It needs the scope strategy to compare
// with, and the registration scope so it can refuse to grant it onward.
type ScopeCeilingConfig interface {
	oauth2.ScopeStrategyProvider
	oauth2.RFC7591ClientRegistrationConfigProvider
}

// CheckGrantableScopes enforces that the scopes requested in metadata are a subset of those the authenticated
// client registration token was itself granted, and additionally refuses the client registration scope even though
// every client creation token holds it: granting it onward would let the registered client obtain creation tokens
// of its own and register further clients, registration authority replicating itself with no administrator
// approving the descendants.
//
// A request with no authenticated requester has no ceiling to enforce: RFC 7591 permits an open registration
// endpoint, and such a deployment has no creation token from which a ceiling could come. Deployments wanting a
// ceiling require authentication on the endpoint.
//
// An omitted or empty 'scope' registers the client with no scopes, so there is nothing to check.
//
// The comparison always uses the server's configured oauth2.ScopeStrategy, never a client-supplied one. No client is
// passed to oauth2.GetScopeStrategy for that reason: the ceiling is a server-side control over what a client may be
// granted, so letting the controlled party supply the comparison function through oauth2.ScopeStrategyProvider would
// be the wrong shape - and it would additionally make registration and update disagree, since only the latter has a
// registered client to hand.
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
		registration = config.GetRFC7591ClientRegistrationScope(ctx)
		strategy     = oauth2.GetScopeStrategy(ctx, config, nil)
		excess       []string
	)

	for _, scope := range requested {
		// The registration scope is never grantable onward, even though every client creation token holds it.
		// Granting it would let the registered client obtain creation tokens of its own.
		if scope == registration || !strategy(grantable, scope) {
			excess = append(excess, scope)
		}
	}

	if len(excess) != 0 {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The request requested the scopes '%s' which the presented Client Registration Token is not permitted to grant.", strings.Join(excess, "', '")))
	}

	return nil
}

// ExcludeRegistrationScope removes the client registration scope from scopes, if present. It is the ceiling-side
// counterpart to the exclusion CheckGrantableScopes enforces on requested scopes: every legitimate creation token
// carries the registration scope by design, so without this the management token minted at registration - and every
// one minted at a later rotation - would carry it forward permanently, letting the registered client obtain creation
// tokens of its own and register further clients unchecked. Excluding it only from CheckGrantableScopes would close
// the update path (a request may not ask for the scope) while leaving the management token itself able to carry it,
// which is the hole that matters most: the scope would sit in the token's own granted scopes regardless of what any
// future request asks for, observable wherever that token's grant is read back - including client registration
// token introspection, where opt-in.
//
// Callers apply this to whatever scopes they are about to hand to NewClientManagementToken as its ceiling, whether
// that ceiling came from an authenticated creation token's own grant or, on an unauthenticated (open) registration
// endpoint, from the request's own metadata. It covers the token half only: the scopes the registered client itself
// is stored with are covered by ExcludeRegistrationScopeFromMetadata, which every registration path must also call.
func ExcludeRegistrationScope(ctx context.Context, config oauth2.RFC7591ClientRegistrationConfigProvider, scopes oauth2.Arguments) (filtered oauth2.Arguments) {
	registration := config.GetRFC7591ClientRegistrationScope(ctx)

	for _, scope := range scopes {
		if scope != registration {
			filtered = append(filtered, scope)
		}
	}

	return filtered
}

// ExcludeRegistrationScopeFromMetadata removes the client registration scope from the 'scope' a registration request
// asks for, so it can never end up on the registered client itself.
//
// It is the third and last place the exclusion is applied, and the only one that covers an **unauthenticated** (open)
// registration endpoint, which RFC 7591 permits. On that path there is no creation token, so CheckGrantableScopes has
// no ceiling to enforce and returns early, and ExcludeRegistrationScope only ever filters the minted management
// token - leaving the requested scope itself untouched. A deployment running an open endpoint would therefore store a
// client whose own registered scopes contain the registration scope, and that client can then obtain creation tokens
// through client_credentials and keep registering clients long after the endpoint is closed again. That is the
// "tempting half-fix" this package's design warns about, in the one configuration where it still bites.
//
// Callers apply this after CheckGrantableScopes, never before: on the authenticated path a request that asks for the
// registration scope must be rejected outright rather than silently stripped, and CheckGrantableScopes is what
// rejects it. Applying it here as well is what makes the exclusion unconditional rather than conditional on a ceiling
// existing.
func ExcludeRegistrationScopeFromMetadata(ctx context.Context, config oauth2.RFC7591ClientRegistrationConfigProvider, metadata *oauth2.ClientRegistrationMetadata) {
	if metadata == nil || len(metadata.Scope) == 0 {
		return
	}

	metadata.Scope = strings.Join(ExcludeRegistrationScope(ctx, config, metadata.GetScopes()), " ")
}

// CheckGrantableAudience enforces that the audiences requested in metadata are a subset of those the authenticated
// client registration token was itself granted.
//
// It mirrors CheckGrantableScopes and carries the same reasoning. No client is passed to oauth2.GetAudienceStrategy:
// that helper prefers a client-supplied strategy when the client implements oauth2.AudienceStrategyProvider, and the
// ceiling is a server-side control over what the controlled party may be granted, so letting that party supply the
// comparison function would let a permissive strategy make every membership test succeed. CheckGrantableScopes passes
// nil to oauth2.GetScopeStrategy for the identical reason. Passing nil also gives the fallback to
// oauth2.DefaultAudienceStrategy when none is configured, which calling config.GetAudienceStrategy directly would
// not.
//
// An empty ceiling rejects every requested audience, which is the same shape as the scope ceiling: a token that was
// issued permitting no audiences may not grant any.
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
