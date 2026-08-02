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

// checkGrantableScopes enforces that the scopes requested in metadata are a subset of those the authenticated client
// registration session permits to be granted.
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
func checkGrantableScopes(ctx context.Context, config oauth2.ScopeStrategyProvider, authenticated oauth2.Requester, metadata *oauth2.ClientRegistrationMetadata) (err error) {
	if authenticated == nil || metadata == nil {
		return nil
	}

	session, ok := authenticated.GetSession().(Session)
	if !ok || !session.IsClientRegistration() {
		return nil
	}

	requested := metadata.GetScopes()
	if len(requested) == 0 {
		return nil
	}

	var (
		grantable = session.GetGrantableScopes()
		strategy  = oauth2.GetScopeStrategy(ctx, config, nil)
		excess    []string
	)

	for _, scope := range requested {
		if !strategy(grantable, scope) {
			excess = append(excess, scope)
		}
	}

	if len(excess) != 0 {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The request requested the scopes '%s' which the presented Client Registration Token is not permitted to grant.", strings.Join(excess, "', '")))
	}

	return nil
}
