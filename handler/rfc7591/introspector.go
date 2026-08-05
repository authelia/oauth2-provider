// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"errors"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/x/errorsx"
)

// ClientRegistrationTokenIntrospector is an oauth2.TokenIntrospector which resolves RFC 7591 / RFC 7592 client
// registration tokens. It is opt-in: introspection is enabled by registering this handler (see
// compose.RFC7591ClientRegistrationTokenIntrospectionFactory), not by configuration, so registration tokens are
// invisible at the introspection endpoint unless a deployment composes it in.
//
// It reports oauth2.ClientRegistrationToken as the token use rather than oauth2.AccessToken, and that distinction is
// a security control. The introspection endpoint permits a caller to authenticate with a bearer token, resolving the
// caller's identity from that token's client; a creation token's client is the privileged client that was issued it.
// Fosite.handleNewIntrospectionRequestClientAuthentication rejects any token whose use is not access_token, so
// reporting the true use keeps a registration token from being spent as a credential even where introspecting one is
// permitted.
type ClientRegistrationTokenIntrospector struct {
	Store    Storage
	Strategy ClientRegistrationTokenStrategy
	Config   oauth2.RFC7591ClientRegistrationConfigProvider
}

// IntrospectToken implements oauth2.TokenIntrospector.
//
// The scopes parameter (the introspection request's optional 'scope' filter, see
// Fosite.IntrospectToken) is intentionally not applied here, unlike hoauth2.CoreValidator's access/refresh token
// introspection. A client registration token's GetGrantedScopes is the ceiling it permits the clients it registers
// or manages to be granted (see CheckGrantableScopes), not a scope of the token's own access in the ordinary sense -
// and is not what an introspection 'scope' filter means. Matching against it would therefore reject a caller's
// filter based on a set of values that describe delegated authority rather than the token's own access, which is not
// a meaningful safeguard, only a footgun for whoever enables introspection. If a deployment needs scope-shaped
// filtering over registration tokens, it should be built against GetGrantedScopes explicitly rather than layered
// onto this parameter.
func (v *ClientRegistrationTokenIntrospector) IntrospectToken(ctx context.Context, token string, tokenUseHint oauth2.TokenUse, request oauth2.AccessRequester, _ []string) (use oauth2.TokenUse, err error) {
	signature := v.Strategy.ClientRegistrationTokenSignature(ctx, token)

	if signature == "" {
		return "", errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	var original oauth2.Requester

	if original, err = v.Store.GetClientRegistrationTokenSession(ctx, signature, request.GetSession()); err != nil {
		if errors.Is(err, oauth2.ErrNotFound) {
			return "", errorsx.WithStack(oauth2.ErrUnknownRequest)
		}

		return "", errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithWrap(err).WithDebugError(err))
	}

	if err = v.Strategy.ValidateClientRegistrationToken(ctx, original, token); err != nil {
		return "", err
	}

	request.Merge(original)

	return oauth2.ClientRegistrationToken, nil
}

var _ oauth2.TokenIntrospector = (*ClientRegistrationTokenIntrospector)(nil)
