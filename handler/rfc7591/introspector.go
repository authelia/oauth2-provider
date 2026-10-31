// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"errors"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/x/errorsx"
)

// ClientRegistrationTokenIntrospector is an oauth2.TokenIntrospector which resolves RFC 7591 / RFC 7592 client
// registration tokens. It is opt-in: introspection is enabled by registering this handler (see
// compose.RFC7591ClientRegistrationTokenIntrospectionFactory), not by configuration.
//
// It reports oauth2.ClientRegistrationToken as the token use, never oauth2.AccessToken, so a registration token cannot
// authenticate a caller of the introspection endpoint.
type ClientRegistrationTokenIntrospector struct {
	Store    Storage
	Strategy ClientRegistrationTokenStrategy
	Config   oauth2.RFC7591ClientRegistrationConfigProvider
}

// IntrospectToken implements oauth2.TokenIntrospector. A client registration token's granted scopes, audience and
// resource are the ceilings it may grant to clients (see CheckGrantableScopes), not the token's own access, so the
// scopes filter is not applied and none of them are reported. RFC 7592 Appendix A limits the token to the client
// configuration endpoint, which is the only audience reported.
//
// See: https://datatracker.ietf.org/doc/html/rfc7592#appendix-A
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

		return "", errorsx.WithStack(hoauth2.IntrospectionStorageError(err))
	}

	if err = v.Strategy.ValidateClientRegistrationToken(ctx, original, token); err != nil {
		return "", err
	}

	reported := &oauth2.Request{
		ID:          original.GetID(),
		RequestedAt: original.GetRequestedAt(),
		Client:      original.GetClient(),
		Form:        original.GetRequestForm(),
		Session:     original.GetSession(),
	}

	if audience := ClientConfigurationURL(v.Config.GetRFC7591ClientRegistrationEndpointURL(ctx), original.GetClient().GetID()); original.GetGrantedAudience().Has(audience) {
		reported.GrantAudience(audience)
	}

	request.Merge(reported)

	return oauth2.ClientRegistrationToken, nil
}

var _ oauth2.TokenIntrospector = (*ClientRegistrationTokenIntrospector)(nil)
