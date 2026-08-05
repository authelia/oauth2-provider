// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"net/url"
	"strings"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/x/errorsx"
)

// ClientConfigurationURL returns the RFC 7592 'registration_client_uri' for the client with the given id.
func ClientConfigurationURL(endpoint, id string) (uri string) {
	return strings.TrimSuffix(endpoint, "/") + "/" + url.PathEscape(id)
}

// NewClientManagementToken mints a client registration token permitting the holder to manage exactly one registered
// client. It binds to that client - which is how the token's managed client id is discovered, on the requester
// rather than the session, see DefaultEndpointAuthStrategy.authenticateClientConfiguration - is audienced to that
// client's registration_client_uri, and carries forward the grantable scope and grantable audience ceilings so an
// update cannot escalate beyond them.
func NewClientManagementToken(ctx context.Context, strategy ClientRegistrationTokenStrategy, store Storage, config oauth2.RFC7591ClientRegistrationConfigProvider, client oauth2.Client, scopes, audience oauth2.Arguments) (tokenString string, err error) {
	id := client.GetID()

	// A management token never expires, and neither configuration nor the client may change that. RFC 7592 provides
	// no way to re-issue a registration_access_token, so a client whose management token expired would permanently
	// lose the ability to read, update or delete its own registration and its client_id would be burned. The lifespan
	// is therefore not routed through oauth2.GetEffectiveLifespan, which would let a CustomTokenLifespansClient - the
	// controlled party - shorten the very credential that controls it.
	return newClientRegistrationToken(ctx, strategy, store, client, &oauth2.DefaultSession{}, ClientConfigurationURL(config.GetRFC7591ClientRegistrationEndpointURL(ctx), id), NonExpiringTokenLifespan, scopes, audience)
}

// newClientRegistrationToken mints and persists a client registration access token. A zero lifespan means the token
// never expires, which RFC 7592 permits for registration access tokens; it is recorded as NonExpiringTokenLifespan
// rather than as no expiry at all, for the reasons given on that constant.
//
// scopes and audience are the ceilings the minted token permits its holder to grant onward to the client it creates
// or manages; they are recorded as the requester's own granted scopes and granted audience - CheckGrantableScopes and
// CheckGrantableAudience read them back from there - alongside the endpoint audience every such token carries.
func newClientRegistrationToken(ctx context.Context, strategy ClientRegistrationTokenStrategy, store Storage, client oauth2.Client, session *oauth2.DefaultSession, audience string, lifespan time.Duration, scopes, ceilingAudience oauth2.Arguments) (tokenString string, err error) {
	if lifespan <= 0 {
		lifespan = NonExpiringTokenLifespan
	}

	session.SetExpiresAt(oauth2.AccessToken, time.Now().UTC().Add(lifespan))

	requester := oauth2.NewRequest()
	requester.Session = session

	// NewRequest supplies a non-nil default client which must be preserved when the caller supplies none: elsewhere in
	// this module Requester.GetClient is assumed non-nil - TokenValidationStrategy.ValidateIDToken's doc comment calls
	// out tolerating a nil client as an explicit deviation from that norm - so overwriting the well-formed default
	// with a nil interface value here would be a foot-gun for any code that later reads this session back.
	if client != nil {
		requester.Client = client
	}

	requester.GrantAudience(audience)

	for _, scope := range scopes {
		requester.GrantScope(scope)
	}

	for _, aud := range ceilingAudience {
		requester.GrantAudience(aud)
	}

	var signature string

	if tokenString, signature, err = strategy.GenerateClientRegistrationToken(ctx, requester); err != nil {
		return "", errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	if err = store.CreateClientRegistrationTokenSession(ctx, signature, requester); err != nil {
		return "", errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	return tokenString, nil
}
