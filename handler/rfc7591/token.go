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
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/x/errorsx"
)

// NonExpiringTokenLifespan is the lifespan applied to a client registration access token whose configured lifespan is
// zero, i.e. one documented as never expiring - the normal expectation for an RFC 7592 'registration_access_token',
// which has no re-issue path.
//
// A zero lifespan cannot simply leave the session's 'expires_at' unset. hoauth2.HMACCoreStrategy.ValidateAccessToken
// treats an unset access token expiry not as "no expiry" but as "expires at RequestedAt plus the global
// AccessTokenLifespan", so an unset expiry would silently retire the token after one hour by default; under
// EnforceJWTProfileAccessTokens no 'exp' claim would be emitted at all and the very same configuration would produce a
// token that genuinely never expires. Recording an explicit far-future expiry instead makes both strategies agree and
// makes "never expires" mean what it says.
//
// A century is chosen because it is unambiguously beyond any deployment's horizon while remaining far away from
// time.Time's and time.Duration's limits, so it serialises safely into a JWT 'exp' claim as seconds since the epoch.
const NonExpiringTokenLifespan = 100 * 365 * 24 * time.Hour

// ClientConfigurationURL returns the RFC 7592 'registration_client_uri' for the client with the given id.
func ClientConfigurationURL(endpoint, id string) (uri string) {
	return strings.TrimSuffix(endpoint, "/") + "/" + url.PathEscape(id)
}

// NewClientCreationToken mints an access token permitting the holder to register new clients. Its granted audience is
// the client registration endpoint, its client is the client that obtained it, and its grantable scopes are the
// ceiling for any client registered with it. The token string is the only opportunity to read the value; only its
// signature is stored.
func NewClientCreationToken(ctx context.Context, strategy hoauth2.AccessTokenStrategy, store Storage, config oauth2.RFC7591ClientRegistrationConfigProvider, client oauth2.Client, scopes oauth2.Arguments) (tokenString string, err error) {
	session := NewDefaultSession()
	session.SetClientRegistrationKind(KindCreate)
	session.SetGrantableScopes(scopes)

	lifespan := oauth2.GetEffectiveLifespan(client, oauth2.GrantType(""), oauth2.AccessToken, config.GetRFC7591ClientRegistrationCreateTokenLifespan(ctx))

	return newClientRegistrationToken(ctx, strategy, store, client, session, config.GetRFC7591ClientRegistrationEndpointURL(ctx), lifespan)
}

// NewClientManagementToken mints an access token permitting the holder to manage exactly one registered client. It
// binds to that client, is audienced to that client's registration_client_uri, carries the client's id as its
// subject, and carries forward the grantable scope ceiling so an update cannot escalate beyond it.
func NewClientManagementToken(ctx context.Context, strategy hoauth2.AccessTokenStrategy, store Storage, config oauth2.RFC7591ClientRegistrationConfigProvider, client oauth2.Client, scopes oauth2.Arguments) (tokenString string, err error) {
	id := client.GetID()

	session := NewDefaultSession()
	session.SetClientRegistrationKind(KindManage)
	session.SetGrantableScopes(scopes)
	session.SetSubject(id)

	lifespan := oauth2.GetEffectiveLifespan(client, oauth2.GrantType(""), oauth2.AccessToken, config.GetRFC7591ClientRegistrationManageTokenLifespan(ctx))

	return newClientRegistrationToken(ctx, strategy, store, client, session, ClientConfigurationURL(config.GetRFC7591ClientRegistrationEndpointURL(ctx), id), lifespan)
}

// newClientRegistrationToken mints and persists a client registration access token. A zero lifespan means the token
// never expires, which RFC 7592 permits for registration access tokens; it is recorded as NonExpiringTokenLifespan
// rather than as no expiry at all, for the reasons given on that constant.
func newClientRegistrationToken(ctx context.Context, strategy hoauth2.AccessTokenStrategy, store Storage, client oauth2.Client, session *DefaultSession, audience string, lifespan time.Duration) (tokenString string, err error) {
	if lifespan <= 0 {
		lifespan = NonExpiringTokenLifespan
	}

	session.SetExpiresAt(oauth2.AccessToken, time.Now().UTC().Add(lifespan))

	requester := oauth2.NewRequest()
	requester.Session = session

	// NewRequest supplies a non-nil default client which must be preserved when the caller supplies none: the
	// persisted session is read back by machinery such as handler/oauth2.TokenRevocationHandler, which dereferences
	// the requester's client without a nil guard.
	if client != nil {
		requester.Client = client
	}

	requester.GrantAudience(audience)

	var signature string

	if tokenString, signature, err = strategy.GenerateAccessToken(ctx, requester); err != nil {
		return "", errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	if err = store.CreateAccessTokenSession(ctx, signature, requester); err != nil {
		return "", errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	return tokenString, nil
}
