// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"net/http"
	"strings"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// EndpointAuthStrategyConfig is the configuration DefaultEndpointAuthStrategy depends on.
type EndpointAuthStrategyConfig interface {
	oauth2.RFC7591ClientRegistrationConfigProvider
}

// DefaultEndpointAuthStrategy is the oauth2.ClientRegistrationEndpointAuthStrategy used to authenticate requests to
// the client registration (RFC 7591) and client configuration (RFC 7592) endpoints.
//
// Both endpoints are authenticated by ordinary access tokens. What makes a token a client registration token is its
// session: a Session whose Kind is KindCreate may register new clients, and one whose Kind is KindManage may manage
// the single client named by its subject. An ordinary access token hydrates to KindNone and is rejected.
type DefaultEndpointAuthStrategy struct {
	Config   EndpointAuthStrategyConfig
	Store    Storage
	Strategy hoauth2.AccessTokenStrategy
}

var _ oauth2.ClientRegistrationEndpointAuthStrategy = (*DefaultEndpointAuthStrategy)(nil)

// NewDefaultEndpointAuthStrategy returns a new *DefaultEndpointAuthStrategy.
func NewDefaultEndpointAuthStrategy(config EndpointAuthStrategyConfig, store Storage, strategy hoauth2.AccessTokenStrategy) (auth *DefaultEndpointAuthStrategy) {
	return &DefaultEndpointAuthStrategy{
		Config:   config,
		Store:    store,
		Strategy: strategy,
	}
}

// AuthenticateClientRegistrationRequest implements oauth2.ClientRegistrationEndpointAuthStrategy. id is empty for a
// client registration request (RFC 7591) and carries the target client id for a client configuration request
// (RFC 7592).
//
// The checks below run in a fixed order, each a precondition of the next:
//
//  1. Exactly one Authorization header is present, using the Bearer scheme (case-insensitively), with a non-empty
//     remainder.
//  2. The token yields a non-empty access token signature.
//  3. That signature resolves to a stored access token session.
//  4. The session is a client registration session at all.
//  5. Its kind matches the endpoint: KindCreate for registration, KindManage for configuration. This and the previous
//     check are what separate a registration token from any other access token, replacing the token prefix gate the
//     dedicated token type used to provide.
//  6. The token itself validates against that session (signature and expiry).
//  7. Its granted audience contains the URL this request was made to, which prevents a management token issued for
//     one client being replayed against another.
//  8. On the client configuration endpoint only (id non-empty), the session subject equals id.
//
// Every failure returns oauth2.ErrRequestUnauthorized. Storage and token validation errors are attached with
// WithWrap and WithDebugError only, never surfaced in the client-facing hint, so a storage error cannot let an
// attacker distinguish an unknown token from an expired one.
func (s *DefaultEndpointAuthStrategy) AuthenticateClientRegistrationRequest(ctx context.Context, r *http.Request, id string) (requester oauth2.Requester, err error) {
	var tokenString string

	if tokenString, err = bearerToken(r); err != nil {
		return nil, err
	}

	// An access token that is malformed below any prefix yields an empty signature, which can never be a legitimate
	// lookup key, so it is rejected here rather than spent on a storage round trip.
	signature := s.Strategy.AccessTokenSignature(ctx, tokenString)

	if signature == "" {
		return nil, errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithHint("The provided credential does not appear to be a Client Registration Token."))
	}

	if requester, err = s.Store.GetAccessTokenSession(ctx, signature, NewDefaultSession()); err != nil {
		return nil, errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithHint("The provided Client Registration Token is not valid.").WithWrap(err).WithDebugError(err))
	}

	var (
		session Session
		ok      bool
	)

	if session, ok = requester.GetSession().(Session); !ok || !session.IsClientRegistration() {
		return nil, errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithHint("The provided credential does not appear to be a Client Registration Token."))
	}

	expected := KindCreate

	if len(id) != 0 {
		expected = KindManage
	}

	if session.GetClientRegistrationKind() != expected {
		return nil, errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithHint("The provided Client Registration Token is not permitted to be used at this endpoint."))
	}

	if err = s.Strategy.ValidateAccessToken(ctx, requester, tokenString); err != nil {
		return nil, errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithHint("The provided Client Registration Token is not valid.").WithWrap(err).WithDebugError(err))
	}

	audience := oauth2.RequestURL(r)
	if !requester.GetGrantedAudience().Has(audience) {
		return nil, errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithHintf("The provided Client Registration Token is not permitted to be used at '%s'.", audience))
	}

	// Defence in depth on the client configuration endpoint: the audience check above already binds the token to this
	// one client, since a management token's audience is that client's own registration_client_uri.
	if len(id) != 0 && session.GetSubject() != id {
		return nil, errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithHintf("The provided Client Registration Token is not permitted to manage the client with id '%s'.", id))
	}

	// The requester ID otherwise carries no meaning here; it is overwritten with the presented token's signature so a
	// caller that needs to delete this session later - such as the client configuration endpoint rotating the
	// management token on a PUT - can do so without re-deriving the signature from the request a second time.
	requester.SetID(signature)

	return requester, nil
}

// bearerToken extracts the token from a request's Authorization header. Exactly one such header must be present,
// using the Bearer scheme (case-insensitively), followed by a non-empty token.
func bearerToken(r *http.Request) (token string, err error) {
	values := r.Header.Values(consts.HeaderAuthorization)

	if len(values) != 1 {
		return "", errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithHint("The request must contain exactly one Authorization header."))
	}

	scheme, value, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, oauth2.BearerAccessToken) || value == "" {
		return "", errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithHint("The Authorization header must use the Bearer scheme."))
	}

	return value, nil
}
