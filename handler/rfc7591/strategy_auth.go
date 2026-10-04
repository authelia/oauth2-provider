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

// EndpointAuthStrategyConfig is the configuration DefaultEndpointAuthStrategy depends on. It names the DPoP and mTLS
// providers required by oauth2.BearerAuthorizationConfig, as the client registration endpoint checks the
// proof-of-possession binding of the creation token it is presented with. It names no scope or audience strategy
// provider, as the required audience and scope are matched by exact containment.
type EndpointAuthStrategyConfig interface {
	oauth2.RFC7591ClientRegistrationConfigProvider
	oauth2.DPoPConfigProvider
	oauth2.MTLSConfigProvider
}

// DefaultEndpointAuthStrategy is the oauth2.ClientRegistrationEndpointAuthStrategy used to authenticate requests to
// the client registration (RFC 7591) and client configuration (RFC 7592) endpoints.
//
// The two endpoints take two different credentials, from two different storage namespaces:
//
//   - The client registration endpoint takes an ordinary access token, obtained through the token endpoint like any
//     other and resolved from access token storage. It is authorised by its granted audience containing this
//     endpoint's audience exactly and its granted scopes containing the configured registration scope exactly.
//   - The client configuration endpoint takes a client management token, which lives in its own storage namespace,
//     never expires, and is audienced at exactly one client's registration_client_uri.
//
// Each branch consults exactly one of the two namespaces, which is what keeps a token of one kind from being
// presented at the other's endpoint.
type DefaultEndpointAuthStrategy struct {
	Config              EndpointAuthStrategyConfig
	Store               Storage
	Strategy            ClientRegistrationTokenStrategy
	AccessTokenStrategy hoauth2.AccessTokenStrategy
}

// NewDefaultEndpointAuthStrategy returns a new *DefaultEndpointAuthStrategy.
func NewDefaultEndpointAuthStrategy(config EndpointAuthStrategyConfig, store Storage, strategy ClientRegistrationTokenStrategy, access hoauth2.AccessTokenStrategy) (auth *DefaultEndpointAuthStrategy) {
	return &DefaultEndpointAuthStrategy{
		Config:              config,
		Store:               store,
		Strategy:            strategy,
		AccessTokenStrategy: access,
	}
}

// AuthenticateClientRegistrationRequest implements oauth2.ClientRegistrationEndpointAuthStrategy. id is empty for a
// client registration request (RFC 7591) and carries the target client id for a client configuration request (RFC
// 7592).
//
// Exactly one Authorization header must be present, with a non-empty remainder. The client registration endpoint
// accepts Bearer (RFC 6750) and DPoP (RFC 9449 Section 7.1); the client configuration endpoint accepts Bearer only,
// because a management token can never be bound.
//
// The client registration branch reports:
//
//   - oauth2.ErrInvalidRequest (400) when more than one Authorization header is present, per RFC 9449
//     Section 7.2 Figure 19.
//   - oauth2.ErrInsufficientScope (403) when the credential holds none of the required scopes, per RFC 6750
//     Section 3.1.
//   - oauth2.ErrInvalidDPoPProof or oauth2.ErrUseDPoPNonce for a failure of the RFC 9449 Section 4.3 criteria.
//   - oauth2.ErrInvalidToken (401) for everything else, per RFC 6750 Section 3.1, so an unknown, expired, or
//     wrongly audienced token cannot be told apart. Storage and token validation errors are never surfaced in the
//     client-facing hint.
//
// The client configuration branch reports oauth2.ErrRequestUnauthorized (401) for every failure to resolve or authorise
// the token itself, and the same codes as above for a malformed Authorization header: oauth2.ErrInvalidRequest (400)
// when more than one is present, and oauth2.ErrInvalidToken (401) when none is present or the scheme is not Bearer. See
// RFC 7592 Section 2.
func (s *DefaultEndpointAuthStrategy) AuthenticateClientRegistrationRequest(ctx context.Context, r *http.Request, id string) (requester oauth2.Requester, err error) {
	var tokenString string

	if len(id) == 0 {
		if tokenString, err = endpointToken(r, true); err != nil {
			return nil, err
		}

		return s.authenticateClientRegistration(ctx, r, tokenString)
	}

	if tokenString, err = endpointToken(r, false); err != nil {
		return nil, err
	}

	return s.authenticateClientConfiguration(ctx, r, tokenString, id)
}

// authenticateClientRegistration authenticates a client registration request (RFC 7591). The credential is an ordinary
// access token, resolved from access token storage and authorised by oauth2.ValidateBearerAuthorization.
//
// Any binding is read off the hydrated oauth2.DefaultSession, so a store that keeps sessions serialized and uses its
// own session type only surfaces a thumbprint if that type's JSON tags agree with oauth2.DefaultSession's
// 'jwk_thumbprint' and 'client_certificate_thumbprint'. Otherwise the token looks unbound: nothing is enforced, or with
// GetDPoPEnforce or GetMTLSEnforce set every registration request is rejected.
func (s *DefaultEndpointAuthStrategy) authenticateClientRegistration(ctx context.Context, r *http.Request, tokenString string) (requester oauth2.Requester, err error) {
	signature := s.AccessTokenStrategy.AccessTokenSignature(ctx, tokenString)

	if signature == "" {
		return nil, errorsx.WithStack(oauth2.ErrInvalidToken.WithHint("The provided credential does not appear to be an Access Token."))
	}

	// A concrete session is passed, never nil: the store hydrates it and ValidateAccessToken reads the expiry back off
	// it.
	if requester, err = s.Store.GetAccessTokenSession(ctx, signature, &oauth2.DefaultSession{}); err != nil {
		return nil, errorsx.WithStack(oauth2.ErrInvalidToken.WithHint("The provided Access Token is not valid.").WithWrap(err).WithDebugError(err))
	}

	if err = s.AccessTokenStrategy.ValidateAccessToken(ctx, requester, tokenString); err != nil {
		return nil, errorsx.WithStack(oauth2.ErrInvalidToken.WithHint("The provided Access Token is not valid.").WithWrap(err).WithDebugError(err))
	}

	if err = oauth2.ValidateBearerAuthorization(ctx, s.Config, r, requester, tokenString, oauth2.BearerAuthorization{
		Audiences: s.Config.GetRFC7591ClientRegistrationEndpointAudiences(ctx),
		Endpoint:  s.Config.GetRFC7591ClientRegistrationEndpointURL(ctx),
		Scopes:    s.Config.GetRFC7591ClientRegistrationScopes(ctx),
	}); err != nil {
		return nil, err
	}

	return requester, nil
}

// authenticateClientConfiguration authenticates a client configuration request (RFC 7592) for the client named by id.
// The credential is a client management token, resolved from the client registration token namespace.
//
// The checks run in a fixed order, each a precondition of the next:
//
//  1. The token yields a non-empty client registration token signature.
//  2. That signature resolves to a stored client registration token session.
//  3. The token itself validates against that session (signature and expiry).
//  4. Its granted audience contains this client's registration_client_uri exactly.
//  5. The client the token was issued to is the client named by id.
//
// The audience in step 4 is derived from the configured registration endpoint URL, as NewClientManagementToken derives
// it, and not from the request. The request URL is the fallback only when no endpoint URL is configured.
func (s *DefaultEndpointAuthStrategy) authenticateClientConfiguration(ctx context.Context, r *http.Request, tokenString, id string) (requester oauth2.Requester, err error) {
	// A token that is malformed below any prefix yields an empty signature, which can never be a legitimate lookup
	// key, so it is rejected here rather than spent on a storage round trip.
	signature := s.Strategy.ClientRegistrationTokenSignature(ctx, tokenString)

	if signature == "" {
		return nil, errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithHint("The provided credential does not appear to be a Client Registration Token."))
	}

	if requester, err = s.Store.GetClientRegistrationTokenSession(ctx, signature, &oauth2.DefaultSession{}); err != nil {
		return nil, errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithHint("The provided Client Registration Token is not valid.").WithWrap(err).WithDebugError(err))
	}

	if err = s.Strategy.ValidateClientRegistrationToken(ctx, requester, tokenString); err != nil {
		return nil, errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithHint("The provided Client Registration Token is not valid.").WithWrap(err).WithDebugError(err))
	}

	audience := oauth2.RequestURL(r)

	if endpoint := s.Config.GetRFC7591ClientRegistrationEndpointURL(ctx); len(endpoint) != 0 {
		audience = ClientConfigurationURL(endpoint, id)
	}

	if !requester.GetGrantedAudience().Has(audience) {
		return nil, errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithHintf("The provided Client Registration Token is not permitted to be used at '%s'.", audience))
	}

	// Defence in depth: Storage is a public interface, and a session persisted by a route other than
	// NewClientManagementToken may not keep the client and the granted audience in sync. A nil client is rejected for
	// the same reason.
	if client := requester.GetClient(); client == nil || client.GetID() != id {
		return nil, errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithHintf("The provided Client Registration Token is not permitted to manage the client with id '%s'.", id))
	}

	// The requester ID is set to the presented token's signature so a caller can delete this session later. The
	// registration branch does not do this: an access token's request ID has meaning of its own.
	requester.SetID(signature)

	return requester, nil
}

// endpointToken extracts the token from a request's Authorization header. Exactly one such header must be present,
// followed by a non-empty token. dpop reports whether the DPoP scheme is permitted in addition to Bearer, and is true
// only for the client registration endpoint. The scheme is not returned: whether a DPoP proof is required is decided by
// the token's own binding.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-7.1
func endpointToken(r *http.Request, dpop bool) (token string, err error) {
	values := r.Header.Values(consts.HeaderAuthorization)

	// RFC 9449 Section 7.2 Figure 19: using more than one method to include an access token is a malformed request,
	// reported with HTTP 400 and 'invalid_request' rather than as an authentication failure. The detection is
	// independent of any token, so distinguishing it discloses nothing.
	if len(values) > 1 {
		return "", errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Multiple methods used to include access token."))
	}

	if len(values) == 0 {
		return "", errorsx.WithStack(oauth2.ErrInvalidToken.WithHint("The request must contain an Authorization header."))
	}

	scheme, value, ok := strings.Cut(values[0], " ")

	// RFC 6750 Section 2.1 gives 'credentials = "Bearer" 1*SP b64token', so more than one space between the scheme and
	// the token is well formed and the remainder must be trimmed rather than handed on with a leading space - which
	// would otherwise be carried into the signature computation and turn a valid credential into an unknown one.
	value = strings.TrimLeft(value, " ")

	if ok && value != "" {
		if strings.EqualFold(scheme, oauth2.BearerAccessToken) || (dpop && strings.EqualFold(scheme, oauth2.DPoPAccessToken)) {
			return value, nil
		}
	}

	if dpop {
		return "", errorsx.WithStack(oauth2.ErrInvalidToken.WithHint("The Authorization header must use the Bearer or DPoP scheme."))
	}

	return "", errorsx.WithStack(oauth2.ErrInvalidToken.WithHint("The Authorization header must use the Bearer scheme."))
}

var (
	_ oauth2.ClientRegistrationEndpointAuthStrategy = (*DefaultEndpointAuthStrategy)(nil)
)
