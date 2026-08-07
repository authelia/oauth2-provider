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
//
// It names no oauth2.ScopeStrategyProvider or oauth2.AudienceStrategyProvider: the client registration endpoint
// authorises an access token by exact containment of the required audience and scope in its grant, never through a
// configured or client-supplied strategy.
//
// It does name the DPoP and mTLS providers, because the client registration endpoint is the resource server for the
// creation token it is presented with. Naming them also satisfies oauth2.BearerAuthorizationConfig.
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
// client registration request (RFC 7591) and carries the target client id for a client configuration request
// (RFC 7592).
//
// Exactly one Authorization header must be present, with a non-empty remainder. The permitted scheme differs by
// branch: the client registration endpoint accepts Bearer (RFC 6750) and DPoP (RFC 9449 Section 7.1), because a
// creation token is an ordinary access token and may be DPoP bound, while the client configuration endpoint accepts
// Bearer only, because a management token is minted outside the binding machinery and can never be bound.
//
// Error codes differ by branch. The client registration branch acts as an OAuth 2.0 protected resource and reports:
//
//   - oauth2.ErrInvalidRequest (400) when more than one Authorization header is present, per RFC 9449
//     Section 7.2 Figure 19.
//   - oauth2.ErrInsufficientScope (403) when the credential holds none of the required scopes, per RFC 6750
//     Section 3.1. RFC 7591 says nothing about authentication errors, so that general rule governs here; the
//     introspection endpoint differs, because RFC 7662 Section 2.3 mandates 401 for the same condition.
//   - oauth2.ErrInvalidDPoPProof or oauth2.ErrUseDPoPNonce for a failure of the RFC 9449 Section 4.3 criteria,
//     propagated from the strategy so a nonce handshake can complete.
//   - oauth2.ErrInvalidToken (401) for everything else, so a storage error cannot let an attacker distinguish an
//     unknown token from an expired one, or either from a wrong audience. Storage and token validation errors are
//     attached with WithWrap and WithDebugError only, never surfaced in the client-facing hint.
//
// The client configuration branch takes a management token that can never be bound, and reports
// oauth2.ErrRequestUnauthorized (401) for every failure to resolve or authorise the token itself. The header is read
// before either branch is chosen, so a malformed Authorization header reports the same codes as above. Each of these
// is a status RFC 7592 Section 2 allows, which requires a 401 for an invalid registration access token and defers to
// RFC 6750 for its form.
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

// authenticateClientRegistration authenticates a client registration request (RFC 7591). The credential is an
// ordinary access token obtained through the token endpoint, so it is resolved from access token storage and
// validated as one.
//
// Resolution happens here; authorising the resolved credential (proof-of-possession, then scope, then audience) is
// delegated to oauth2.ValidateBearerAuthorization, which the introspection endpoint also calls with its own
// configuration values.
//
// A deployment caveat: any binding is read off the session hydrated below, which is an oauth2.DefaultSession. The
// RFC 7591 request handler supplies no session, so a store that keeps sessions serialized and uses its own session
// type only surfaces a thumbprint if that type's JSON tags agree with oauth2.DefaultSession's 'jwk_thumbprint' and
// 'client_certificate_thumbprint'. Where they do not, the token arrives looking unbound: with enforcement unset the
// binding is lost quietly, and with GetDPoPEnforce or GetMTLSEnforce set every registration request is rejected
// instead.
func (s *DefaultEndpointAuthStrategy) authenticateClientRegistration(ctx context.Context, r *http.Request, tokenString string) (requester oauth2.Requester, err error) {
	signature := s.AccessTokenStrategy.AccessTokenSignature(ctx, tokenString)

	if signature == "" {
		return nil, errorsx.WithStack(oauth2.ErrInvalidToken.WithHint("The provided credential does not appear to be an Access Token."))
	}

	// A concrete session is passed, never nil: GetAccessTokenSession hydrates the session it is given and
	// ValidateAccessToken below reads the expiry back off it, so a nil here would leave a zero expiry that falls
	// through to the requested-at plus lifespan branch of the expiry check. oauth2.DefaultSession serves even though
	// the deployment's own session type is unknown here, since only the expiry is read and every session carries it.
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
// The credential is a client management token, resolved from the client registration token namespace which the
// registration branch above never consults. That separation, not any property of the session, is what keeps the two
// credentials from being interchangeable.
//
// The checks run in a fixed order, each a precondition of the next:
//
//  1. The token yields a non-empty client registration token signature.
//  2. That signature resolves to a stored client registration token session.
//  3. The token itself validates against that session (signature and expiry).
//  4. Its granted audience contains this client's registration_client_uri exactly, which prevents a management token
//     issued for one client being replayed against another.
//  5. The client the token was issued to is the client named by id.
//
// The audience in step 4 is derived from the configured registration endpoint rather than from the request, because
// that is where it came from: NewClientManagementToken audiences a management token at
// ClientConfigurationURL(GetRFC7591ClientRegistrationEndpointURL, id), and hands the client the same value as its
// registration_client_uri. Comparing against oauth2.RequestURL(r) would instead make the check depend on how the
// request reached the server, so a deployment behind a proxy that terminates TLS, rewrites the path, or presents a
// different host would reject every management token it issued. The fallback to the request URL is kept only for a
// deployment that configures no endpoint URL.
func (s *DefaultEndpointAuthStrategy) authenticateClientConfiguration(ctx context.Context, r *http.Request, tokenString, id string) (requester oauth2.Requester, err error) {
	// A malformed token yields an empty signature, which can never be a legitimate lookup key, so it is rejected here
	// rather than spent on a storage round trip.
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

	// Defence in depth. The audience check above already binds the token to one client, and NewClientManagementToken
	// always audiences at ClientConfigurationURL(endpoint, client.GetID()) for the same client it binds the requester
	// to, so this cannot fire through the minting path. It stays because Storage is a public interface: a session
	// persisted by some other route (a store migration, an administrative tool, a third-party
	// ClientRegistrationTokenStrategy) is not guaranteed to keep the client and the granted audience in sync.
	//
	// The nil check is part of the same defence. A token whose client cannot be identified is not a token permitted
	// to manage this one.
	if client := requester.GetClient(); client == nil || client.GetID() != id {
		return nil, errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithHintf("The provided Client Registration Token is not permitted to manage the client with id '%s'.", id))
	}

	// The requester ID carries no other meaning here, so it is overwritten with the presented token's signature. That
	// lets a caller which needs to delete this session later, such as the client configuration endpoint rotating the
	// management token on a PUT, do so without re-deriving the signature from the request. The registration branch
	// does not do this, since an access token's request ID has meaning of its own.
	requester.SetID(signature)

	return requester, nil
}

// endpointToken extracts the token from a request's Authorization header. Exactly one such header must be present,
// followed by a non-empty token.
//
// dpop reports whether the RFC 9449 DPoP scheme is permitted in addition to Bearer, and is true only for the client
// registration endpoint: a creation token is an ordinary access token, and RFC 9449 Section 7.1 requires a DPoP-bound
// one be presented under that scheme. A client management token can never be bound, so the client configuration
// endpoint keeps Bearer only.
//
// The scheme itself is not returned. Whether a DPoP proof is required is decided by the token's own binding, read off
// its session by oauth2.ValidateBearerAuthorization, never by how the caller chose to present it; rfc9449's
// ValidateResourceAccess re-reads the header itself and rejects a bound token presented under any other scheme.
func endpointToken(r *http.Request, dpop bool) (token string, err error) {
	values := r.Header.Values(consts.HeaderAuthorization)

	// RFC 9449 Section 7.2 Figure 19: using more than one method to include an access token is a malformed request,
	// reported with HTTP 400 and 'invalid_request' rather than as an authentication failure.
	if len(values) > 1 {
		return "", errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Multiple methods used to include access token."))
	}

	if len(values) == 0 {
		return "", errorsx.WithStack(oauth2.ErrInvalidToken.WithHint("The request must contain an Authorization header."))
	}

	scheme, value, ok := strings.Cut(values[0], " ")

	// RFC 6750 Section 2.1 gives 'credentials = "Bearer" 1*SP b64token', so more than one space between the scheme and
	// the token is well formed and the remainder must be trimmed. A leading space would otherwise be carried into the
	// signature computation and turn a valid credential into an unknown one.
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
