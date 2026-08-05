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
	"authelia.com/provider/oauth2/handler/rfc8705"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// EndpointAuthStrategyConfig is the configuration DefaultEndpointAuthStrategy depends on.
//
// It names no oauth2.ScopeStrategyProvider or oauth2.AudienceStrategyProvider: the client registration endpoint
// authorises an access token by exact containment of the required audience and scope in its grant, never through a
// configured or client-supplied strategy - see authenticateClientRegistration for why.
//
// It does name the DPoP and mTLS providers, because the client registration endpoint is a resource server for the
// creation token it is presented with, and a proof-of-possession binding is only worth anything if the resource
// server checks it - see validateProofOfPossession.
type EndpointAuthStrategyConfig interface {
	oauth2.RFC7591ClientRegistrationConfigProvider
	oauth2.DPoPConfigProvider
	oauth2.MTLSConfigProvider
}

// DPoPResourceStrategy is the resource-server half of the RFC 9449 strategy, which the client registration endpoint
// needs and oauth2.DPoPStrategy - the type EndpointAuthStrategyConfig's GetDPoPStrategy returns - does not declare.
// *rfc9449.DefaultStrategy implements it; the assertion is made at the point of use rather than by widening
// oauth2.DPoPStrategy so a deployment supplying its own strategy is not broken by a method it has no DPoP-bound
// creation tokens to serve.
type DPoPResourceStrategy interface {
	// ValidateResourceAccess performs the RFC 9449 7.1/7.2 resource-server checks for a DPoP-bound access token.
	ValidateResourceAccess(ctx context.Context, r *http.Request, accessToken, boundJKT string, requireNonce bool) (parsed *oauth2.DPoPProof, err error)
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
// Bearer only, because a management token is minted outside the binding machinery and can never be bound. The token
// is then resolved by the branch the endpoint calls for - see authenticateClientRegistration and
// authenticateClientConfiguration, which take entirely different credentials from entirely different storage
// namespaces.
//
// Every failure returns oauth2.ErrRequestUnauthorized. Storage, token validation and proof-of-possession errors are
// attached with WithWrap and WithDebugError only, never surfaced in the client-facing hint, so a storage error
// cannot let an attacker distinguish an unknown token from an expired one.
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
// validated as one. Two independent checks authorise it, both by exact containment: its granted audience must
// contain this endpoint's audience, and its granted scopes must contain the configured registration scope. The
// audience says the token is for this endpoint; the scope says its holder may register clients.
func (s *DefaultEndpointAuthStrategy) authenticateClientRegistration(ctx context.Context, r *http.Request, tokenString string) (requester oauth2.Requester, err error) {
	signature := s.AccessTokenStrategy.AccessTokenSignature(ctx, tokenString)

	if signature == "" {
		return nil, errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithHint("The provided credential does not appear to be an Access Token."))
	}

	// A concrete session is passed, never nil: GetAccessTokenSession is documented to hydrate the session it is given,
	// and ValidateAccessToken below reads the expiry back off it. A store that keeps sessions serialized unmarshals
	// into this argument and returns a requester carrying it, so a nil here either fails to unmarshal, yields a
	// requester whose session is nil, or hydrates nothing and leaves a zero expiry that silently falls through to the
	// requested-at plus lifespan branch of the expiry check. oauth2.DefaultSession is the right concrete type despite
	// the deployment's own session type being unknown here: only the expiry is read, every session type carries it,
	// and this strategy has no request-scoped session to hydrate into instead.
	if requester, err = s.Store.GetAccessTokenSession(ctx, signature, &oauth2.DefaultSession{}); err != nil {
		return nil, errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithHint("The provided Access Token is not valid.").WithWrap(err).WithDebugError(err))
	}

	if err = s.AccessTokenStrategy.ValidateAccessToken(ctx, requester, tokenString); err != nil {
		return nil, errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithHint("The provided Access Token is not valid.").WithWrap(err).WithDebugError(err))
	}

	audience := s.Config.GetRFC7591ClientRegistrationEndpointAudience(ctx)

	if len(audience) == 0 {
		audience = oauth2.RequestURL(r)
	}

	// Both checks below are exact containment, deliberately, and neither resolves an oauth2.ScopeStrategy or
	// oauth2.AudienceStrategy at all - not even the server's own.
	//
	// A strategy is a policy about what a client may ask for; this is an endpoint authorization decision about what a
	// token already carries, and the two must not share a comparison function. The default oauth2.ScopeStrategy is
	// oauth2.WildcardScopeStrategy, under which a token granted '*' matches every scope including the registration
	// scope - so a registered client granted '*' (which CheckGrantableScopes admits, since it excludes only the
	// registration scope by exact equality) would obtain creation tokens of its own and register further clients,
	// which is precisely the self-replication ExcludeRegistrationScope and CheckGrantableScopes exist to close. The
	// same asymmetry applies to the audience: a deployment-configured oauth2.AudienceStrategy loose enough to match
	// the registration endpoint by prefix or by wildcard would admit a token never issued for this endpoint.
	//
	// Exact containment here is symmetric with the exclusion applied on the way out, and it matches what the client
	// configuration branch below already does with its own audience.
	if !requester.GetGrantedAudience().Has(audience) {
		return nil, errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithHintf("The provided Access Token is not permitted to be used at '%s'.", audience))
	}

	scope := s.Config.GetRFC7591ClientRegistrationScope(ctx)

	if !requester.GetGrantedScopes().Has(scope) {
		return nil, errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithHintf("The provided Access Token is not granted the '%s' scope which is required to register clients.", scope))
	}

	if err = s.validateProofOfPossession(ctx, r, requester, tokenString); err != nil {
		return nil, err
	}

	return requester, nil
}

// validateProofOfPossession enforces any RFC 9449 (DPoP) or RFC 8705 (mTLS) binding the presented creation token
// carries. This endpoint is the resource server for that token, and a binding nothing checks is not a binding: a
// DPoP-bound token that is accepted as a plain bearer credential can be lifted out of a proxy log and replayed here
// with no key at all.
//
// Nothing happens unless the token is actually bound. A creation token issued without binding - the ordinary case,
// and every creation token issued before binding was possible - reaches here with no thumbprint on its session and
// is admitted unchanged. A binding whose method is disabled in configuration is likewise skipped, matching
// ApplyConfirmation: a session outlives a configuration change, and enforcing a binding the rest of the deployment
// has stopped asserting would reject a token nothing else considers bound.
//
// Two caveats a deployment must know about, both consequences of what this endpoint has to work with:
//
//   - The binding is read off the session hydrated by authenticateClientRegistration, which is an
//     oauth2.DefaultSession. A store that keeps sessions serialized and uses its own session type therefore only
//     surfaces a thumbprint here if that type's JSON tags agree with oauth2.DefaultSession's 'jwk_thumbprint' and
//     'client_certificate_thumbprint'. Where they do not, the token arrives looking unbound and this function has
//     nothing to enforce. There is no session to hydrate into instead - the RFC 7591 request handler takes none.
//   - A DPoP failure is reported as oauth2.ErrRequestUnauthorized like every other failure in this strategy,
//     including oauth2.ErrUseDPoPNonce. The client registration endpoint's error writer emits no DPoP-Nonce
//     challenge header, so a deployment that sets GetDPoPNonceRequired cannot complete a nonce handshake here and
//     should not use DPoP-bound creation tokens.
func (s *DefaultEndpointAuthStrategy) validateProofOfPossession(ctx context.Context, r *http.Request, requester oauth2.Requester, tokenString string) (err error) {
	session := requester.GetSession()

	if session == nil {
		return nil
	}

	if s.Config.GetDPoPEnabled(ctx) {
		if bound, ok := session.(oauth2.DPoPBoundSession); ok {
			if jkt := bound.GetDPoPJWKThumbprint(); jkt != "" {
				strategy, isResourceStrategy := s.Config.GetDPoPStrategy(ctx).(DPoPResourceStrategy)

				// Fail closed: the token asserts a binding this deployment cannot verify, so it cannot be accepted
				// as if it carried none.
				if !isResourceStrategy {
					return errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithHint("The provided Access Token is not valid.").WithDebug("The provided Access Token is bound to a DPoP key but the configured DPoP strategy cannot validate resource access."))
				}

				if _, err = strategy.ValidateResourceAccess(ctx, r, tokenString, jkt, s.Config.GetDPoPNonceRequired(ctx)); err != nil {
					return errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithHint("The provided Access Token is not valid.").WithWrap(err).WithDebugError(err))
				}
			}
		}
	}

	if s.Config.GetMTLSEnabled(ctx) {
		if bound, ok := session.(oauth2.MTLSBoundSession); ok {
			if x5t := bound.GetClientCertificateSHA256Thumbprint(); x5t != "" {
				if _, err = rfc8705.ValidateResourceAccess(r, s.Config.GetMTLSClientCertificateHeader(ctx), x5t); err != nil {
					return errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithHint("The provided Access Token is not valid.").WithWrap(err).WithDebugError(err))
				}
			}
		}
	}

	return nil
}

// authenticateClientConfiguration authenticates a client configuration request (RFC 7592) for the client named by id.
// The credential is a client management token, resolved from the client registration token namespace which the
// registration branch above never consults - that separation, not any property of the session, is what keeps the two
// credentials from being interchangeable.
//
// The checks run in a fixed order, each a precondition of the next:
//
//  1. The token yields a non-empty client registration token signature.
//  2. That signature resolves to a stored client registration token session.
//  3. The token itself validates against that session (signature and expiry).
//  4. Its granted audience contains this client's registration_client_uri exactly, unconditionally - which is what
//     prevents a management token issued for one client being replayed against another.
//  5. The client the token was issued to is the client named by id.
//
// The audience in step 4 is derived from the configured registration endpoint rather than from the request, because
// that is where it came from: NewClientManagementToken audiences a management token at
// ClientConfigurationURL(GetRFC7591ClientRegistrationEndpointURL, id), and the same value is handed to the client as
// its registration_client_uri. Comparing against oauth2.RequestURL(r) instead would make the check depend on how the
// request happened to reach the server - a deployment behind a proxy that terminates TLS, rewrites the path, or
// presents a different host would reject every management token it ever issued, and the Host header the reconstructed
// URL is built from is client-controlled in the first place. The fallback to the request URL is kept only for a
// deployment that configures no endpoint URL, matching authenticateClientRegistration's own fallback above.
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

	// Defence in depth: the audience check above already binds the token to this one client unconditionally, since a
	// management token's audience is that client's own registration_client_uri. Through the real minting path
	// (NewClientManagementToken) this check can never actually fire, because that constructor always audiences a
	// management token at ClientConfigurationURL(endpoint, client.GetID()) for the same client it binds the requester
	// to - the two can never disagree. It stays because Storage is a public interface: a caller that persists a client
	// registration token session by some other route (a custom store migration, an administrative tool, a third-party
	// ClientRegistrationTokenStrategy) is not guaranteed to keep the client and the granted audience in sync, and this
	// is the last check standing between such a session and cross-client management.
	// TestAuthRejectsMintedAudienceMismatchingClientID constructs exactly that out-of-sync shape and pins this line.
	//
	// The nil check is part of the same defence: newClientRegistrationToken takes care to leave a well-formed default
	// client on the requester rather than a nil one, but a session persisted by some other route carries whatever that
	// route put there, and a token whose client cannot be identified is by definition not a token permitted to manage
	// this one.
	if client := requester.GetClient(); client == nil || client.GetID() != id {
		return nil, errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithHintf("The provided Client Registration Token is not permitted to manage the client with id '%s'.", id))
	}

	// The requester ID otherwise carries no meaning here; it is overwritten with the presented token's signature so a
	// caller that needs to delete this session later - such as the client configuration endpoint rotating the
	// management token on a PUT - can do so without re-deriving the signature from the request a second time. The
	// registration branch deliberately does not do this: an access token's request ID has meaning of its own.
	requester.SetID(signature)

	return requester, nil
}

// endpointToken extracts the token from a request's Authorization header. Exactly one such header must be present,
// followed by a non-empty token.
//
// dpop reports whether the RFC 9449 DPoP scheme is permitted in addition to Bearer, and is true only for the client
// registration endpoint: a creation token is an ordinary access token, and RFC 9449 Section 7.1 requires a DPoP-bound
// one be presented under that scheme, so refusing it would make binding unusable rather than merely unenforced. A
// client management token is minted outside the binding machinery and can never be bound, so the client configuration
// endpoint keeps Bearer only and a DPoP presentation there is a malformed request rather than a token to look up.
//
// The scheme itself is not returned. Whether a DPoP proof is required is decided by the token's own binding, read off
// its session in validateProofOfPossession, never by how the caller chose to present it; rfc9449's
// ValidateResourceAccess re-reads the header itself and rejects a bound token presented under any other scheme.
func endpointToken(r *http.Request, dpop bool) (token string, err error) {
	values := r.Header.Values(consts.HeaderAuthorization)

	if len(values) != 1 {
		return "", errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithHint("The request must contain exactly one Authorization header."))
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
		return "", errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithHint("The Authorization header must use the Bearer or DPoP scheme."))
	}

	return "", errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithHint("The Authorization header must use the Bearer scheme."))
}

var (
	_ oauth2.ClientRegistrationEndpointAuthStrategy = (*DefaultEndpointAuthStrategy)(nil)
)
