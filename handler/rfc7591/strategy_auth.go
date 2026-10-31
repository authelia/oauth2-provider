// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"authelia.com/provider/jose"
	josejwt "authelia.com/provider/jose/jwt"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

// EndpointAuthStrategyConfig is the configuration DefaultEndpointAuthStrategy depends on. It names the DPoP and mTLS
// providers required by oauth2.BearerAuthorizationConfig, as the client registration endpoint checks the
// proof-of-possession binding of the creation token it is presented with. It names no scope or audience strategy
// provider, as the required audience and scope are matched by exact containment.
type EndpointAuthStrategyConfig interface {
	oauth2.RFC7591ClientRegistrationConfigProvider
	oauth2.RFC7591ClientRegistrationPolicyProvider
	oauth2.AccessTokenIssuerProvider
	oauth2.JWKSFetcherStrategyProvider
	oauth2.HTTPClientProvider
	oauth2.DPoPConfigProvider
	oauth2.MTLSConfigProvider
}

// DefaultEndpointAuthStrategy is the oauth2.ClientRegistrationEndpointAuthStrategy used to authenticate requests to
// the client registration (RFC 7591) and client configuration (RFC 7592) endpoints.
//
// The two endpoints take two different credentials, from two different storage namespaces:
//
//   - The client registration endpoint takes an ordinary access token, obtained through the token endpoint like any
//     other and resolved from access token storage, or a JWT access token validated per RFC 9068 Section 4. A JWT from
//     this server is also resolved from storage unless GetRFC7591ClientRegistrationStatelessAccessTokens is set, and a
//     JWT from a trusted issuer never is. It is authorised by its granted audience containing this endpoint's audience exactly and its granted
//     scopes containing the configured registration scope exactly.
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

	// JWTStrategy decodes and verifies a JWT client creation token. When nil, AccessTokenStrategy is used if it
	// implements jwt.Strategy, and otherwise every creation token is resolved from access token storage.
	JWTStrategy jwt.Strategy

	discovery jwksURIDiscovery
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
// Any binding is read off the hydrated accessTokenSession, so a store that keeps sessions serialized and uses its own
// session type only surfaces a thumbprint if that type's JSON keys match those of oauth2.DefaultSession or
// handler/oauth2.JWTSession. Otherwise the token looks unbound: nothing is enforced, or with GetDPoPEnforce or
// GetMTLSEnforce set every registration request is rejected.
//
// The registration policy claim is read from the same session's extra claims, so the same caveat applies: a session
// type which does not round-trip its extra claims, or does not implement oauth2.ExtraClaimsSession, yields a token
// that carries no policy.
//
// The result is a RegistrationPolicyRequester whose counter key is "session:" followed by the request id, or empty when
// the stored requester has no id so that a 'max_registrations' policy fails rather than sharing one counter.
//
// When a JWT strategy is available, a token with the shape of a JWS is instead validated by
// authenticateClientRegistrationJWT, and a token with the shape of a JWE is rejected.
func (s *DefaultEndpointAuthStrategy) authenticateClientRegistration(ctx context.Context, r *http.Request, tokenString string) (requester oauth2.Requester, err error) {
	if strategy := s.jwtStrategy(); strategy != nil {
		switch strings.Count(tokenString, ".") {
		case 2:
			return s.authenticateClientRegistrationJWT(ctx, r, strategy, tokenString)
		case 4:
			return nil, errInvalidAccessToken(errors.New("encrypted access tokens are not supported at the client registration endpoint"))
		}
	}

	signature := s.AccessTokenStrategy.AccessTokenSignature(ctx, tokenString)

	if signature == "" {
		return nil, errorsx.WithStack(oauth2.ErrInvalidToken.WithHint("The provided credential does not appear to be an Access Token."))
	}

	// A concrete session is passed, never nil: the store hydrates it and ValidateAccessToken reads the expiry back off
	// it.
	if requester, err = s.Store.GetAccessTokenSession(ctx, signature, &accessTokenSession{}); err != nil {
		return nil, errInvalidAccessToken(err)
	}

	if err = s.AccessTokenStrategy.ValidateAccessToken(ctx, requester, tokenString); err != nil {
		return nil, errInvalidAccessToken(err)
	}

	if err = oauth2.ValidateBearerAuthorization(ctx, s.Config, r, requester, tokenString, oauth2.BearerAuthorization{
		Audiences: s.Config.GetRFC7591ClientRegistrationEndpointAudiences(ctx),
		Endpoint:  s.Config.GetRFC7591ClientRegistrationEndpointURL(ctx),
		Scopes:    s.Config.GetRFC7591ClientRegistrationScopes(ctx),
	}); err != nil {
		return nil, err
	}

	var key string

	if id := requester.GetID(); id != "" {
		key = "session:" + id
	}

	return newPolicyRequester(requester, s.Config.GetRFC7591ClientRegistrationPolicyClaim(ctx), key, true), nil
}

// authenticateClientRegistrationJWT authenticates a client registration request (RFC 7591) presenting a JWT access
// token, validated per RFC 9068 Section 4: the 'typ' header is 'at+jwt', the signature
// verifies with the keys of strategy, 'iss' equals GetAccessTokenIssuer exactly, 'exp' is present and in the future,
// and 'jti' is present. The proof-of-possession binding, scope and audience are then checked by
// oauth2.ValidateBearerAuthorization against the requester rebuilt from the claims, as for an opaque token.
//
// A token whose unverified 'iss' equals an entry of GetRFC7591ClientRegistrationTrustedIssuers exactly is instead
// verified with the keys published at that entry's JSONWebKeysURI, or at the 'jwks_uri' of the issuer's OpenID
// Connect Discovery 1.0 metadata when it has none, and must then carry that 'iss' exactly. The
// unverified 'iss' only selects the keys: a token claiming GetAccessTokenIssuer is verified with this server's keys
// alone, and any other 'iss' is rejected. The key is the one named by the 'kid' header, the set being refreshed when it
// holds no such key at most once a minute per location; a token without a 'kid' is verified only when exactly one key
// of the set matches its 'alg'.
// Only asymmetric algorithms are accepted from a trusted issuer.
//
// A token issued by this server must also resolve from access token storage, so that revoking it takes effect, unless
// GetRFC7591ClientRegistrationStatelessAccessTokens is set and its policy does not set 'max_registrations'.
//
// The result is a RegistrationPolicyRequester carrying the registration policy claim of the token. Its counter key is
// "session:" followed by the request id when the token was resolved from storage, as that id survives a refresh, and
// otherwise "jwt:" followed by the JSON array of the 'iss' and 'jti' claims. Its policy may hold 'pattern' rules when the token
// was issued by this server or by an issuer of GetRFC7591ClientRegistrationPatternIssuers.
//
// See: https://www.rfc-editor.org/rfc/rfc9068#section-4
func (s *DefaultEndpointAuthStrategy) authenticateClientRegistrationJWT(ctx context.Context, r *http.Request, strategy jwt.Strategy, tokenString string) (requester oauth2.Requester, err error) {
	var (
		issuer string
		opts   []jwt.StrategyOpt
	)

	if issuer, opts, err = s.clientRegistrationJWTIssuer(ctx, tokenString); err != nil {
		if errors.Is(err, oauth2.ErrServerError) {
			return nil, err
		}

		return nil, errInvalidAccessToken(err)
	}

	var token *jwt.Token

	if token, err = strategy.Decode(ctx, tokenString, opts...); err != nil {
		if isKeySourceFailure(err) {
			return nil, errorsx.WithStack(oauth2.ErrServerError.WithHint("The keys of the access token issuer could not be retrieved.").WithWrap(err).WithDebugError(err))
		}

		return nil, errInvalidAccessToken(err)
	}

	if err = token.Valid(jwt.ValidateTypes(jwt.JSONWebTokenTypeAccessToken)); err != nil {
		return nil, errInvalidAccessToken(err)
	}

	if err = token.Claims.Valid(jwt.ValidateIssuer(issuer), jwt.ValidateRequireExpiresAt()); err != nil {
		return nil, errInvalidAccessToken(err)
	}

	claims := token.Claims.ToMapClaims()

	jti, _ := claims[consts.ClaimJWTID].(string)

	if jti == "" {
		return nil, errInvalidAccessToken(errors.New("the token does not have a 'jti' claim"))
	}

	claim, hasClaim := claims[s.Config.GetRFC7591ClientRegistrationPolicyClaim(ctx)]

	var (
		key      string
		resolved bool
	)

	if issuer == s.Config.GetAccessTokenIssuer(ctx) && (!s.Config.GetRFC7591ClientRegistrationStatelessAccessTokens(ctx) || policyClaimLimitsRegistrations(claim)) {
		if key, err = s.storedCounterKey(ctx, tokenString); err != nil {
			return nil, errInvalidAccessToken(err)
		}

		resolved = true
	}

	requester = hoauth2.AccessTokenJWTToRequest(token)

	if err = oauth2.ValidateBearerAuthorization(ctx, s.Config, r, requester, tokenString, oauth2.BearerAuthorization{
		Audiences: s.Config.GetRFC7591ClientRegistrationEndpointAudiences(ctx),
		Endpoint:  s.Config.GetRFC7591ClientRegistrationEndpointURL(ctx),
		Scopes:    s.Config.GetRFC7591ClientRegistrationScopes(ctx),
	}); err != nil {
		return nil, err
	}

	if !resolved {
		var identity []byte

		if identity, err = json.Marshal([]string{issuer, jti}); err != nil {
			return nil, errInvalidAccessToken(err)
		}

		key = "jwt:" + string(identity)
	}

	patterns := issuer == s.Config.GetAccessTokenIssuer(ctx) || slices.Contains(s.Config.GetRFC7591ClientRegistrationPatternIssuers(ctx), issuer)

	return &policyRequester{Requester: requester, claim: claim, ok: hasClaim, key: key, patterns: patterns}, nil
}

func (s *DefaultEndpointAuthStrategy) storedCounterKey(ctx context.Context, tokenString string) (key string, err error) {
	signature := s.AccessTokenStrategy.AccessTokenSignature(ctx, tokenString)

	if signature == "" {
		signature = tokenString[strings.LastIndexByte(tokenString, '.')+1:]
	}

	var stored oauth2.Requester

	if stored, err = s.Store.GetAccessTokenSession(ctx, signature, &accessTokenSession{}); err != nil {
		return "", err
	}

	if id := stored.GetID(); id != "" {
		key = "session:" + id
	}

	return key, nil
}

func policyClaimLimitsRegistrations(claim any) bool {
	policy, ok := claim.(map[string]any)
	if !ok {
		return false
	}

	_, ok = policy[policyMemberMaxRegistrations]

	return ok
}

func (s *DefaultEndpointAuthStrategy) clientRegistrationJWTIssuer(ctx context.Context, tokenString string) (issuer string, opts []jwt.StrategyOpt, err error) {
	var parsed *josejwt.JSONWebToken

	if parsed, err = josejwt.ParseSigned(tokenString, jwt.SignatureAlgorithms); err != nil {
		return "", nil, err
	}

	var claims struct {
		Issuer string `json:"iss"`
	}

	if err = parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return "", nil, err
	}

	if claims.Issuer == "" {
		return "", nil, errors.New("the token does not have an 'iss' claim")
	}

	if self := s.Config.GetAccessTokenIssuer(ctx); self != "" && claims.Issuer == self {
		return self, nil, nil
	}

	for _, trusted := range s.Config.GetRFC7591ClientRegistrationTrustedIssuers(ctx) {
		if trusted.Issuer == "" || trusted.Issuer != claims.Issuer {
			continue
		}

		var location string

		if location, err = s.discovery.resolve(ctx, s.Config, trusted); err != nil {
			return "", nil, errorsx.WithStack(oauth2.ErrServerError.WithHint("The keys of the access token issuer could not be retrieved.").WithWrap(err).WithDebugError(err))
		}

		return trusted.Issuer, []jwt.StrategyOpt{
			jwt.WithSigAlgorithm(trustedIssuerSignatureAlgorithms...),
			jwt.WithKeyFunc(jwksKeyFunc(s.Config, location)),
		}, nil
	}

	return "", nil, fmt.Errorf("the issuer '%s' is neither this server nor a trusted issuer", claims.Issuer)
}

func jwksKeyFunc(config oauth2.JWKSFetcherStrategyProvider, location string) jwt.KeyFuncJWS {
	return func(ctx context.Context, token *josejwt.JSONWebToken, _ jwt.MapClaims) (key *jose.JSONWebKey, err error) {
		if len(token.Headers) != 1 {
			return nil, errors.New("the token does not have exactly one signature")
		}

		kid, alg := token.Headers[0].KeyID, token.Headers[0].Algorithm
		fetcher := config.GetJWKSFetcherStrategy(ctx)

		var jwks *jose.JSONWebKeySet

		if jwks, err = fetcher.Resolve(ctx, location, false); err != nil {
			return nil, err
		}

		if key, err = jwt.SearchJWKS(jwks, kid, alg, jwt.JSONWebTokenUseSignature, true); err == nil {
			return key, nil
		}

		// The 'kid' of an unverified token is attacker controlled, so the forced refresh it triggers is rate limited.
		if !jwksRefreshes.allow(location, time.Now()) {
			return nil, err
		}

		if jwks, err = fetcher.Resolve(ctx, location, true); err != nil {
			return nil, err
		}

		return jwt.SearchJWKS(jwks, kid, alg, jwt.JSONWebTokenUseSignature, true)
	}
}

const jwksRefreshInterval = time.Minute

var jwksRefreshes jwksRefreshLimiter

// jwksRefreshLimiter permits at most one forced refresh of each key set location per jwksRefreshInterval.
type jwksRefreshLimiter struct {
	mu   sync.Mutex
	last map[string]time.Time
}

func (l *jwksRefreshLimiter) allow(location string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if last, ok := l.last[location]; ok && now.Sub(last) < jwksRefreshInterval {
		return false
	}

	if l.last == nil {
		l.last = map[string]time.Time{}
	}

	l.last[location] = now

	return true
}

func (s *DefaultEndpointAuthStrategy) jwtStrategy() (strategy jwt.Strategy) {
	if s.JWTStrategy != nil {
		return s.JWTStrategy
	}

	if strategy, ok := s.AccessTokenStrategy.(jwt.Strategy); ok {
		return strategy
	}

	return nil
}

func errInvalidAccessToken(err error) error {
	return errorsx.WithStack(oauth2.ErrInvalidToken.WithHint("The provided Access Token is not valid.").WithWrap(err).WithDebugError(err))
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
// The result is a RegistrationPolicyRequester carrying the policy stored under consts.ClientRegistrationPolicyInternalKey
// and no counter key.
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

	// The stored policy was checked for 'pattern' rules when the client was registered.
	return newPolicyRequester(requester, consts.ClientRegistrationPolicyInternalKey, "", true), nil
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
	trustedIssuerSignatureAlgorithms = []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512, jose.EdDSA, jose.Ed25519}
)

var (
	_ oauth2.ClientRegistrationEndpointAuthStrategy = (*DefaultEndpointAuthStrategy)(nil)
)

type accessTokenSession struct {
	oauth2.DefaultSession
}

func (s *accessTokenSession) UnmarshalJSON(data []byte) (err error) {
	if err = json.Unmarshal(data, &s.DefaultSession); err != nil {
		return err
	}

	var stored struct {
		ExpiresAt                   map[oauth2.TokenType]time.Time `json:"ExpiresAt"`
		JWKThumbprint               string                         `json:"JWKThumbprint"`
		ClientCertificateThumbprint string                         `json:"ClientCertificateThumbprint"`
		JWTClaims                   *struct {
			Extra map[string]any `json:"Extra"`
		} `json:"JWTClaims"`
	}

	if err = json.Unmarshal(data, &stored); err != nil {
		return err
	}

	if len(s.ExpiresAt) == 0 {
		s.ExpiresAt = stored.ExpiresAt
	}

	if s.JWKThumbprint == "" {
		s.JWKThumbprint = stored.JWKThumbprint
	}

	if s.ClientCertificateThumbprint == "" {
		s.ClientCertificateThumbprint = stored.ClientCertificateThumbprint
	}

	if len(s.Extra) == 0 && stored.JWTClaims != nil {
		s.Extra = stored.JWTClaims.Extra
	}

	return nil
}
