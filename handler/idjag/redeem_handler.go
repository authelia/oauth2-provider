// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package idjag

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"authelia.com/provider/jose"
	josejwt "authelia.com/provider/jose/jwt"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/rfc7523"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// RedeemHandler redeems an Identity Assertion JWT Authorization Grant whose JOSE 'typ' header is 'oauth-id-jag+jwt',
// presented as an RFC 7523 'jwt-bearer' assertion or, when the grant carries a 'cnf' claim, with the 'jwt-dpop' grant
// type Section 9.8.1.2.1 uses, which requires a DPoP proof for the key the grant is bound to. The client MUST be
// registered for the grant type it uses. Every other assertion is left to rfc7523.Handler. It is also a token endpoint
// binding handler, which enforces the grant's 'cnf' claim and MUST follow rfc9449.Handler. Under 'jwt-dpop' a
// malformed, expired or replayed proof answers invalid_dpop_proof per RFC 9449, keeping use_dpop_nonce usable, rather
// than the invalid_grant of draft-parecki-oauth-jwt-dpop-grant-01 Section 4. A requested resource or scope within the
// grant that the client is not permitted is dropped rather than refused.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-9.8.1.2.1
// See: https://datatracker.ietf.org/doc/html/draft-parecki-oauth-jwt-dpop-grant-01#section-3.1
type RedeemHandler struct {
	Config  RedeemConfig
	Storage RedeemStorage

	*hoauth2.HandleHelper
}

var redeemAlgorithms = []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512}

const (
	accessResponseResource = "resource"
	hintIDJAGRedeemed      = "The Identity Assertion JWT Authorization Grant was already redeemed."
)

// HandleTokenEndpointRequest validates the grant. A 'jwt-dpop' grant MUST carry a 'cnf' claim and a DPoP proof. A
// request that requires a DPoP proof, because of the 'jwt-dpop' grant type, because the grant carries a 'cnf' claim
// or because DPoP bound access tokens are required, and carries no DPoP header is rejected here with invalid_grant,
// before rfc9449.Handler would answer invalid_dpop_proof. The proof itself is validated by rfc9449.Handler.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4.1
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-9.8.1.2.2
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-9.8.1.2.4
func (h *RedeemHandler) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) (err error) {
	if !h.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	assertion := request.GetRequestForm().Get(consts.FormParameterAssertion)

	client := request.GetClient()

	if client == nil || client.GetID() == "" {
		return errorsx.WithStack(oauth2.ErrInvalidClient.WithHint("An Identity Assertion JWT Authorization Grant requires client authentication."))
	}

	if client.IsPublic() {
		return errorsx.WithStack(oauth2.ErrUnauthorizedClient.WithHint("An Identity Assertion JWT Authorization Grant is only supported for confidential clients (Section 9.1)."))
	}

	grantType := request.GetGrantTypes()[0]

	if !client.GetGrantTypes().Has(grantType) {
		return errorsx.WithStack(oauth2.ErrUnauthorizedClient.WithHintf("The OAuth 2.0 Client is not allowed to use authorization grant '%s'.", grantType))
	}

	token, issuer, err := parseAssertion(assertion)
	if err != nil {
		return err
	}

	trusted, header, err := h.trust(ctx, client, token, issuer)
	if err != nil {
		return err
	}

	var (
		claims josejwt.Claims
		raw    = map[string]any{}
	)

	if err = h.verify(ctx, token, trusted, header, &claims, &raw); err != nil {
		return err
	}

	if err = h.validate(ctx, client, claims, raw); err != nil {
		return err
	}

	if err = h.unused(ctx, claims); err != nil {
		return err
	}

	subject, err := h.Storage.ResolveIDJAGSubject(ctx, client, raw)

	switch {
	case errors.Is(err, oauth2.ErrNotFound):
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The subject of the Identity Assertion JWT Authorization Grant could not be resolved."))
	case err != nil:
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	if err = h.grant(ctx, request, client, raw); err != nil {
		return err
	}

	return h.finish(ctx, request, client, subject, claims.Expiry.Time(), raw)
}

// PopulateTokenEndpointResponse issues the access token, and includes the granted resources in the response as Section
// 4.4.1 requires. No refresh token is issued. A single-use grant is consumed here, after the binding phase, so a
// request that fails any check does not consume it.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4.3
func (h *RedeemHandler) PopulateTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
	if !h.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	if err = h.consume(ctx, request.GetRequestForm().Get(consts.FormParameterAssertion)); err != nil {
		return err
	}

	if _, err = h.IssueAccessToken(ctx, h.lifespan(ctx, request.GetClient()), request, response); err != nil {
		return err
	}

	switch resources := request.GetGrantedResource(); len(resources) {
	case 0:
	case 1:
		response.SetExtra(accessResponseResource, resources[0])
	default:
		response.SetExtra(accessResponseResource, []string(resources))
	}

	return nil
}

// CanSkipClientAuth implements oauth2.TokenEndpointHandler. Section 9.1 limits the grant to confidential clients.
func (h *RedeemHandler) CanSkipClientAuth(_ context.Context, _ oauth2.AccessRequester) bool {
	return false
}

// CanHandleTokenEndpointRequest implements oauth2.TokenEndpointHandler. It claims only a request whose assertion is an
// Identity Assertion JWT Authorization Grant, so the client authentication policy of every other 'jwt-bearer' request
// stays with rfc7523.Handler.
func (h *RedeemHandler) CanHandleTokenEndpointRequest(_ context.Context, request oauth2.AccessRequester) bool {
	if !request.GetGrantTypes().ExactOne(consts.GrantTypeOAuthJWTBearer) && !request.GetGrantTypes().ExactOne(consts.GrantTypeOAuthJWTDPoP) {
		return false
	}

	return rfc7523.IsIDJAGAssertion(request.GetRequestForm().Get(consts.FormParameterAssertion))
}

// BindAccessRequest enforces the 'cnf' claim of an Identity Assertion JWT Authorization Grant against the DPoP proof
// rfc9449.Handler published for this request, so it MUST be registered after rfc9449.Handler in the token endpoint
// binding handlers. A malformed proof is rejected by rfc9449.Handler before this runs. rfc9449.Handler also binds the
// session to the proof key, so the issued access token is bound to the key the grant names.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-9.8.1.2
func (h *RedeemHandler) BindAccessRequest(ctx context.Context, request oauth2.AccessRequester) (err error) {
	if !h.CanHandleTokenEndpointRequest(ctx, request) {
		return nil
	}

	jkt, err := confirmationJWKThumbprint(request.GetRequestForm().Get(consts.FormParameterAssertion))

	switch {
	case err != nil:
		return err
	case jkt == "" && request.GetGrantTypes().ExactOne(consts.GrantTypeOAuthJWTDPoP):
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHintf("The '%s' authorization grant requires a 'cnf' claim.", consts.GrantTypeOAuthJWTDPoP))
	case jkt == "":
		return nil
	}

	proof := oauth2.GetDPoPProof(ctx)

	switch {
	case proof == nil:
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("Proof of possession is required for this authorization grant."))
	case subtle.ConstantTimeCompare([]byte(proof.Thumbprint), []byte(jkt)) != 1:
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The DPoP proof key does not match the key the authorization grant is bound to."))
	}

	return nil
}

// PopulateBoundTokenEndpointResponse implements oauth2.TokenEndpointBindingHandler. rfc9449.Handler sets the token
// type of a bound access token.
func (h *RedeemHandler) PopulateBoundTokenEndpointResponse(_ context.Context, _ oauth2.AccessRequester, _ oauth2.AccessResponder) (err error) {
	return nil
}

func (h *RedeemHandler) finish(ctx context.Context, request oauth2.AccessRequester, client oauth2.Client, subject string, expiry time.Time, raw map[string]any) (err error) {
	session, ok := request.GetSession().(interface {
		rfc7523.Session
		oauth2.Session
	})
	if !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebugf("The session must implement rfc7523.Session but got type: %T", request.GetSession()))
	}

	if err := h.confirm(ctx, session, raw); err != nil {
		return err
	}

	if err := h.requireProof(ctx, request, client, raw); err != nil {
		return err
	}

	session.SetSubject(subject)
	expires := time.Now().UTC().Add(h.lifespan(ctx, client)).Round(time.Second)

	// RFC 7521 Section 4.1: the access token SHOULD NOT outlive the assertion.
	if expiry = expiry.UTC(); expiry.Before(expires) {
		expires = expiry
	}

	session.SetExpiresAt(oauth2.AccessToken, expires)

	if s, ok := session.(RedeemSession); ok {
		s.SetIDJAGClaims(raw)
	}

	return nil
}

func (h *RedeemHandler) lifespan(ctx context.Context, client oauth2.Client) time.Duration {
	return oauth2.GetEffectiveLifespan(client, oauth2.GrantTypeJWTBearer, oauth2.AccessToken, h.Config.GetAccessTokenLifespan(ctx))
}

func (h *RedeemHandler) unused(ctx context.Context, claims josejwt.Claims) (err error) {
	if !h.Config.GetIDJAGSingleUse(ctx) {
		return nil
	}

	var used bool

	if used, err = h.Storage.IsIDJAGUsed(ctx, claims.Issuer, claims.ID); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	} else if used {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint(hintIDJAGRedeemed))
	}

	return nil
}

func (h *RedeemHandler) consume(ctx context.Context, assertion string) (err error) {
	if !h.Config.GetIDJAGSingleUse(ctx) {
		return nil
	}

	claims, _, err := unverifiedClaims(assertion)
	if err != nil {
		return err
	}

	if claims.Expiry == nil {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The Identity Assertion JWT Authorization Grant must contain an 'exp' claim."))
	}

	if err = h.Storage.MarkIDJAGUsed(ctx, claims.Issuer, claims.ID, claims.Expiry.Time()); err != nil {
		if errors.Is(err, oauth2.ErrJTIKnown) {
			return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint(hintIDJAGRedeemed))
		}

		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	return nil
}

func (h *RedeemHandler) trust(ctx context.Context, client oauth2.Client, token *josejwt.JSONWebToken, issuer string) (trusted *oauth2.IDJAGTrustedIssuer, header jose.Header, err error) {
	trusted, err = h.Storage.GetIDJAGTrustedIssuer(ctx, issuer)

	switch {
	case errors.Is(err, oauth2.ErrNotFound):
		return nil, header, errorsx.WithStack(oauth2.ErrInvalidGrant.WithHintf("The issuer '%s' is not trusted.", issuer))
	case err != nil:
		return nil, header, errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	if len(trusted.Clients) != 0 && !slices.Contains(trusted.Clients, client.GetID()) {
		return nil, header, errorsx.WithStack(oauth2.ErrInvalidGrant.WithHintf("The OAuth 2.0 Client is not permitted to present grants from the issuer '%s'.", issuer))
	}

	header = token.Headers[0]

	algs := trusted.SigningAlgs
	if len(algs) == 0 {
		algs = []string{string(jose.RS256)}
	}

	if !slices.Contains(algs, header.Algorithm) {
		return nil, header, errorsx.WithStack(oauth2.ErrInvalidGrant.WithHintf("The algorithm '%s' is not permitted for the issuer '%s'.", header.Algorithm, issuer))
	}

	return trusted, header, nil
}

func (h *RedeemHandler) verify(ctx context.Context, token *josejwt.JSONWebToken, trusted *oauth2.IDJAGTrustedIssuer, header jose.Header, claims *josejwt.Claims, raw *map[string]any) (err error) {
	switch {
	case trusted.JSONWebKeys != nil:
		err = verifyWithKeys(token, trusted.JSONWebKeys, header, claims, raw)
	case trusted.JSONWebKeysURI == "":
		return errorsx.WithStack(oauth2.ErrServerError.WithDebugf("The trusted issuer '%s' has no keys.", trusted.Issuer))
	default:
		fetcher := h.Config.GetJWKSFetcherStrategy(ctx)

		for _, ignoreCache := range []bool{false, true} {
			var jwks *jose.JSONWebKeySet

			if jwks, err = fetcher.Resolve(ctx, trusted.JSONWebKeysURI, ignoreCache); err != nil {
				return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
			}

			if err = verifyWithKeys(token, jwks, header, claims, raw); !errors.Is(err, errNoCandidateKey) {
				break
			}
		}
	}

	if err != nil {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("No key of the issuer verifies the Identity Assertion JWT Authorization Grant.").WithWrap(err).WithDebugError(err))
	}

	return nil
}

var errNoCandidateKey = errors.New("no candidate key matches the token header")

func verifyWithKeys(token *josejwt.JSONWebToken, jwks *jose.JSONWebKeySet, header jose.Header, claims *josejwt.Claims, raw *map[string]any) (err error) {
	if jwks == nil {
		return errNoCandidateKey
	}

	err = errNoCandidateKey

	for _, candidate := range jwks.Keys {
		if header.KeyID != "" && candidate.KeyID != header.KeyID {
			continue
		}

		if candidate.Use != "" && candidate.Use != consts.JSONWebTokenUseSignature {
			continue
		}

		if candidate.Algorithm != "" && candidate.Algorithm != header.Algorithm {
			continue
		}

		verified := map[string]any{}

		var verifiedClaims josejwt.Claims

		if err = token.Claims(&candidate, &verifiedClaims, &verified); err != nil {
			continue
		}

		*claims, *raw = verifiedClaims, verified

		return nil
	}

	return err
}

func (h *RedeemHandler) validate(ctx context.Context, client oauth2.Client, claims josejwt.Claims, raw map[string]any) (err error) {
	expected := h.Config.GetAuthorizationServerIdentificationIssuer(ctx)
	if expected == "" {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("The authorization server issuer identifier is not configured."))
	}

	if len(claims.Audience) != 1 || subtle.ConstantTimeCompare([]byte(claims.Audience[0]), []byte(expected)) != 1 {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHintf("The 'aud' claim must contain exactly the issuer identifier '%s'.", expected))
	}

	if claims.Issuer == expected {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The Identity Assertion JWT Authorization Grant was issued by this authorization server, and it must cross a trust domain (Section 9.3)."))
	}

	if err = requireClaims(client, claims, raw); err != nil {
		return err
	}

	if _, ok := raw[claimAuthorizationDetails]; ok {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHintf("The '%s' claim is not supported.", claimAuthorizationDetails))
	}

	now := time.Now()
	skewed := now.Add(max(h.Config.GetJWTClockSkew(ctx), 0))

	switch {
	case claims.Expiry.Time().Before(now):
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The Identity Assertion JWT Authorization Grant is expired."))
	case claims.NotBefore != nil && claims.NotBefore.Time().After(skewed):
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The Identity Assertion JWT Authorization Grant is not yet valid."))
	case claims.IssuedAt.Time().After(skewed):
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The 'iat' claim of the Identity Assertion JWT Authorization Grant is in the future."))
	case claims.Expiry.Time().Sub(claims.IssuedAt.Time()) > h.Config.GetJWTMaxDuration(ctx):
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The 'exp' claim of the Identity Assertion JWT Authorization Grant is unreasonably far in the future."))
	}

	return nil
}

func confirmationJWKThumbprint(assertion string) (jkt string, err error) {
	_, raw, err := unverifiedClaims(assertion)
	if err != nil {
		return "", err
	}

	cnf, _ := raw[consts.ClaimConfirmation].(map[string]any)
	jkt, _ = cnf[consts.ClaimConfirmationJWKThumbprint].(string)

	return jkt, nil
}

func unverifiedClaims(assertion string) (claims josejwt.Claims, raw map[string]any, err error) {
	token, err := josejwt.ParseSigned(assertion, redeemAlgorithms)
	if err != nil {
		return claims, nil, errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("Unable to parse the Identity Assertion JWT Authorization Grant.").WithWrap(err).WithDebugError(err))
	}

	raw = map[string]any{}

	if err = token.UnsafeClaimsWithoutVerification(&claims, &raw); err != nil {
		return claims, nil, errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("Unable to parse the Identity Assertion JWT Authorization Grant.").WithWrap(err).WithDebugError(err))
	}

	return claims, raw, nil
}

func parseAssertion(assertion string) (token *josejwt.JSONWebToken, issuer string, err error) {
	token, err = josejwt.ParseSigned(assertion, redeemAlgorithms)
	if err != nil {
		return nil, "", errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("Unable to parse the Identity Assertion JWT Authorization Grant.").WithWrap(err).WithDebugError(err))
	}

	if len(token.Headers) != 1 {
		return nil, "", errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The Identity Assertion JWT Authorization Grant must have exactly one signature."))
	}

	var unverified josejwt.Claims

	if err = token.UnsafeClaimsWithoutVerification(&unverified); err != nil || unverified.Issuer == "" {
		return nil, "", errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The Identity Assertion JWT Authorization Grant must contain an 'iss' claim."))
	}

	return token, unverified.Issuer, nil
}

func requireClaims(client oauth2.Client, claims josejwt.Claims, raw map[string]any) (err error) {
	clientID, _ := raw[consts.ClaimClientIdentifier].(string)

	switch {
	case claims.Subject == "":
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The Identity Assertion JWT Authorization Grant must contain a 'sub' claim."))
	case claims.ID == "":
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The Identity Assertion JWT Authorization Grant must contain a 'jti' claim."))
	case claims.IssuedAt == nil:
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The Identity Assertion JWT Authorization Grant must contain an 'iat' claim."))
	case claims.Expiry == nil:
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The Identity Assertion JWT Authorization Grant must contain an 'exp' claim."))
	case clientID == "":
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The Identity Assertion JWT Authorization Grant must contain a 'client_id' claim."))
	case clientID != client.GetID():
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The 'client_id' claim does not identify the authenticated client."))
	}

	return nil
}

func (h *RedeemHandler) grant(ctx context.Context, request oauth2.AccessRequester, client oauth2.Client, raw map[string]any) (err error) {
	var granted []string

	switch scope := raw[consts.ClaimScope].(type) {
	case nil:
	case string:
		granted = strings.Fields(scope)
	default:
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The 'scope' claim must be a string."))
	}

	candidates := granted

	if requested := request.GetRequestedScopes(); len(requested) != 0 {
		for _, scope := range requested {
			if !slices.Contains(granted, scope) {
				return errorsx.WithStack(oauth2.ErrInvalidScope.WithHintf("The scope '%s' is not granted by the Identity Assertion JWT Authorization Grant.", scope))
			}
		}

		candidates = requested
	}

	scopeStrategy := oauth2.GetScopeStrategy(ctx, h.Config, client)

	for _, scope := range candidates {
		if scopeStrategy(client.GetScopes(), scope) {
			request.GrantScope(scope)
		}
	}

	return h.grantResources(ctx, request, client, raw)
}

func (h *RedeemHandler) grantResources(ctx context.Context, request oauth2.AccessRequester, client oauth2.Client, raw map[string]any) (err error) {
	var resources []string

	switch resource := raw[consts.ClaimResource].(type) {
	case nil:
	case string:
		resources = []string{resource}
	case []any:
		for _, value := range resource {
			if s, ok := value.(string); ok {
				resources = append(resources, s)
			} else {
				return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The 'resource' claim must be a string or an array of strings."))
			}
		}
	default:
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The 'resource' claim must be a string or an array of strings."))
	}

	if requested := request.GetRequestedResource(); len(requested) != 0 {
		for _, resource := range requested {
			if !slices.Contains(resources, resource) {
				return errorsx.WithStack(oauth2.ErrInvalidTarget.WithHintf("The resource '%s' is not granted by the Identity Assertion JWT Authorization Grant.", resource))
			}
		}

		resources = requested
	}

	resourceStrategy := oauth2.GetResourceStrategy(ctx, h.Config, client)

	// A resource the client is not permitted is dropped, as a scope is.
	for _, resource := range resources {
		if resourceStrategy(client.GetAudience(), []string{resource}) == nil {
			request.GrantResource(resource)
		}
	}

	return nil
}

func (h *RedeemHandler) confirm(ctx context.Context, session oauth2.Session, raw map[string]any) (err error) {
	value, ok := raw[consts.ClaimConfirmation]
	if !ok {
		return nil
	}

	cnf, _ := value.(map[string]any)
	jkt, _ := cnf[consts.ClaimConfirmationJWKThumbprint].(string)

	switch {
	case len(cnf) != 1 || jkt == "":
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The 'cnf' claim must contain only a 'jkt' member."))
	case !h.Config.GetDPoPEnabled(ctx):
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The Identity Assertion JWT Authorization Grant requires proof of possession, which is not enabled."))
	case !oauth2.IsValidDPoPJWKThumbprint(jkt):
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The 'jkt' member of the 'cnf' claim is not a valid JWK SHA-256 Thumbprint."))
	}

	if _, ok = session.(oauth2.DPoPBoundSession); !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("The session does not support DPoP binding."))
	}

	return nil
}

func (h *RedeemHandler) requireProof(ctx context.Context, request oauth2.AccessRequester, client oauth2.Client, raw map[string]any) (err error) {
	_, bound := raw[consts.ClaimConfirmation]

	if request.GetGrantTypes().ExactOne(consts.GrantTypeOAuthJWTDPoP) {
		if !bound {
			return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHintf("The '%s' authorization grant requires a 'cnf' claim.", consts.GrantTypeOAuthJWTDPoP))
		}
	} else if !h.Config.GetDPoPEnabled(ctx) || (!bound && !h.constrained(ctx, client)) {
		return nil
	}

	r, _ := ctx.Value(oauth2.RequestContextKey).(*http.Request)
	if r == nil {
		return nil
	}

	// A single empty value is no proof, as rfc9449.Handler reads it; several values are left to it to reject.
	if values := r.Header.Values(consts.HeaderDPoP); len(values) > 1 || (len(values) == 1 && values[0] != "") {
		return nil
	}

	if bound {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("Proof of possession is required for this authorization grant."))
	}

	return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("A sender-constrained access token is required, and the request has no DPoP proof."))
}

func (h *RedeemHandler) constrained(ctx context.Context, client oauth2.Client) bool {
	if h.Config.GetDPoPEnforce(ctx) {
		return true
	}

	if c, ok := client.(oauth2.DPoPClient); ok {
		return c.GetEnableDPoPBoundAccessTokens()
	}

	return false
}

var (
	_ oauth2.TokenEndpointHandler        = (*RedeemHandler)(nil)
	_ oauth2.TokenEndpointBindingHandler = (*RedeemHandler)(nil)
)
