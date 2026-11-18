// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7523

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"authelia.com/provider/jose"
	"authelia.com/provider/jose/jwt"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/clone"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/jwtgrant"
	oauth2jwt "authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

// Handler implements the RFC 7523 JWT Profile for OAuth 2.0 Authorization Grants at the token endpoint. An assertion is
// accepted from an issuer the Storage trusts, see oauth2.RFC7523TrustedIssuer, and the access token is issued to the
// local subject the Storage resolves from its claims. An assertion whose issuer is one this authorization server issues
// JWT authorization grants as is refused, see oauth2.IsAuthorizationGrantIssuer.
//
// It does not rate limit. The trusted issuer of an assertion is looked up before its signature is verified, so the
// time taken to reject an assertion can reveal whether its issuer is trusted, and a caller that may repeat the request
// can measure it. Deployments SHOULD rate limit failed assertions per client, and per source when
// oauth2.GrantTypeJWTBearerCanSkipClientAuthProvider allows the client to go unauthenticated.
//
// See: https://datatracker.ietf.org/doc/html/rfc7523#section-2.1
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-chaining-17#section-2.4.2
type Handler struct {
	Storage Storage

	Config interface {
		oauth2.AccessTokenLifespanProvider
		oauth2.IssuerProvider
		oauth2.EndpointURLsProvider
		oauth2.AllowedJWTAssertionAudiencesProvider
		oauth2.GrantTypeJWTBearerCanSkipClientAuthProvider
		oauth2.GrantTypeJWTBearerIDOptionalProvider
		oauth2.GrantTypeJWTBearerIssuedDateOptionalProvider
		oauth2.GetJWTMaxDurationProvider
		oauth2.JWTClockSkewProvider
		oauth2.AudienceStrategyProvider
		oauth2.ResourceStrategyProvider
		oauth2.ScopeStrategyProvider
		oauth2.GrantAssertionAlgorithmsProvider
		oauth2.JWKSFetcherStrategyProvider
		oauth2.RFC8693ConfigProvider
	}

	*hoauth2.HandleHelper
}

// HandleTokenEndpointRequest validates the assertion of a JWT bearer grant against its trusted issuer, resolves its
// subject, and grants the audience and resources the issuer permits and the scope the assertion, the issuer and the
// client permit. The access token expires no later than the assertion, the 'offline' and 'offline_access' scopes are
// never granted as no refresh token is issued, and the verified claims are handed to a GrantClaimsSession.
//
// See: https://datatracker.ietf.org/doc/html/rfc7523#section-3
// See: https://datatracker.ietf.org/doc/html/rfc7521#section-4.1
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-chaining-17#section-5.4
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-chaining-17#section-2.4.2
//
//nolint:gocyclo
func (c *Handler) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) (err error) {
	assertion := request.GetRequestForm().Get(consts.FormParameterAssertion)

	if assertion != "" && IsIDJAGAssertion(assertion) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	if err = c.CheckRequest(ctx, request); err != nil {
		return err
	}

	if assertion == "" {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The assertion request parameter must be set when using grant_type of '%s'.", consts.GrantTypeOAuthJWTBearer))
	}

	token, issuer, err := jwtgrant.Parse(grantName, oauth2jwt.ToAsymmetricSignatureAlgorithms(c.Config.GetRFC7523AssertionSigningAlgValues(ctx)), assertion)
	if err != nil {
		return err
	}

	if err = c.validateTokenType(token); err != nil {
		return err
	}

	unverified := jwt.Claims{}

	if err = token.UnsafeClaimsWithoutVerification(&unverified); err != nil || unverified.Subject == "" {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The JWT in 'assertion' request parameter MUST contain a 'sub' (subject) claim."))
	}

	trusted, err := c.trust(ctx, token, issuer)
	if err != nil {
		return err
	}

	keys := jwtgrant.Keys{Issuer: trusted.Issuer, JSONWebKeys: trusted.JSONWebKeys, JSONWebKeysURI: trusted.JSONWebKeysURI, SigningAlgs: trusted.SigningAlgs}

	claims, raw, keyID, err := jwtgrant.Verify(ctx, grantName, token, keys, c.Config.GetJWKSFetcherStrategy)
	if err != nil {
		return unverifiedError(err)
	}

	if err = c.validateClient(request, trusted); err != nil {
		return err
	}

	// A bearer assertion has no proof of possession, so a key bound assertion is never accepted as one.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-parecki-oauth-jwt-dpop-grant-02#section-5.2
	if _, bound := raw[consts.ClaimConfirmation]; bound {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHintf("The JWT in 'assertion' request parameter contains a '%s' (confirmation) claim, which cannot be used with authorization grant '%s'.", consts.ClaimConfirmation, consts.GrantTypeOAuthJWTBearer))
	}

	if err = c.validateTokenClaims(ctx, claims); err != nil {
		return err
	}

	subject, err := c.resolve(ctx, request, trusted, keyID, claims, raw)
	if err != nil {
		return err
	}

	if err = c.grantScopes(ctx, request, trusted, raw); err != nil {
		return err
	}

	if err = c.validateRequestedAudience(ctx, request, trusted.Audience); err != nil {
		return err
	}

	for _, audience := range request.GetRequestedAudience() {
		request.GrantAudience(audience)
	}

	for _, resource := range request.GetRequestedResource() {
		request.GrantResource(resource)
	}

	session, err := c.getSessionFromRequest(request)
	if err != nil {
		return err
	}

	atLifespan := oauth2.GetEffectiveLifespan(request.GetClient(), oauth2.GrantTypeJWTBearer, oauth2.AccessToken, c.HandleHelper.Config.GetAccessTokenLifespan(ctx))

	session.SetExpiresAt(oauth2.AccessToken, jwtgrant.CapExpiry(time.Now().UTC().Add(atLifespan).Round(time.Second), claims.Expiry.Time(), 0))
	session.SetSubject(subject)

	if s, ok := session.(GrantClaimsSession); ok {
		s.SetRFC7523GrantClaims(maps.Clone(raw))
	}

	return nil
}

// PopulateTokenEndpointResponse issues the access token. An assertion carrying a 'jti' is marked as used here, after
// the token endpoint binding phase, so a request that fails any check does not consume it.
//
// See: https://datatracker.ietf.org/doc/html/rfc7523#section-3
func (c *Handler) PopulateTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
	if err = c.CheckRequest(ctx, request); err != nil {
		return err
	}

	assertion := request.GetRequestForm().Get(consts.FormParameterAssertion)

	if IsIDJAGAssertion(assertion) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	if err = c.consume(ctx, assertion); err != nil {
		return err
	}

	atLifespan := oauth2.GetEffectiveLifespan(request.GetClient(), oauth2.GrantTypeJWTBearer, oauth2.AccessToken, c.Config.GetAccessTokenLifespan(ctx))

	_, err = c.IssueAccessToken(ctx, atLifespan, request, response)

	return err
}

func (c *Handler) consume(ctx context.Context, assertion string) (err error) {
	claims, _, err := jwtgrant.UnverifiedClaims(grantName, oauth2jwt.ToAsymmetricSignatureAlgorithms(c.Config.GetRFC7523AssertionSigningAlgValues(ctx)), assertion)
	if err != nil {
		return err
	}

	if claims.ID == "" {
		return nil
	}

	return jwtgrant.Consume(ctx, grantName, func(ctx context.Context) error {
		return c.Storage.MarkRFC7523JWTUsedForTime(ctx, claims.Issuer, claims.ID, claims.Expiry.Time())
	})
}

// CanSkipClientAuth reports whether the configuration permits the JWT bearer grant without client authentication.
func (c *Handler) CanSkipClientAuth(ctx context.Context, request oauth2.AccessRequester) bool {
	return c.Config.GetGrantTypeJWTBearerCanSkipClientAuth(ctx)
}

// CanHandleTokenEndpointRequest reports whether the 'grant_type' is exactly
// 'urn:ietf:params:oauth:grant-type:jwt-bearer'.
func (c *Handler) CanHandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) bool {
	// The 'grant_type' parameter is REQUIRED. Value MUST be set to "urn:ietf:params:oauth:grant-type:jwt-bearer".
	return request.GetGrantTypes().ExactOne(consts.GrantTypeOAuthJWTBearer)
}

// CheckRequest returns oauth2.ErrUnknownRequest when the request is not a JWT bearer grant. When client authentication
// is required, or the client did authenticate, it also requires the client to be registered for the
// 'urn:ietf:params:oauth:grant-type:jwt-bearer' grant type.
func (c *Handler) CheckRequest(ctx context.Context, request oauth2.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	// Client authentication is optional.
	// See: https://www.rfc-editor.org/rfc/rfc7523#section-2.1

	// if client is authenticated, check grant types.
	if (!c.CanSkipClientAuth(ctx, request) || isAuthenticatedClient(request.GetClient())) && !request.GetClient().GetGrantTypes().Has(consts.GrantTypeOAuthJWTBearer) {
		return errorsx.WithStack(oauth2.ErrUnauthorizedClient.WithHintf("The OAuth 2.0 Client is not allowed to use authorization grant '%s'.", consts.GrantTypeOAuthJWTBearer))
	}

	return nil
}

// validateTokenType enforces the JOSE 'typ' header rule from RFC 7519 §5.1: if present, the
// value MUST identify the object as a JWT. Per RFC 6838 media-type matching is
// case-insensitive, and per RFC 8725 §3.11 'application/jwt' is treated equivalently. An
// absent 'typ' header is allowed (it's RECOMMENDED but not required by RFC 7519).
func (c *Handler) validateTokenType(token *jwt.JSONWebToken) error {
	for _, header := range token.Headers {
		raw, ok := header.ExtraHeaders[jose.HeaderType]
		if !ok {
			continue
		}

		typ, _ := raw.(string)
		if typ == "" {
			continue
		}

		if oauth2.IsTxnTokenType(typ) {
			return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The JWT in 'assertion' request parameter is a transaction token, which cannot be used as an assertion."))
		}

		if !strings.EqualFold(typ, consts.JSONWebTokenTypeJWT) && !strings.EqualFold(typ, "application/jwt") {
			return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHintf("The JWT in 'assertion' request parameter has an invalid 'typ' header value '%s'; expected 'JWT'.", typ))
		}
	}

	return nil
}

func (c *Handler) trust(ctx context.Context, token *jwt.JSONWebToken, issuer string) (trusted *oauth2.RFC7523TrustedIssuer, err error) {
	if oauth2.IsAuthorizationGrantIssuer(ctx, c.Config.GetRFC8693TokenTypes(ctx), issuer) {
		verifyDecoy(token)

		return nil, errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint(hintAssertionUnverified).WithDebug("The issuer of the JWT in 'assertion' request parameter is one this authorization server issues JWT authorization grants as, which are issued for another trust domain."))
	}

	if trusted, err = c.Storage.GetRFC7523TrustedIssuer(ctx, issuer); err != nil {
		if errors.Is(err, oauth2.ErrNotFound) {
			verifyDecoy(token)

			return nil, errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint(hintAssertionUnverified).WithWrap(err).WithDebugError(err))
		}

		return nil, errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	if trusted == nil {
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("The storage returned no trusted issuer and no error."))
	}

	if trusted.Issuer != issuer {
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("The storage returned a trusted issuer whose issuer is not the one requested."))
	}

	return trusted, nil
}

func (c *Handler) validateClient(request oauth2.AccessRequester, trusted *oauth2.RFC7523TrustedIssuer) (err error) {
	if len(trusted.Clients) == 0 {
		return nil
	}

	if client := request.GetClient(); !isAuthenticatedClient(client) || client.IsPublic() || !slices.Contains(trusted.Clients, client.GetID()) {
		return errorsx.WithStack(oauth2.ErrAccessDenied.WithHint("The OAuth 2.0 Client is not allowed to use an authorization grant from this issuer."))
	}

	return nil
}

func (c *Handler) validateTokenClaims(ctx context.Context, claims jwt.Claims) (err error) {
	// See: https://www.rfc-editor.org/rfc/rfc10070#section-4
	audiences := oauth2.JWTBearerGrantAudiences(ctx, c.Config)

	if len(audiences) == 0 {
		return errorsx.WithStack(oauth2.ErrServerError.WithHint("The JWT in 'assertion' request parameter can't be validated as the authorization server isn't configured to accept JWT assertions."))
	}

	if len(claims.Audience) == 0 {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The JWT in 'assertion' request parameter MUST contain an 'aud' (audience) claim."))
	}

	validAudience := false

verify:
	for _, unverified := range claims.Audience {
		for _, aud := range audiences {
			if subtle.ConstantTimeCompare([]byte(aud), []byte(unverified)) == 1 {
				validAudience = true
				break verify
			}
		}
	}

	if !validAudience {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHintf("The JWT in 'assertion' request parameter MUST contain an 'aud' (audience) claim containing a value '%s' that identifies the authorization server as an intended audience.", strings.Join(audiences, "', '")))
	}

	if claims.Expiry == nil {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The JWT in 'assertion' request parameter MUST contain an 'exp' (expiration time) claim."))
	}

	if claims.IssuedAt == nil && !c.Config.GetGrantTypeJWTBearerIssuedDateOptional(ctx) {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The JWT in 'assertion' request parameter MUST contain an 'iat' (issued at) claim."))
	}

	// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.1
	if err = jwtgrant.ValidateTime(grantName, claims, jwtgrant.TimeOptions{Skew: max(c.Config.GetJWTClockSkew(ctx), 0), MaxDuration: c.Config.GetJWTMaxDuration(ctx)}); err != nil {
		return err
	}

	if claims.ID == "" {
		if c.Config.GetGrantTypeJWTBearerIDOptional(ctx) {
			return nil
		}

		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The JWT in 'assertion' request parameter MUST contain an 'jti' (JWT ID) claim."))
	}

	return jwtgrant.CheckUnused(ctx, grantName, func(ctx context.Context) (bool, error) {
		return c.Storage.IsRFC7523JWTUsed(ctx, claims.Issuer, claims.ID)
	})
}

func (c *Handler) resolve(ctx context.Context, request oauth2.AccessRequester, trusted *oauth2.RFC7523TrustedIssuer, keyID string, claims jwt.Claims, raw map[string]any) (subject string, err error) {
	if len(trusted.Subjects) != 0 && !slices.Contains(trusted.Subjects, claims.Subject) {
		return "", errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The subject of the JWT in 'assertion' request parameter is not accepted from its issuer."))
	}

	var client oauth2.Client

	if isAuthenticatedClient(request.GetClient()) {
		client = request.GetClient()
	}

	subject, err = c.Storage.ResolveRFC7523Subject(ctx, client, trusted, keyID, clone.Map(raw))

	switch {
	case err == nil && subject != "":
		return subject, nil
	case err == nil:
		return "", errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint(hintSubjectUnresolved))
	case errors.Is(err, oauth2.ErrNotFound):
		return "", errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint(hintSubjectUnresolved).WithWrap(err).WithDebugError(err))
	case errors.Is(err, oauth2.ErrAccessDenied):
		return "", err
	default:
		return "", errorsx.WithStack(oauth2.ErrServerError.WithDebugError(err))
	}
}

func unverifiedError(err error) error {
	if errors.Is(err, oauth2.ErrInvalidGrant) {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint(hintAssertionUnverified).WithWrap(err).WithDebugError(err))
	}

	return err
}

type extendedSession interface {
	Session
	oauth2.Session
}

func (c *Handler) getSessionFromRequest(request oauth2.AccessRequester) (extendedSession, error) {
	session := request.GetSession()
	if jwtSession, ok := session.(extendedSession); !ok {
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithHintf("Session must be of type *rfc7523.Session but got type: %T", session))
	} else {
		return jwtSession, nil
	}
}

func (c *Handler) grantScopes(ctx context.Context, request oauth2.AccessRequester, trusted *oauth2.RFC7523TrustedIssuer, raw map[string]any) (err error) {
	var claim []string

	value, present := raw[consts.ClaimScope]

	if present {
		scope, ok := value.(string)
		if !ok {
			return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHintf("The JWT in 'assertion' request parameter contains a '%s' claim which is not a string.", consts.ClaimScope))
		}

		claim = strings.Fields(scope)
	}

	refusal := c.scopeRefusal(ctx, request.GetClient(), trusted, claim, present)

	requested := request.GetRequestedScopes()

	if len(requested) == 0 {
		for _, scope := range claim {
			if refusal(scope) == "" {
				request.GrantScope(scope)
			}
		}

		return nil
	}

	for _, scope := range requested {
		if hint := refusal(scope); hint != "" {
			return errorsx.WithStack(oauth2.ErrInvalidScope.WithHint(hint))
		}
	}

	for _, scope := range requested {
		request.GrantScope(scope)
	}

	return nil
}

func (c *Handler) scopeRefusal(ctx context.Context, client oauth2.Client, trusted *oauth2.RFC7523TrustedIssuer, claim []string, present bool) (refusal func(scope string) (hint string)) {
	authenticated := isAuthenticatedClient(client)

	issuerStrategy := oauth2.GetScopeStrategy(ctx, c.Config, nil)
	clientStrategy := issuerStrategy

	if authenticated {
		clientStrategy = oauth2.GetScopeStrategy(ctx, c.Config, client)
	}

	return func(scope string) (hint string) {
		switch {
		case scope == consts.ScopeOffline || scope == consts.ScopeOfflineAccess:
			return fmt.Sprintf("The scope '%s' is not available with authorization grant '%s' as it does not issue a refresh token.", scope, consts.GrantTypeOAuthJWTBearer)
		case present && !slices.Contains(claim, scope):
			return fmt.Sprintf("The JWT in 'assertion' request parameter does not grant scope '%s'.", scope)
		case !issuerStrategy(trusted.Scopes, scope):
			return fmt.Sprintf("The issuer '%s' is not allowed to grant scope '%s'.", trusted.Issuer, scope)
		case authenticated && !clientStrategy(client.GetScopes(), scope):
			return fmt.Sprintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope)
		default:
			return ""
		}
	}
}

func (c *Handler) validateRequestedAudience(ctx context.Context, request oauth2.AccessRequester, audience []string) (err error) {
	if err = oauth2.ExactAudienceStrategy(audience, request.GetRequestedAudience()); err != nil {
		return err
	}

	if err = oauth2.ExactAudienceStrategy(audience, request.GetRequestedResource()); err != nil {
		return err
	}

	if err = oauth2.GetAudienceStrategy(ctx, c.Config, nil)(audience, request.GetRequestedAudience()); err != nil {
		return err
	}

	return oauth2.GetResourceStrategy(ctx, c.Config, nil)(audience, request.GetRequestedResource())
}

// GrantTypesSupported returns the grant types this handler serves.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
func (c *Handler) GrantTypesSupported(ctx context.Context) (types []string) {
	return []string{consts.GrantTypeOAuthJWTBearer}
}

// CodeChallengeMethodsSupported returns nil because the handler does not enforce PKCE.
//
// See: https://datatracker.ietf.org/doc/html/rfc7636#section-4.3
func (c *Handler) CodeChallengeMethodsSupported(ctx context.Context) (methods []string) {
	return nil
}

// IDTokenSigningAlgValuesSupported returns nil because the handler does not issue ID Tokens.
//
// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
func (c *Handler) IDTokenSigningAlgValuesSupported(ctx context.Context) (algs []string) {
	return nil
}

// RFC8693TokenTypesSupported returns nil because the handler does not issue RFC 8693 tokens.
//
// See: https://datatracker.ietf.org/doc/html/rfc8693#section-3
func (c *Handler) RFC8693TokenTypesSupported(ctx context.Context) (types []string) {
	return nil
}

var (
	_ oauth2.TokenEndpointHandler = (*Handler)(nil)
)
