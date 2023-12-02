// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc7523

import (
	"context"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"

	"github.com/authelia/goauth2"
	"github.com/authelia/goauth2/handler/oauth2"
	"github.com/authelia/goauth2/internal/errorsx"
)

// #nosec:gosec G101 - False Positive
const grantTypeJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"

type Handler struct {
	Storage RFC7523KeyStorage

	Config interface {
		goauth2.AccessTokenLifespanProvider
		goauth2.TokenURLProvider
		goauth2.GrantTypeJWTBearerCanSkipClientAuthProvider
		goauth2.GrantTypeJWTBearerIDOptionalProvider
		goauth2.GrantTypeJWTBearerIssuedDateOptionalProvider
		goauth2.GetJWTMaxDurationProvider
		goauth2.AudienceStrategyProvider
		goauth2.ScopeStrategyProvider
	}

	*oauth2.HandleHelper
}

var _ goauth2.TokenEndpointHandler = (*Handler)(nil)

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.1.3 (everything) and
// https://tools.ietf.org/html/rfc7523#section-2.1 (everything)
func (c *Handler) HandleTokenEndpointRequest(ctx context.Context, request goauth2.AccessRequester) error {
	if err := c.CheckRequest(ctx, request); err != nil {
		return err
	}

	assertion := request.GetRequestForm().Get("assertion")
	if assertion == "" {
		return errorsx.WithStack(goauth2.ErrInvalidRequest.WithHintf("The assertion request parameter must be set when using grant_type of '%s'.", grantTypeJWTBearer))
	}

	token, err := jwt.ParseSigned(assertion)
	if err != nil {
		return errorsx.WithStack(goauth2.ErrInvalidGrant.
			WithHint("Unable to parse JSON Web Token passed in \"assertion\" request parameter.").
			WithWrap(err).WithDebug(err.Error()),
		)
	}

	// Check fo required claims in token, so we can later find public key based on them.
	if err := c.validateTokenPreRequisites(token); err != nil {
		return err
	}

	key, err := c.findPublicKeyForToken(ctx, token)
	if err != nil {
		return err
	}

	claims := jwt.Claims{}
	if err := token.Claims(key, &claims); err != nil {
		return errorsx.WithStack(goauth2.ErrInvalidGrant.
			WithHint("Unable to verify the integrity of the 'assertion' value.").
			WithWrap(err).WithDebug(err.Error()),
		)
	}

	if err := c.validateTokenClaims(ctx, claims, key); err != nil {
		return err
	}

	scopes, err := c.Storage.GetPublicKeyScopes(ctx, claims.Issuer, claims.Subject, key.KeyID)
	if err != nil {
		return errorsx.WithStack(goauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	for _, scope := range request.GetRequestedScopes() {
		if !c.Config.GetScopeStrategy(ctx)(scopes, scope) {
			return errorsx.WithStack(goauth2.ErrInvalidScope.WithHintf("The public key registered for issuer \"%s\" and subject \"%s\" is not allowed to request scope \"%s\".", claims.Issuer, claims.Subject, scope))
		}
	}

	if claims.ID != "" {
		if err := c.Storage.MarkJWTUsedForTime(ctx, claims.ID, claims.Expiry.Time()); err != nil {
			return errorsx.WithStack(goauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
	}

	for _, scope := range request.GetRequestedScopes() {
		request.GrantScope(scope)
	}

	for _, audience := range claims.Audience {
		request.GrantAudience(audience)
	}

	session, err := c.getSessionFromRequest(request)
	if err != nil {
		return err
	}

	atLifespan := goauth2.GetEffectiveLifespan(request.GetClient(), goauth2.GrantTypeJWTBearer, goauth2.AccessToken, c.HandleHelper.Config.GetAccessTokenLifespan(ctx))
	session.SetExpiresAt(goauth2.AccessToken, time.Now().UTC().Add(atLifespan).Round(time.Second))
	session.SetSubject(claims.Subject)

	return nil
}

func (c *Handler) PopulateTokenEndpointResponse(ctx context.Context, request goauth2.AccessRequester, response goauth2.AccessResponder) error {
	if err := c.CheckRequest(ctx, request); err != nil {
		return err
	}

	atLifespan := goauth2.GetEffectiveLifespan(request.GetClient(), goauth2.GrantTypeJWTBearer, goauth2.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	return c.IssueAccessToken(ctx, atLifespan, request, response)
}

func (c *Handler) CanSkipClientAuth(ctx context.Context, requester goauth2.AccessRequester) bool {
	return c.Config.GetGrantTypeJWTBearerCanSkipClientAuth(ctx)
}

func (c *Handler) CanHandleTokenEndpointRequest(ctx context.Context, requester goauth2.AccessRequester) bool {
	// grant_type REQUIRED.
	// Value MUST be set to "urn:ietf:params:oauth:grant-type:jwt-bearer"
	return requester.GetGrantTypes().ExactOne(grantTypeJWTBearer)
}

func (c *Handler) CheckRequest(ctx context.Context, request goauth2.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(goauth2.ErrUnknownRequest)
	}

	// Client Authentication is optional:
	//
	// Authentication of the client is optional, as described in
	//   Section 3.2.1 of OAuth 2.0 [RFC6749] and consequently, the
	//   "client_id" is only needed when a form of client authentication that
	//   relies on the parameter is used.

	// if client is authenticated, check grant types
	if !c.CanSkipClientAuth(ctx, request) && !request.GetClient().GetGrantTypes().Has(grantTypeJWTBearer) {
		return errorsx.WithStack(goauth2.ErrUnauthorizedClient.WithHintf("The OAuth 2.0 Client is not allowed to use authorization grant \"%s\".", grantTypeJWTBearer))
	}

	return nil
}

func (c *Handler) validateTokenPreRequisites(token *jwt.JSONWebToken) error {
	unverifiedClaims := jwt.Claims{}
	if err := token.UnsafeClaimsWithoutVerification(&unverifiedClaims); err != nil {
		return errorsx.WithStack(goauth2.ErrInvalidGrant.
			WithHint("Looks like there are no claims in JWT in \"assertion\" request parameter.").
			WithWrap(err).WithDebug(err.Error()),
		)
	}
	if unverifiedClaims.Issuer == "" {
		return errorsx.WithStack(goauth2.ErrInvalidGrant.
			WithHint("The JWT in \"assertion\" request parameter MUST contain an \"iss\" (issuer) claim."),
		)
	}
	if unverifiedClaims.Subject == "" {
		return errorsx.WithStack(goauth2.ErrInvalidGrant.
			WithHint("The JWT in \"assertion\" request parameter MUST contain a \"sub\" (subject) claim."),
		)
	}

	return nil
}

func (c *Handler) findPublicKeyForToken(ctx context.Context, token *jwt.JSONWebToken) (*jose.JSONWebKey, error) {
	unverifiedClaims := jwt.Claims{}
	if err := token.UnsafeClaimsWithoutVerification(&unverifiedClaims); err != nil {
		return nil, errorsx.WithStack(goauth2.ErrInvalidRequest.WithWrap(err).WithDebug(err.Error()))
	}

	var keyID string
	for _, header := range token.Headers {
		if header.KeyID != "" {
			keyID = header.KeyID
			break
		}
	}

	keyNotFoundErr := goauth2.ErrInvalidGrant.WithHintf(
		"No public JWK was registered for issuer \"%s\" and subject \"%s\", and public key is required to check signature of JWT in \"assertion\" request parameter.",
		unverifiedClaims.Issuer,
		unverifiedClaims.Subject,
	)
	if keyID != "" {
		key, err := c.Storage.GetPublicKey(ctx, unverifiedClaims.Issuer, unverifiedClaims.Subject, keyID)
		if err != nil {
			return nil, errorsx.WithStack(keyNotFoundErr.WithWrap(err).WithDebug(err.Error()))
		}
		return key, nil
	}

	keys, err := c.Storage.GetPublicKeys(ctx, unverifiedClaims.Issuer, unverifiedClaims.Subject)
	if err != nil {
		return nil, errorsx.WithStack(keyNotFoundErr.WithWrap(err).WithDebug(err.Error()))
	}

	claims := jwt.Claims{}
	for _, key := range keys.Keys {
		err := token.Claims(key, &claims)
		if err == nil {
			return &key, nil
		}
	}

	return nil, errorsx.WithStack(keyNotFoundErr)
}

func (c *Handler) validateTokenClaims(ctx context.Context, claims jwt.Claims, key *jose.JSONWebKey) error {
	if len(claims.Audience) == 0 {
		return errorsx.WithStack(goauth2.ErrInvalidGrant.
			WithHint("The JWT in \"assertion\" request parameter MUST contain an \"aud\" (audience) claim."),
		)
	}

	if !claims.Audience.Contains(c.Config.GetTokenURL(ctx)) {
		return errorsx.WithStack(goauth2.ErrInvalidGrant.
			WithHintf(
				"The JWT in \"assertion\" request parameter MUST contain an \"aud\" (audience) claim containing a value \"%s\" that identifies the authorization server as an intended audience.",
				c.Config.GetTokenURL(ctx),
			),
		)
	}

	if claims.Expiry == nil {
		return errorsx.WithStack(goauth2.ErrInvalidGrant.
			WithHint("The JWT in \"assertion\" request parameter MUST contain an \"exp\" (expiration time) claim."),
		)
	}

	if claims.Expiry.Time().Before(time.Now()) {
		return errorsx.WithStack(goauth2.ErrInvalidGrant.
			WithHint("The JWT in \"assertion\" request parameter expired."),
		)
	}

	if claims.NotBefore != nil && !claims.NotBefore.Time().Before(time.Now()) {
		return errorsx.WithStack(goauth2.ErrInvalidGrant.
			WithHintf(
				"The JWT in \"assertion\" request parameter contains an \"nbf\" (not before) claim, that identifies the time '%s' before which the token MUST NOT be accepted.",
				claims.NotBefore.Time().Format(time.RFC3339),
			),
		)
	}

	if !c.Config.GetGrantTypeJWTBearerIssuedDateOptional(ctx) && claims.IssuedAt == nil {
		return errorsx.WithStack(goauth2.ErrInvalidGrant.
			WithHint("The JWT in \"assertion\" request parameter MUST contain an \"iat\" (issued at) claim."),
		)
	}

	var issuedDate time.Time
	if claims.IssuedAt != nil {
		issuedDate = claims.IssuedAt.Time()
	} else {
		issuedDate = time.Now()
	}
	if claims.Expiry.Time().Sub(issuedDate) > c.Config.GetJWTMaxDuration(ctx) {
		return errorsx.WithStack(goauth2.ErrInvalidGrant.
			WithHintf(
				"The JWT in \"assertion\" request parameter contains an \"exp\" (expiration time) claim with value \"%s\" that is unreasonably far in the future, considering token issued at \"%s\".",
				claims.Expiry.Time().Format(time.RFC3339),
				issuedDate.Format(time.RFC3339),
			),
		)
	}

	if !c.Config.GetGrantTypeJWTBearerIDOptional(ctx) && claims.ID == "" {
		return errorsx.WithStack(goauth2.ErrInvalidGrant.
			WithHint("The JWT in \"assertion\" request parameter MUST contain an \"jti\" (JWT ID) claim."),
		)
	}

	if claims.ID != "" {
		used, err := c.Storage.IsJWTUsed(ctx, claims.ID)
		if err != nil {
			return errorsx.WithStack(goauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
		if used {
			return errorsx.WithStack(goauth2.ErrJTIKnown)
		}
	}

	return nil
}

type extendedSession interface {
	Session
	goauth2.Session
}

func (c *Handler) getSessionFromRequest(requester goauth2.AccessRequester) (extendedSession, error) {
	session := requester.GetSession()
	if jwtSession, ok := session.(extendedSession); !ok {
		return nil, errorsx.WithStack(
			goauth2.ErrServerError.WithHintf("Session must be of type *rfc7523.Session but got type: %T", session),
		)
	} else {
		return jwtSession, nil
	}
}
