// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc7523

import (
	"context"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

type Handler struct {
	Storage RFC7523KeyStorage

	Config interface {
		oauth2.AccessTokenLifespanProvider
		oauth2.TokenURLProvider
		oauth2.GrantTypeJWTBearerCanSkipClientAuthProvider
		oauth2.GrantTypeJWTBearerIDOptionalProvider
		oauth2.GrantTypeJWTBearerIssuedDateOptionalProvider
		oauth2.GetJWTMaxDurationProvider
		oauth2.AudienceStrategyProvider
		oauth2.ScopeStrategyProvider
	}

	*hoauth2.HandleHelper
}

var (
	_ oauth2.TokenEndpointHandler = (*Handler)(nil)
)

// HandleTokenEndpointRequest implements https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3 (everything) and
// https://datatracker.ietf.org/doc/html/rfc7523#section-2.1 (everything)
//
// TODO: Refactor time permitting.
//
//nolint:gocyclo
func (c *Handler) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) (err error) {
	if err = c.CheckRequest(ctx, request); err != nil {
		return err
	}

	assertion := request.GetRequestForm().Get(consts.FormParameterAssertion)
	if assertion == "" {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The assertion request parameter must be set when using grant_type of '%s'.", consts.GrantTypeOAuthJWTBearer))
	}

	token, err := jwt.ParseSigned(assertion, []jose.SignatureAlgorithm{jose.HS256, jose.HS384, jose.HS512, jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512})
	if err != nil {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.
			WithHint("Unable to parse JSON Web Token passed in 'assertion' request parameter.").
			WithWrap(err).WithDebugError(err),
		)
	}

	// Check fo required claims in token, so we can later find public key based on them.
	if err = c.validateTokenPreRequisites(token); err != nil {
		return err
	}

	key, err := c.findPublicKeyForToken(ctx, token)
	if err != nil {
		return err
	}

	claims := jwt.Claims{}

	if err = token.Claims(key, &claims); err != nil {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.
			WithHint("Unable to verify the integrity of the 'assertion' value.").
			WithWrap(err).WithDebugError(err),
		)
	}

	if err = c.validateTokenClaims(ctx, claims, key); err != nil {
		return err
	}

	scopes, err := c.Storage.GetPublicKeyScopes(ctx, claims.Issuer, claims.Subject, key.KeyID)
	if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	for _, scope := range request.GetRequestedScopes() {
		if !c.Config.GetScopeStrategy(ctx)(scopes, scope) {
			return errorsx.WithStack(oauth2.ErrInvalidScope.WithHintf("The public key registered for issuer '%s' and subject '%s' is not allowed to request scope '%s'.", claims.Issuer, claims.Subject, scope))
		}
	}

	if claims.ID != "" {
		if err := c.Storage.MarkJWTUsedForTime(ctx, claims.ID, claims.Expiry.Time()); err != nil {
			return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
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

	atLifespan := oauth2.GetEffectiveLifespan(request.GetClient(), oauth2.GrantTypeJWTBearer, oauth2.AccessToken, c.HandleHelper.Config.GetAccessTokenLifespan(ctx))
	session.SetExpiresAt(oauth2.AccessToken, time.Now().UTC().Add(atLifespan).Round(time.Second))
	session.SetSubject(claims.Subject)

	return nil
}

func (c *Handler) PopulateTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) error {
	if err := c.CheckRequest(ctx, request); err != nil {
		return err
	}

	atLifespan := oauth2.GetEffectiveLifespan(request.GetClient(), oauth2.GrantTypeJWTBearer, oauth2.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	return c.IssueAccessToken(ctx, atLifespan, request, response)
}

func (c *Handler) CanSkipClientAuth(ctx context.Context, requester oauth2.AccessRequester) bool {
	return c.Config.GetGrantTypeJWTBearerCanSkipClientAuth(ctx)
}

func (c *Handler) CanHandleTokenEndpointRequest(ctx context.Context, requester oauth2.AccessRequester) bool {
	// grant_type REQUIRED.
	// Value MUST be set to "urn:ietf:params:oauth:grant-type:jwt-bearer"
	return requester.GetGrantTypes().ExactOne(consts.GrantTypeOAuthJWTBearer)
}

func (c *Handler) CheckRequest(ctx context.Context, request oauth2.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	// Client Authentication is optional:
	//
	// Authentication of the client is optional, as described in
	//   Section 3.2.1 of OAuth 2.0 [RFC6749] and consequently, the
	//   "client_id" is only needed when a form of client authentication that
	//   relies on the parameter is used.

	// if client is authenticated, check grant types
	if !c.CanSkipClientAuth(ctx, request) && !request.GetClient().GetGrantTypes().Has(consts.GrantTypeOAuthJWTBearer) {
		return errorsx.WithStack(oauth2.ErrUnauthorizedClient.WithHintf("The OAuth 2.0 Client is not allowed to use authorization grant '%s'.", consts.GrantTypeOAuthJWTBearer))
	}

	return nil
}

func (c *Handler) validateTokenPreRequisites(token *jwt.JSONWebToken) error {
	unverifiedClaims := jwt.Claims{}
	if err := token.UnsafeClaimsWithoutVerification(&unverifiedClaims); err != nil {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.
			WithHint("Looks like there are no claims in JWT in 'assertion' request parameter.").
			WithWrap(err).WithDebugError(err),
		)
	}
	if unverifiedClaims.Issuer == "" {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.
			WithHint("The JWT in 'assertion' request parameter MUST contain an 'iss' (issuer) claim."),
		)
	}
	if unverifiedClaims.Subject == "" {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.
			WithHint("The JWT in 'assertion' request parameter MUST contain a 'sub' (subject) claim."),
		)
	}

	return nil
}

func (c *Handler) findPublicKeyForToken(ctx context.Context, token *jwt.JSONWebToken) (*jose.JSONWebKey, error) {
	unverifiedClaims := jwt.Claims{}
	if err := token.UnsafeClaimsWithoutVerification(&unverifiedClaims); err != nil {
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithWrap(err).WithDebugError(err))
	}

	var keyID string
	for _, header := range token.Headers {
		if header.KeyID != "" {
			keyID = header.KeyID
			break
		}
	}

	keyNotFoundErr := oauth2.ErrInvalidGrant.WithHintf(
		"No public JWK was registered for issuer '%s' and subject '%s', and public key is required to check signature of JWT in 'assertion' request parameter.",
		unverifiedClaims.Issuer,
		unverifiedClaims.Subject,
	)
	if keyID != "" {
		key, err := c.Storage.GetPublicKey(ctx, unverifiedClaims.Issuer, unverifiedClaims.Subject, keyID)
		if err != nil {
			return nil, errorsx.WithStack(keyNotFoundErr.WithWrap(err).WithDebugError(err))
		}
		return key, nil
	}

	keys, err := c.Storage.GetPublicKeys(ctx, unverifiedClaims.Issuer, unverifiedClaims.Subject)
	if err != nil {
		return nil, errorsx.WithStack(keyNotFoundErr.WithWrap(err).WithDebugError(err))
	}

	claims := jwt.Claims{}

	for _, key := range keys.Keys {
		if err = token.Claims(key, &claims); err == nil {
			return &key, nil
		}
	}

	return nil, errorsx.WithStack(keyNotFoundErr)
}

// TODO: Refactor time permitting.
//
//nolint:gocyclo,unparam
func (c *Handler) validateTokenClaims(ctx context.Context, claims jwt.Claims, key *jose.JSONWebKey) error {
	if len(claims.Audience) == 0 {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.
			WithHint("The JWT in 'assertion' request parameter MUST contain an 'aud' (audience) claim."),
		)
	}

	if !claims.Audience.Contains(c.Config.GetTokenURL(ctx)) {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.
			WithHintf(
				"The JWT in 'assertion' request parameter MUST contain an 'aud' (audience) claim containing a value '%s' that identifies the authorization server as an intended audience.",
				c.Config.GetTokenURL(ctx),
			),
		)
	}

	if claims.Expiry == nil {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.
			WithHint("The JWT in 'assertion' request parameter MUST contain an 'exp' (expiration time) claim."),
		)
	}

	if claims.Expiry.Time().Before(time.Now()) {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.
			WithHint("The JWT in 'assertion' request parameter expired."),
		)
	}

	if claims.NotBefore != nil && !claims.NotBefore.Time().Before(time.Now()) {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.
			WithHintf(
				"The JWT in 'assertion' request parameter contains an 'nbf' (not before) claim, that identifies the time '%s' before which the token MUST NOT be accepted.",
				claims.NotBefore.Time().Format(time.RFC3339),
			),
		)
	}

	if !c.Config.GetGrantTypeJWTBearerIssuedDateOptional(ctx) && claims.IssuedAt == nil {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.
			WithHint("The JWT in 'assertion' request parameter MUST contain an 'iat' (issued at) claim."),
		)
	}

	var issuedDate time.Time
	if claims.IssuedAt != nil {
		issuedDate = claims.IssuedAt.Time()
	} else {
		issuedDate = time.Now()
	}
	if claims.Expiry.Time().Sub(issuedDate) > c.Config.GetJWTMaxDuration(ctx) {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.
			WithHintf(
				"The JWT in 'assertion' request parameter contains an 'exp' (expiration time) claim with value '%s' that is unreasonably far in the future, considering token issued at '%s'.",
				claims.Expiry.Time().Format(time.RFC3339),
				issuedDate.Format(time.RFC3339),
			),
		)
	}

	if !c.Config.GetGrantTypeJWTBearerIDOptional(ctx) && claims.ID == "" {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.
			WithHint("The JWT in 'assertion' request parameter MUST contain an 'jti' (JWT ID) claim."),
		)
	}

	if claims.ID != "" {
		used, err := c.Storage.IsJWTUsed(ctx, claims.ID)
		if err != nil {
			return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
		}
		if used {
			return errorsx.WithStack(oauth2.ErrJTIKnown)
		}
	}

	return nil
}

type extendedSession interface {
	Session
	oauth2.Session
}

func (c *Handler) getSessionFromRequest(requester oauth2.AccessRequester) (extendedSession, error) {
	session := requester.GetSession()
	if jwtSession, ok := session.(extendedSession); !ok {
		return nil, errorsx.WithStack(
			oauth2.ErrServerError.WithHintf("Session must be of type *rfc7523.Session but got type: %T", session),
		)
	} else {
		return jwtSession, nil
	}
}
