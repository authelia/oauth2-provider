// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"context"
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

// TokenExchangeGrantHandler is the grant handler for RFC8693
type TokenExchangeGrantHandler struct {
	Config oauth2.RFC8693ConfigProvider

	ScopeStrategy    oauth2.ScopeStrategy
	AudienceStrategy oauth2.AudienceStrategy
	ResourceStrategy oauth2.ResourceStrategy

	// Storage marks a custom JWT presented as a subject or actor token as used. It is required when a *JWTType
	// sets ValidateJTI.
	Storage CustomJWTStorage
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.3.2
//
//nolint:gocyclo
func (c *TokenExchangeGrantHandler) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	client := request.GetClient()

	if client.IsPublic() {
		return errors.WithStack(oauth2.ErrInvalidGrant.WithHint("The OAuth 2.0 Client is marked as public and is thus not allowed to use authorization grant 'urn:ietf:params:oauth:grant-type:token-exchange'."))
	}

	// Check whether client is allowed to use token exchange
	if !client.GetGrantTypes().Has(consts.GrantTypeOAuthTokenExchange) {
		return errors.WithStack(oauth2.ErrUnauthorizedClient.WithHintf("The OAuth 2.0 Client is not allowed to use authorization grant '%s'.", consts.GrantTypeOAuthTokenExchange))
	}

	var (
		session Session
		ok      bool
	)

	if session, ok = request.GetSession().(Session); !ok || session == nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to perform token exchange because the session is not of the right type."))
	}

	// Only a subject or actor token validated by a token type handler for this request may be issued against, and only
	// an 'act' claim derived from them may be issued.
	session.SetSubjectToken(nil)
	session.SetActorToken(nil)
	session.SetClaimActor(nil)

	form := request.GetRequestForm()
	configTypesSupported := c.Config.GetRFC8693TokenTypes(ctx)

	var (
		supportedSubjectTypes, supportedActorTypes, supportedRequestTypes oauth2.Arguments
		rfc8693Client                                                     Client
	)

	if rfc8693Client, ok = client.(Client); ok {
		supportedRequestTypes = rfc8693Client.GetSupportedRequestTokenTypes()
		supportedActorTypes = rfc8693Client.GetSupportedActorTokenTypes()
		supportedSubjectTypes = rfc8693Client.GetSupportedSubjectTokenTypes()
	}

	var (
		subjectToken, subjectTokenType string
	)

	// From https://tools.ietf.org/html/rfc8693#section-2.1:
	//
	//	subject_token
	//		REQUIRED.  A security token that represents the identity of the
	//		party on behalf of whom the request is being made.  Typically, the
	//		subject of this token will be the subject of the security token
	//		issued in response to the request.
	if subjectToken = form.Get(consts.FormParameterSubjectToken); subjectToken == "" {
		return errors.WithStack(oauth2.ErrInvalidRequest.WithHintf("Mandatory parameter '%s' is missing.", "subject_token"))
	}

	// From https://tools.ietf.org/html/rfc8693#section-2.1:
	//
	//	subject_token_type
	//		REQUIRED.  An identifier, as described in Section 3, that
	//		indicates the type of the security token in the "subject_token"
	//		parameter.
	if subjectTokenType = form.Get(consts.FormParameterSubjectTokenType); subjectTokenType == "" {
		return errors.WithStack(oauth2.ErrInvalidRequest.WithHintf("Mandatory parameter '%s' is missing.", consts.FormParameterSubjectTokenType))
	}

	if tt := configTypesSupported[subjectTokenType]; tt == nil {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' token type is not supported as a '%s'.", subjectTokenType, consts.FormParameterSubjectTokenType))
	}

	if len(supportedSubjectTypes) > 0 && !supportedSubjectTypes.Has(subjectTokenType) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The OAuth 2.0 client is not allowed to use '%s' as '%s'.", subjectTokenType, consts.FormParameterSubjectTokenType))
	}

	var (
		actorToken, actorTokenType string
	)

	// From https://tools.ietf.org/html/rfc8693#section-2.1:
	//
	//	actor_token
	//		OPTIONAL . A security token that represents the identity of the acting party.
	//		Typically, this will be the party that is authorized to use the requested security
	//		token and act on behalf of the subject.
	if actorToken = form.Get(consts.FormParameterActorToken); actorToken != "" {
		// From https://tools.ietf.org/html/rfc8693#section-2.1:
		//
		//	actor_token_type
		//		An identifier, as described in Section 3, that indicates the type of the security token
		//		in the actor_token parameter. This is REQUIRED when the actor_token parameter is present
		//		in the request but MUST NOT be included otherwise.
		if actorTokenType = form.Get(consts.FormParameterActorTokenType); actorTokenType == "" {
			return errors.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' is empty even though the '%s' is not empty.", consts.FormParameterActorTokenType, consts.FormParameterActorToken))
		}

		if tt := configTypesSupported[actorTokenType]; tt == nil {
			return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' token type is not supported as a '%s'.", actorTokenType, consts.FormParameterActorTokenType))
		}

		if len(supportedActorTypes) > 0 && !supportedActorTypes.Has(actorTokenType) {
			return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The OAuth 2.0 client is not allowed to use '%s' as '%s'.", actorTokenType, consts.FormParameterActorTokenType))
		}
	} else if actorTokenType = form.Get(consts.FormParameterActorTokenType); actorTokenType != "" {
		return errors.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' is not empty even though the '%s' is empty.", consts.FormParameterActorTokenType, consts.FormParameterActorToken))
	}

	// check if supported
	requestedTokenType := form.Get(consts.FormParameterRequestedTokenType)
	if requestedTokenType == "" {
		requestedTokenType = c.Config.GetDefaultRFC8693RequestedTokenType(ctx)
	}

	if tt := configTypesSupported[requestedTokenType]; tt == nil {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' token type is not supported as a '%s'.", requestedTokenType, consts.FormParameterRequestedTokenType))
	}

	if len(supportedRequestTypes) > 0 && !supportedRequestTypes.Has(requestedTokenType) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The OAuth 2.0 client is not allowed to use '%s' as '%s'.", requestedTokenType, consts.FormParameterRequestedTokenType))
	}

	if requestedTokenType == consts.TokenTypeRFC8693IDJAG {
		switch subjectTokenType {
		case consts.TokenTypeRFC8693AccessToken, consts.TokenTypeRFC8693IDJAG:
			return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' token type is not supported as a '%s' when the '%s' is '%s'.", subjectTokenType, consts.FormParameterSubjectTokenType, consts.FormParameterRequestedTokenType, consts.TokenTypeRFC8693IDJAG))
		}

		return nil
	}

	// Check the requested scope.
	scopeStrategy := c.GetScopeStrategy(ctx, client)
	for _, scope := range request.GetRequestedScopes() {
		if !scopeStrategy(client.GetScopes(), scope) {
			return errors.WithStack(oauth2.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
	}

	// Check the requested audience.
	if err = c.GetAudienceStrategy(ctx, client)(client.GetAudience(), request.GetRequestedAudience()); err != nil {
		return errors.WithStack(oauth2.ErrInvalidTarget.WithDebugError(err).WithWrap(err))
	}

	// Check the requested resource indicators (RFC 8707).
	if err = c.GetResourceStrategy(ctx, client)(client.GetAudience(), request.GetRequestedResource()); err != nil {
		return errors.WithStack(oauth2.ErrInvalidTarget.WithDebugError(err).WithWrap(err))
	}

	// Grant the validated scopes. The token type handlers reject any scope the subject token does not grant, so what
	// remains is the intersection of the client's and the subject token's scopes.
	for _, scope := range request.GetRequestedScopes() {
		request.GrantScope(scope)
	}

	// Grant the validated audience and resource so the issued token's 'aud' claim reflects
	// the exchange request's RFC 8693 audience and RFC 8707 resource parameters.
	for _, audience := range request.GetRequestedAudience() {
		request.GrantAudience(audience)
	}

	for _, resource := range request.GetRequestedResource() {
		request.GrantResource(resource)
	}

	return nil
}

// GetScopeStrategy returns the locally-configured scope strategy if set, otherwise the one from Config.
func (c *TokenExchangeGrantHandler) GetScopeStrategy(ctx context.Context, client oauth2.Client) (strategy oauth2.ScopeStrategy) {
	if client != nil {
		if p, ok := client.(oauth2.ScopeStrategyProvider); ok {
			if strategy = p.GetScopeStrategy(ctx); strategy != nil {
				return strategy
			}
		}
	}

	if c.ScopeStrategy != nil {
		return c.ScopeStrategy
	}

	if strategy = c.Config.GetScopeStrategy(ctx); strategy != nil {
		return strategy
	}

	return oauth2.ExactScopeStrategy
}

// GetAudienceStrategy returns the locally-configured audience strategy if set, otherwise the one from Config.
func (c *TokenExchangeGrantHandler) GetAudienceStrategy(ctx context.Context, client oauth2.Client) (strategy oauth2.AudienceStrategy) {
	if client != nil {
		if p, ok := client.(oauth2.AudienceStrategyProvider); ok {
			if strategy = p.GetAudienceStrategy(ctx); strategy != nil {
				return strategy
			}
		}
	}

	if c.AudienceStrategy != nil {
		return c.AudienceStrategy
	}

	if strategy = c.Config.GetAudienceStrategy(ctx); strategy != nil {
		return strategy
	}

	return oauth2.DefaultAudienceStrategy
}

// GetResourceStrategy returns the locally-configured resource strategy if set, otherwise the one from Config.
func (c *TokenExchangeGrantHandler) GetResourceStrategy(ctx context.Context, client oauth2.Client) (strategy oauth2.ResourceStrategy) {
	if client != nil {
		if p, ok := client.(oauth2.ResourceStrategyProvider); ok {
			if strategy = p.GetResourceStrategy(ctx); strategy != nil {
				return strategy
			}
		}
	}

	if c.ResourceStrategy != nil {
		return c.ResourceStrategy
	}

	if strategy = c.Config.GetResourceStrategy(ctx); strategy != nil {
		return strategy
	}

	return oauth2.DefaultAudienceStrategy
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-4.3.3.
//
// When the token exchange request includes an 'actor_token' (delegation), this handler is responsible for setting the
// 'act' claim on the issued token's session per RFC 8693 Section 4.1. Pure impersonation (no actor_token) leaves the
// session unchanged so the issued token represents the subject acting alone.
//
// IMPORTANT ordering note: this handler MUST be registered BEFORE the token-type handlers (AccessTokenTypeHandler,
// RefreshTokenTypeHandler, IDTokenTypeHandler, CustomJWTTypeHandler) in the TokenEndpointHandlers slice. The token
// type handlers' PopulateTokenEndpointResponse implementations issue the token by serializing the session, so the
// 'act' claim must be on the session before they run.
//
// An 'actor_token' with neither a 'sub' nor a 'client_id' claim does not identify the actor, and is rejected with
// 'invalid_request' per RFC 8693 Section 2.2.2.
//
// See https://datatracker.ietf.org/doc/html/rfc8693#section-4.1.
func (c *TokenExchangeGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	session, _ := request.GetSession().(Session)
	if session == nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to perform token exchange because the session is not of the right type."))
	}

	form := request.GetRequestForm()
	requestedTokenType := form.Get(consts.FormParameterRequestedTokenType)
	if requestedTokenType == "" {
		requestedTokenType = c.Config.GetDefaultRFC8693RequestedTokenType(ctx)
	}

	configTypesSupported := c.Config.GetRFC8693TokenTypes(ctx)
	if tt := configTypesSupported[requestedTokenType]; tt == nil {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' token type is not supported as a '%s'.", requestedTokenType, consts.FormParameterRequestedTokenType))
	}

	var act map[string]any

	if act, err = buildActClaim(session); err != nil {
		return err
	}

	if err = c.consume(ctx, request, session); err != nil {
		return err
	}

	if act != nil {
		session.SetClaimActor(act)
	}

	return nil
}

func (c *TokenExchangeGrantHandler) consume(ctx context.Context, request oauth2.AccessRequester, session Session) (err error) {
	form := request.GetRequestForm()
	types := c.Config.GetRFC8693TokenTypes(ctx)

	presented := []struct {
		kind   string
		claims map[string]any
	}{
		{form.Get(consts.FormParameterActorTokenType), session.GetActorToken()},
		{form.Get(consts.FormParameterSubjectTokenType), session.GetSubjectToken()},
	}

	type marker struct {
		iss, jti string
		exp      time.Time
	}

	var markers []marker

	for _, token := range presented {
		if jwtType, ok := types[token.kind].(*JWTType); !ok || jwtType == nil || !jwtType.ValidateJTI {
			continue
		}

		if c.Storage == nil {
			return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to perform token exchange because the storage required to validate the 'jti' claim of a JSON Web Token is not configured."))
		}

		iss, _ := token.claims[consts.ClaimIssuer].(string)
		jti, _ := token.claims[consts.ClaimJWTID].(string)

		if jti == "" {
			return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Claim 'jti' from token is missing."))
		}

		if slices.ContainsFunc(markers, func(m marker) bool { return m.iss == iss && m.jti == jti }) {
			continue
		}

		markers = append(markers, marker{iss: iss, jti: jti, exp: time.Unix(toInt64(token.claims[consts.ClaimExpirationTime]), 0)})
	}

	if len(markers) == 0 {
		return nil
	}

	if ctx, err = storage.MaybeBeginTx(ctx, c.Storage); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	for _, m := range markers {
		if c.Storage.SetTokenExchangeCustomJWT(ctx, m.iss, m.jti, m.exp) != nil {
			if err = storage.MaybeRollbackTx(ctx, c.Storage); err != nil {
				return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
			}

			return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Claim 'jti' from the token must be used only once."))
		}
	}

	if err = storage.MaybeCommitTx(ctx, c.Storage); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	return nil
}

// buildActClaim derives the RFC 8693 §4.1 'act' claim for the issued token from the session populated by the upstream
// token-type handlers. It returns nil when no actor_token was supplied (i.e. impersonation, where no 'act' claim is
// required).
//
// The actor's identity is taken from the actor_token's identifying claims ('sub' and 'client_id'), and an actor_token
// with neither is an error. If the subject_token already carried an 'act' claim, that prior actor is nested under the
// new 'act' to express the chain of delegation per §4.1: "the outermost act claim represents the current actor while
// nested act claims represent prior actors".
//
// The function does not mutate any of the input maps; the returned map is a fresh allocation safe for the caller to
// store on the session.
func buildActClaim(session Session) (map[string]any, error) {
	actorToken := session.GetActorToken()
	if actorToken == nil {
		return nil, nil
	}

	act := map[string]any{}

	if sub, ok := actorToken[consts.ClaimSubject].(string); ok && sub != "" {
		act[consts.ClaimSubject] = sub
	}

	if clientID, ok := actorToken[consts.ClaimClientIdentifier].(string); ok && clientID != "" {
		act[consts.ClaimClientIdentifier] = clientID
	}

	if len(act) == 0 {
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' does not identify the actor as it has neither a '%s' nor a '%s' claim.", consts.FormParameterActorToken, consts.ClaimSubject, consts.ClaimClientIdentifier))
	}

	subjectToken := session.GetSubjectToken()
	if subjectToken != nil {
		if existing, ok := subjectToken[consts.ClaimActor].(map[string]any); ok && len(existing) > 0 {
			act[consts.ClaimActor] = copyClaimMap(existing)
		}
	}

	return act, nil
}

// resolveRequestedTokenType returns the oauth2.RFC8693TokenType registered for the request's resolved
// 'requested_token_type' parameter. When 'requested_token_type' is absent on the request the configured default is
// substituted (matching the resolution logic in the token-type handlers' PopulateTokenEndpointResponse). Returns
// nil when the requested type is not registered; callers SHOULD treat that as a server-side configuration error;
// in practice TokenExchangeGrantHandler.HandleTokenEndpointRequest already rejects requests with unknown
// requested_token_type values, so this returns nil only when called outside the normal handler ordering.
func resolveRequestedTokenType(ctx context.Context, request oauth2.AccessRequester, config oauth2.RFC8693ConfigProvider) oauth2.RFC8693TokenType {
	id := request.GetRequestForm().Get(consts.FormParameterRequestedTokenType)
	if id == "" {
		id = config.GetDefaultRFC8693RequestedTokenType(ctx)
	}

	return config.GetRFC8693TokenTypes(ctx)[id]
}

// IsIDJAGRequest returns true when the resolved 'requested_token_type' of the request is an Identity Assertion JWT
// Authorization Grant.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.3
func IsIDJAGRequest(ctx context.Context, request oauth2.Requester, config oauth2.RFC8693ConfigProvider) bool {
	requested := request.GetRequestForm().Get(consts.FormParameterRequestedTokenType)
	if requested == "" {
		requested = config.GetDefaultRFC8693RequestedTokenType(ctx)
	}

	return requested == consts.TokenTypeRFC8693IDJAG
}

// RequireSubjectToken returns an error unless a token type handler validated the 'subject_token' of the request.
func RequireSubjectToken(request oauth2.AccessRequester) (err error) {
	return requireSubjectToken(request)
}

// RequireActorToken returns an error when the request carries an 'actor_token' no token type handler validated.
func RequireActorToken(request oauth2.AccessRequester) (err error) {
	return requireActorToken(request)
}

// CapToSubjectTokenExpiry returns the earlier of expires and the expiry of the validated 'subject_token'.
func CapToSubjectTokenExpiry(request oauth2.Requester, expires time.Time) time.Time {
	return capToSubjectTokenExpiry(request, expires)
}

func errExchangeTokenValidation(err error) error {
	if !hoauth2.IsTokenRejection(err) {
		return errors.WithStack(err)
	}

	return errors.WithStack(oauth2.ErrInvalidRequest.WithHint("Token is not valid or has expired.").WithDebugError(err))
}

// validateExchangeTokenPolicy applies the client and scope policy for a 'subject_token' or 'actor_token' resolved
// back to the request it was issued for.
//
// A client may not exchange a subject token issued to itself, and may only request scopes the subject token was
// granted. Neither rule applies to an actor token, which identifies the acting party rather than the authority
// being exchanged: that party is normally the requesting client itself, and the issued token's scopes come from
// the subject token.
//
// See https://datatracker.ietf.org/doc/html/rfc8693#section-2.1.
func validateExchangeTokenPolicy(ctx context.Context, request oauth2.AccessRequester, config oauth2.RFC8693ConfigProvider, strategy oauth2.ScopeStrategy, original oauth2.Requester, role tokenRole) (err error) {
	client := request.GetClient()
	originalClientID := original.GetClient().GetID()
	self := client.GetID() == originalClientID

	if role == tokenRoleSubject && IsIDJAGRequest(ctx, request, config) {
		if !self {
			return errors.WithStack(oauth2.ErrInvalidGrant.WithHintf("The subject token was not issued to the OAuth 2.0 client requesting a '%s'.", consts.TokenTypeRFC8693IDJAG))
		}

		return nil
	}

	if self && role == tokenRoleSubject {
		return errors.WithStack(oauth2.ErrInvalidGrant.WithHint("Clients are not allowed to perform a token exchange on their own tokens."))
	}

	// A client implicitly authorizes the exchange of its own token.
	if !self {
		if originalClient, ok := original.GetClient().(Client); ok {
			if !originalClient.GetTokenExchangePermitted(client, resolveRequestedTokenType(ctx, request, config)) {
				return errors.WithStack(oauth2.ErrInvalidGrant.WithHintf("The OAuth 2.0 client is not permitted to exchange %s issued to client %s", role.hint(), originalClientID))
			}
		}
	}

	if role != tokenRoleSubject {
		return nil
	}

	return validateRequestedScopes(request, strategy, original.GetGrantedScopes())
}

func validateSubjectTokenScope(request oauth2.AccessRequester, granted []string) (err error) {
	return validateRequestedScopes(request, oauth2.ExactScopeStrategy, granted)
}

func validateRequestedScopes(request oauth2.AccessRequester, strategy oauth2.ScopeStrategy, granted []string) (err error) {
	for _, scope := range request.GetRequestedScopes() {
		if !strategy(granted, scope) {
			return errors.WithStack(oauth2.ErrInvalidScope.WithHintf("The subject token is not granted '%s' and so this scope cannot be requested.", scope))
		}
	}

	return nil
}

func scopeClaim(claims map[string]any) (scopes []string) {
	switch value := claims[consts.ClaimScope].(type) {
	case string:
		return strings.Fields(value)
	case []string:
		return value
	case []any:
		for _, item := range value {
			if scope, ok := item.(string); ok {
				scopes = append(scopes, scope)
			}
		}
	}

	return scopes
}

// copyClaimMap returns a deep copy of the supplied claim map so the caller can mutate or store the result without
// disturbing the source map (e.g. the subject_token snapshot persisted on the session). Nested maps are recursively
// copied; other values are copied by reference since claim values are expected to be immutable JSON scalars or slices.
func copyClaimMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}

	dst := make(map[string]any, len(src))

	for k, v := range src {
		if nested, ok := v.(map[string]any); ok {
			dst[k] = copyClaimMap(nested)

			continue
		}

		dst[k] = v
	}

	return dst
}

// CanSkipClientAuth indicates if client auth can be skipped
func (c *TokenExchangeGrantHandler) CanSkipClientAuth(ctx context.Context, request oauth2.AccessRequester) bool {
	return false
}

// CanHandleTokenEndpointRequest indicates if the token endpoint request can be handled
func (c *TokenExchangeGrantHandler) CanHandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) bool {
	// grant_type REQUIRED.
	return request.GetGrantTypes().ExactOne(consts.GrantTypeOAuthTokenExchange)
}

type tokenBinding struct {
	jkt string
	x5t string
}

func (b tokenBinding) none() bool {
	return b.jkt == "" && b.x5t == ""
}

func bindingOf(session oauth2.Session) (binding tokenBinding) {
	if session == nil {
		return binding
	}

	if bound, ok := session.(oauth2.DPoPBoundSession); ok {
		binding.jkt = bound.GetDPoPJWKThumbprint()
	}

	if bound, ok := session.(oauth2.MTLSBoundSession); ok {
		binding.x5t = bound.GetClientCertificateSHA256Thumbprint()
	}

	return binding
}

func newTokenSession(session oauth2.Session) oauth2.Session {
	if t := reflect.TypeOf(session); t != nil && t.Kind() == reflect.Pointer {
		if s, ok := reflect.New(t.Elem()).Interface().(oauth2.Session); ok {
			return s
		}
	}

	return session.Clone()
}

func tokenClaimsMap(session oauth2.Session) map[string]any {
	if s, ok := session.(Session); ok && s != nil {
		return s.AccessTokenClaimsMap()
	}

	claims := map[string]any{}

	if s, ok := session.(oauth2.ExtraClaimsSession); ok && s != nil {
		maps.Copy(claims, s.GetExtraClaims())
	}

	claims[consts.ClaimSubject] = session.GetSubject()
	claims[consts.ClaimUsername] = session.GetUsername()

	return claims
}

func authenticationContextClaims(session oauth2.Session) (claims map[string]any) {
	claims = map[string]any{}

	s, ok := session.(interface{ IDTokenClaims() *jwt.IDTokenClaims })
	if !ok {
		return claims
	}

	login := s.IDTokenClaims()
	if login == nil {
		return claims
	}

	if login.AuthTime != nil {
		claims[consts.ClaimAuthenticationTime] = login.AuthTime.Unix()
	}

	if login.AuthenticationContextClassReference != "" {
		claims[consts.ClaimAuthenticationContextClassReference] = login.AuthenticationContextClassReference
	}

	if len(login.AuthenticationMethodsReferences) != 0 {
		claims[consts.ClaimAuthenticationMethodsReference] = slices.Clone(login.AuthenticationMethodsReferences)
	}

	return claims
}

func bindingOfConfirmation(claims map[string]any) (binding tokenBinding, err error) {
	var key string

	if key, err = oauth2.GetOIDCKeyBindingConfirmationJWKThumbprint(claims); err != nil {
		return tokenBinding{}, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The 'cnf' claim of the presented token carries a 'jwk' that could not be read as a JSON Web Key.").WithWrap(err).WithDebugError(err))
	}

	binding.jkt = oauth2.GetDPoPConfirmationJWKThumbprint(claims)
	binding.x5t = oauth2.GetMTLSConfirmationX509SHA256Thumbprint(claims)

	switch {
	case binding.jkt == "":
		binding.jkt = key
	case key != "" && key != binding.jkt:
		return tokenBinding{}, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The 'cnf' claim of the presented token carries a 'jkt' and a 'jwk' that identify different keys."))
	}

	return binding, nil
}

func clearInheritedKeyBinding(session oauth2.Session) {
	bound, ok := session.(oauth2.DPoPBoundSession)
	if !ok {
		return
	}

	bound.SetOIDCKeyBindingGranted(false)
	bound.SetDPoPPublicKeyJWK(nil)
	bound.SetRequestedDPoPJWKThumbprint("")
}

func inheritTokenBinding(request oauth2.AccessRequester, incoming tokenBinding, role tokenRole, prior tokenBinding) (err error) {
	session := request.GetSession()

	clearInheritedKeyBinding(session)

	if incoming.none() {
		return nil
	}

	// Section 2.2.2 mandates 'invalid_request' when a subject or actor token is unacceptable based on policy, which
	// is what this is; it is not 'invalid_grant', despite the fault lying in the tokens rather than the syntax.
	if !prior.none() && prior != incoming {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The subject token and the actor token are bound to different keys or certificates, and the issued token can only carry one binding."))
	}

	if incoming.jkt != "" {
		bound, ok := session.(oauth2.DPoPBoundSession)
		if !ok {
			return errorsx.WithStack(oauth2.ErrServerError.WithHintf("The session does not support DPoP binding, which is required to exchange %s bound to a DPoP proof-of-possession key.", role.hint()))
		}

		bound.SetDPoPJWKThumbprint(incoming.jkt)
	}

	if incoming.x5t != "" {
		bound, ok := session.(oauth2.MTLSBoundSession)
		if !ok {
			return errorsx.WithStack(oauth2.ErrServerError.WithHintf("The session does not support mutual-TLS certificate binding, which is required to exchange %s bound to a client certificate.", role.hint()))
		}

		bound.SetClientCertificateSHA256Thumbprint(incoming.x5t)
	}

	return nil
}

func requireSubjectToken(request oauth2.AccessRequester) (err error) {
	if session, ok := request.GetSession().(Session); ok && session != nil && session.GetSubjectToken() != nil {
		return nil
	}

	subjectTokenType := request.GetRequestForm().Get(consts.FormParameterSubjectTokenType)

	return errorsx.WithStack(oauth2.ErrInvalidRequest.
		WithHintf("The '%s' token type is not supported as a '%s'.", subjectTokenType, consts.FormParameterSubjectTokenType).
		WithDebugf("The '%s' value '%s' is registered in the token types configuration but no token type handler validated a subject token for it, so the '%s' was never read. A registered type must be claimed by one of the token type handlers, being one of the three built-in types or a '*rfc8693.JWTType'.", consts.FormParameterSubjectTokenType, subjectTokenType, consts.FormParameterSubjectToken))
}

func requireActorToken(request oauth2.AccessRequester) (err error) {
	form := request.GetRequestForm()

	if form.Get(consts.FormParameterActorToken) == "" {
		return nil
	}

	if session, ok := request.GetSession().(Session); ok && session != nil && session.GetActorToken() != nil {
		return nil
	}

	actorTokenType := form.Get(consts.FormParameterActorTokenType)

	return errorsx.WithStack(oauth2.ErrInvalidRequest.
		WithHintf("The '%s' token type is not supported as a '%s'.", actorTokenType, consts.FormParameterActorTokenType).
		WithDebugf("The '%s' value '%s' is registered in the token types configuration but no token type handler validated an actor token for it, so the '%s' was never read. A registered type must be claimed by one of the token type handlers, being one of the three built-in types or a '*rfc8693.JWTType'.", consts.FormParameterActorTokenType, actorTokenType, consts.FormParameterActorToken))
}

func isRefreshTokenSubject(request oauth2.Requester) bool {
	return request.GetRequestForm().Get(consts.FormParameterSubjectTokenType) == consts.TokenTypeRFC8693RefreshToken
}

func subjectTokenExpiry(request oauth2.Requester) time.Time {
	session, ok := request.GetSession().(Session)
	if !ok || session == nil {
		return time.Time{}
	}

	if subject := toInt64(session.GetSubjectToken()[consts.ClaimExpirationTime]); subject > 0 {
		return time.Unix(subject, 0).UTC()
	}

	return time.Time{}
}

func capToSubjectTokenExpiry(request oauth2.Requester, expires time.Time) time.Time {
	if limit := subjectTokenExpiry(request); !limit.IsZero() && limit.Before(expires) {
		return limit
	}

	return expires
}

func refreshTokenExpiry(request oauth2.Requester, lifespan time.Duration) time.Time {
	if lifespan > -1 {
		return capToSubjectTokenExpiry(request, time.Now().UTC().Add(lifespan)).Truncate(jwt.TimePrecision)
	}

	return subjectTokenExpiry(request)
}

func recordSubjectTokenDeadline(request oauth2.Requester) {
	session, ok := request.GetSession().(interface{ SetExpiryDeadline(deadline time.Time) })
	if !ok {
		return
	}

	if deadline := subjectTokenExpiry(request); !deadline.IsZero() {
		session.SetExpiryDeadline(deadline)
	}
}
