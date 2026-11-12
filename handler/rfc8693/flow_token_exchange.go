// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
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

	// Storage marks a custom or self-signed JWT presented as a subject or actor token as used. It is required when a
	// *JWTType validation or *SelfSignedTokenType sets ValidateJTI, other than on a request for a Transaction Token, where
	// TxnTokenTypeHandler.JTIStorage marks it once the token is signed.
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
		// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-4.3.3
		if IsIDJAGRequest(ctx, request, c.Config) {
			return errors.WithStack(oauth2.ErrInvalidClient.WithHintf("A '%s' requires client authentication.", consts.TokenTypeRFC8693IDJAG))
		}

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

	// The 'subject_token' is REQUIRED.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc8693#section-2.1
	if subjectToken = form.Get(consts.FormParameterSubjectToken); subjectToken == "" {
		return errors.WithStack(oauth2.ErrInvalidRequest.WithHintf("Mandatory parameter '%s' is missing.", "subject_token"))
	}

	// The 'subject_token_type' is REQUIRED.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc8693#section-2.1
	if subjectTokenType = form.Get(consts.FormParameterSubjectTokenType); subjectTokenType == "" {
		return errors.WithStack(oauth2.ErrInvalidRequest.WithHintf("Mandatory parameter '%s' is missing.", consts.FormParameterSubjectTokenType))
	}

	if !isAcceptedTokenType(configTypesSupported[subjectTokenType]) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' token type is not supported as a '%s'.", subjectTokenType, consts.FormParameterSubjectTokenType))
	}

	if len(supportedSubjectTypes) > 0 && !supportedSubjectTypes.Has(subjectTokenType) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The OAuth 2.0 client is not allowed to use '%s' as '%s'.", subjectTokenType, consts.FormParameterSubjectTokenType))
	}

	var (
		actorToken, actorTokenType string
	)

	// The 'actor_token' is OPTIONAL.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc8693#section-2.1
	if actorToken = form.Get(consts.FormParameterActorToken); actorToken != "" {
		// The 'actor_token_type' is REQUIRED when the 'actor_token' is present and MUST NOT be included otherwise.
		//
		// See: https://datatracker.ietf.org/doc/html/rfc8693#section-2.1
		if actorTokenType = form.Get(consts.FormParameterActorTokenType); actorTokenType == "" {
			return errors.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' is empty even though the '%s' is not empty.", consts.FormParameterActorTokenType, consts.FormParameterActorToken))
		}

		if !isAcceptedTokenType(configTypesSupported[actorTokenType]) {
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

	requestedType := configTypesSupported[requestedTokenType]
	if !IsIssuable(requestedType) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' token type is not supported as a '%s'.", requestedTokenType, consts.FormParameterRequestedTokenType))
	}

	if tokenType, ok := requestedType.(*JWTType); ok && tokenType.Issue.Issuer == "" {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebugf("The JSON Web Token type '%s' has no issuer.", requestedTokenType))
	}

	if len(supportedRequestTypes) > 0 && !supportedRequestTypes.Has(requestedTokenType) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The OAuth 2.0 client is not allowed to use '%s' as '%s'.", requestedTokenType, consts.FormParameterRequestedTokenType))
	}

	if requestedTokenType == consts.TokenTypeRFC8693IDJAG {
		// The IdP MUST determine that it issued the subject token for that purpose, which only an ID Token or a refresh
		// token establishes.
		//
		// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-4.3.3
		switch subjectTokenType {
		case consts.TokenTypeRFC8693IDToken, consts.TokenTypeRFC8693RefreshToken:
		default:
			return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' token type is not supported as a '%s' when the '%s' is '%s'.", subjectTokenType, consts.FormParameterSubjectTokenType, consts.FormParameterRequestedTokenType, consts.TokenTypeRFC8693IDJAG))
		}

		// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-4.3.3
		if len(request.GetRequestedAudience()) != 1 {
			return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("Exactly one '%s' is required when the '%s' is '%s'.", consts.FormParameterAudience, consts.FormParameterRequestedTokenType, consts.TokenTypeRFC8693IDJAG))
		}

		// Section 4.3 defines no processing for the 'actor_token' and the grant would not identify the actor.
		//
		// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-4.3.3
		if actorToken != "" {
			return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' is not supported when the '%s' is '%s'.", consts.FormParameterActorToken, consts.FormParameterRequestedTokenType, consts.TokenTypeRFC8693IDJAG))
		}

		return nil
	}

	if txnType, isTxn := configTypesSupported[requestedTokenType].(*TxnTokenType); isTxn && txnType != nil {
		if err = validateTxnTokenRequest(ctx, request, c.Config, txnType); err != nil {
			return err
		}
	}

	if authorizationGrantType(ctx, request, c.Config) != nil {
		if !allowsAuthorizationGrantIssuance(client) {
			return errors.WithStack(oauth2.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not permitted to be issued a JWT authorization grant via token exchange."))
		}

		if err = validateAuthorizationGrantTarget(request); err != nil {
			return err
		}
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
	if err = c.GetResourceStrategy(ctx, client)(client.GetResource(), request.GetRequestedResource()); err != nil {
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
// session unchanged so the issued token represents the subject acting alone. A 'subject_token' with an 'act' claim is
// rejected without an 'actor_token', as the issued token would no longer record the prior actors, unless it is a JWT
// authorization grant which carries them over.
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

	if err = validateActorChainDepth(ctx, c.Config, session); err != nil {
		return err
	}

	var act map[string]any

	if act, err = buildActClaim(session); err != nil {
		return err
	}

	if _, delegated := session.GetSubjectToken()[consts.ClaimActor]; delegated && act == nil && authorizationGrantType(ctx, request, c.Config) == nil && !isTxnTokenReplacement(ctx, request, c.Config) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The subject token has an '%s' claim so an '%s' is required.", consts.ClaimActor, consts.FormParameterActorToken))
	}

	if requestedTokenType == consts.TokenTypeRFC8693RefreshToken && !allowsRefreshTokenIssuance(request.GetClient()) {
		return errRefreshTokenIssuance()
	}

	if !isTxnTokenRequest(ctx, request, c.Config) {
		if err = consumeTokenJTIs(ctx, c.Config, c.Storage, request, session); err != nil {
			return err
		}
	}

	if act != nil {
		session.SetClaimActor(act)
	}

	return nil
}

func consumeTokenJTIs(ctx context.Context, config oauth2.RFC8693ConfigProvider, store CustomJWTStorage, request oauth2.AccessRequester, session Session) (err error) {
	form := request.GetRequestForm()
	types := config.GetRFC8693TokenTypes(ctx)

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
		if !validatesJTI(types[token.kind]) {
			continue
		}

		if store == nil {
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

	if ctx, err = storage.MaybeBeginTx(ctx, store); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	for _, m := range markers {
		if err = store.SetTokenExchangeCustomJWT(ctx, m.iss, m.jti, m.exp); err != nil {
			if rollback := storage.MaybeRollbackTx(ctx, store); rollback != nil {
				return errorsx.WithStack(oauth2.ErrServerError.WithWrap(rollback).WithDebugError(rollback))
			}

			if errors.Is(err, oauth2.ErrJTIKnown) {
				return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Claim 'jti' from the token must be used only once.").WithWrap(err))
			}

			return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
		}
	}

	if err = storage.MaybeCommitTx(ctx, store); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	return nil
}

func isAcceptedTokenType(tokenType oauth2.RFC8693TokenType) bool {
	if jwtType, ok := tokenType.(*JWTType); ok {
		return jwtType != nil && jwtType.Validate != nil
	}

	return tokenType != nil
}

func validatesJTI(tokenType oauth2.RFC8693TokenType) bool {
	switch t := tokenType.(type) {
	case *JWTType:
		return t != nil && t.Validate != nil && t.Validate.ValidateJTI
	case *SelfSignedTokenType:
		return t != nil && t.ValidateJTI
	default:
		return false
	}
}

// buildActClaim derives the RFC 8693 §4.1 'act' claim for the issued token from the actor_token's 'sub' and
// 'client_id' claims, nesting any 'act' claim the subject_token already carried. It returns nil when no actor_token
// was supplied (impersonation), and an error when the actor_token has neither claim. The input maps are not mutated.
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

// validateActorChainDepth limits the size of an issued token before the chain of the subject token is copied, as RFC
// 8693 Section 4.1 sets no limit on nesting and each exchange adds an actor. A JWT authorization grant without an
// 'actor_token' carries the chain of the subject token.
func validateActorChainDepth(ctx context.Context, config oauth2.RFC8693ConfigProvider, session Session) error {
	limit, depth := config.GetRFC8693MaxActorChainDepth(ctx), 0

	if session.GetActorToken() != nil {
		depth++
	}

	act, _ := session.GetSubjectToken()[consts.ClaimActor].(map[string]any)

	for ; len(act) > 0 && depth <= limit; depth++ {
		act, _ = act[consts.ClaimActor].(map[string]any)
	}

	if depth > limit {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' claim would exceed the permitted %d actors.", consts.ClaimActor, limit))
	}

	return nil
}

// resolveRequestedTokenType returns the oauth2.RFC8693TokenType registered for the request's resolved
// 'requested_token_type' parameter, substituting the configured default when it is absent. Returns nil when the
// requested type is not registered.
func resolveRequestedTokenType(ctx context.Context, request oauth2.Requester, config oauth2.RFC8693ConfigProvider) oauth2.RFC8693TokenType {
	return config.GetRFC8693TokenTypes(ctx)[requestedTokenTypeIdentifier(ctx, request, config)]
}

func requestedTokenTypeIdentifier(ctx context.Context, request oauth2.Requester, config oauth2.RFC8693ConfigProvider) string {
	if id := request.GetRequestForm().Get(consts.FormParameterRequestedTokenType); id != "" {
		return id
	}

	return config.GetDefaultRFC8693RequestedTokenType(ctx)
}

// IsIDJAGRequest returns true when the resolved 'requested_token_type' of the request is an Identity Assertion JWT
// Authorization Grant.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-4.3
func IsIDJAGRequest(ctx context.Context, request oauth2.Requester, config oauth2.RFC8693ConfigProvider) bool {
	return IsIDJAGRequestedTokenType(requestedTokenTypeIdentifier(ctx, request, config))
}

// IsIDJAGRequestedTokenType returns true when the RFC 8693 token type identifier, such as a 'requested_token_type'
// value, is the Identity Assertion JWT Authorization Grant. Unlike oauth2.IsIDJAGTokenType it does not check a JOSE
// 'typ' header.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-4.3
func IsIDJAGRequestedTokenType(identifier string) bool {
	return identifier == consts.TokenTypeRFC8693IDJAG
}

func authorizationGrantType(ctx context.Context, request oauth2.Requester, config oauth2.RFC8693ConfigProvider) *JWTType {
	if jwtType, ok := resolveRequestedTokenType(ctx, request, config).(*JWTType); ok && jwtType != nil && jwtType.Issue != nil && jwtType.Issue.AuthorizationGrant {
		return jwtType
	}

	return nil
}

// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-chaining-17#section-2.3.1
func validateAuthorizationGrantTarget(request oauth2.Requester) error {
	switch targets := oauth2.JoinGrantedAudienceAndResource(request.GetRequestedAudience(), request.GetRequestedResource()); len(targets) {
	case 0:
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("One of '%s' or '%s' is required to identify the intended authorization server of a JWT authorization grant.", consts.FormParameterAudience, consts.FormParameterResource))
	case 1:
		return nil
	default:
		return errorsx.WithStack(oauth2.ErrInvalidTarget.WithHint("A JWT authorization grant may only identify a single authorization server."))
	}
}

func isIDTokenRequest(ctx context.Context, request oauth2.Requester, config oauth2.RFC8693ConfigProvider) bool {
	return requestedTokenTypeIdentifier(ctx, request, config) == consts.TokenTypeRFC8693IDToken
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

func errExchangeTokenLookup(err error) error {
	if errors.Is(err, oauth2.ErrNotFound) || errors.Is(err, oauth2.ErrInactiveToken) || hoauth2.IsTokenRejection(err) {
		return errors.WithStack(oauth2.ErrInvalidRequest.WithHint("Token is not valid or has expired.").WithDebugError(err))
	}

	return errors.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
}

func errExchangeSubjectLookup(err error) error {
	rfc := outermostRFC6749Error(err)

	switch {
	case errors.Is(err, oauth2.ErrUnknownRequest):
		return errors.WithStack(oauth2.ErrServerError.WithDebugError(err))
	case rfc != nil && rfc.CodeField >= http.StatusInternalServerError, rfc == nil && !errors.Is(err, oauth2.ErrNotFound):
		return errors.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	case rfc == nil, rfc.ErrorField == oauth2.ErrNotFound.ErrorField:
		return errors.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' does not identify a subject.", consts.FormParameterSubjectToken).WithWrap(err).WithDebugError(err))
	default:
		return errors.WithStack(rfc)
	}
}

func outermostRFC6749Error(err error) *oauth2.RFC6749Error {
	if custom, ok := err.(interface{ As(target any) bool }); ok { //nolint:errorlint
		var rfc *oauth2.RFC6749Error

		if custom.As(&rfc) && rfc != nil {
			return rfc
		}
	}

	switch e := err.(type) { //nolint:errorlint
	case nil:
		return nil
	case *oauth2.RFC6749Error:
		return e
	case oauth2.RFC6749Error:
		return &e
	case interface{ Unwrap() []error }:
		for _, wrapped := range e.Unwrap() {
			if rfc := outermostRFC6749Error(wrapped); rfc != nil {
				return rfc
			}
		}

		return nil
	case interface{ Unwrap() error }:
		return outermostRFC6749Error(e.Unwrap())
	default:
		return nil
	}
}

func errExchangeTokenValidation(err error) error {
	if !hoauth2.IsTokenRejection(err) {
		return errors.WithStack(err)
	}

	return errors.WithStack(oauth2.ErrInvalidRequest.WithHint("Token is not valid or has expired.").WithDebugError(err))
}

// validateExchangeTokenPolicy applies the client and scope policy for a 'subject_token' or 'actor_token' resolved
// back to the request it was issued for. RFC 8693 Section 2.2.2 mandates 'invalid_request' for a token that is
// unacceptable based on policy.
//
// A refresh token is only accepted from the client it was issued to, as RFC 6749 Section 10.4 requires that binding to
// be verified. A token of another kind issued to another client is only accepted when its audience includes the
// requesting client, and when that client also permits the requesting client with GetTokenExchangePermitted if its
// client type can express a permission. An actor token identifies the acting party, which its audience does not
// establish, so its client must explicitly permit the requesting client as described by ActorTokenExchangeClient.
//
// A client may not exchange an access token issued to itself as a subject token, except for a JWT authorization grant
// or when it opts in with GetAllowOwnAccessTokenExchange. It may also opt in with
// GetRestrictOwnAccessTokenExchangeTargets to only request the audience and resources that access token was granted.
// A client may only request scopes the subject token was granted. Neither rule applies to an actor token, which
// identifies the acting party rather than the authority being exchanged: that party is normally the requesting client
// itself, and the issued token's scopes come from the subject token.
//
// See: https://datatracker.ietf.org/doc/html/rfc8693#section-2.1
// See: https://datatracker.ietf.org/doc/html/rfc8693#section-2.2.2
// See: https://datatracker.ietf.org/doc/html/rfc6749#section-10.4
func validateExchangeTokenPolicy(ctx context.Context, request oauth2.AccessRequester, config oauth2.RFC8693ConfigProvider, store oauth2.ClientGetter, strategy oauth2.ScopeStrategy, original oauth2.Requester, role tokenRole, refresh bool) (err error) {
	client := request.GetClient()
	originalClientID := original.GetClient().GetID()
	self := client.GetID() == originalClientID

	if role == tokenRoleSubject && IsIDJAGRequest(ctx, request, config) {
		if !self {
			return errors.WithStack(oauth2.ErrInvalidRequest.WithHintf("The subject token was not issued to the OAuth 2.0 client requesting a '%s'.", consts.TokenTypeRFC8693IDJAG))
		}

		return nil
	}

	if refresh && !self {
		return errors.WithStack(oauth2.ErrInvalidRequest.WithHintf("The refresh token presented as %s was not issued to the OAuth 2.0 client.", role.hint()))
	}

	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-chaining-17#section-2.1
	if self && role == tokenRoleSubject && !refresh && authorizationGrantType(ctx, request, config) == nil {
		if !allowsOwnAccessTokenExchange(client) {
			return errors.WithStack(oauth2.ErrInvalidRequest.WithHint("Clients are not allowed to perform a token exchange on their own access tokens."))
		}

		if restrictsOwnAccessTokenTargets(client) {
			if err := validateOwnAccessTokenTarget(ctx, request, config, original); err != nil {
				return err
			}
		}
	}

	// A client implicitly authorizes the exchange of its own token.
	if !self {
		if !slices.Contains(oauth2.JoinGrantedAudienceAndResource(original.GetGrantedAudience(), original.GetGrantedResource()), client.GetID()) {
			return errors.WithStack(oauth2.ErrInvalidRequest.WithHintf("The audience of %s does not include the OAuth 2.0 client.", role.hint()))
		}

		if err = validateExchangeOwner(ctx, request, config, store, original.GetClient(), role); err != nil {
			return err
		}
	}

	if role != tokenRoleSubject {
		return nil
	}

	return validateRequestedScopes(request, strategy, original.GetGrantedScopes())
}

func permitsExchange(owner, client oauth2.Client, requested oauth2.RFC8693TokenType, role tokenRole) bool {
	// A client resolved from a Client ID Metadata Document permits only the clients the operator lists for it, and no
	// other client by default.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc8693#section-5
	if jwt.IsClientIDMetadataDocumentClient(owner) {
		listed, ok := owner.(TokenExchangePermittedClientsClient)
		if !ok || !slices.Contains(listed.GetTokenExchangePermittedClientIDs(), client.GetID()) {
			return false
		}
	}

	if role == tokenRoleActor {
		if c, ok := owner.(ActorTokenExchangeClient); ok {
			return c.GetActorTokenExchangePermitted(client, requested)
		}
	}

	c, ok := owner.(Client)
	if !ok {
		return role != tokenRoleActor
	}

	return c.GetTokenExchangePermitted(client, requested)
}

func validateOwnAccessTokenTarget(ctx context.Context, request oauth2.AccessRequester, config oauth2.RFC8693ConfigProvider, original oauth2.Requester) (err error) {
	client := request.GetClient()

	if err = oauth2.GetAudienceStrategy(ctx, config, client)(original.GetGrantedAudience(), request.GetRequestedAudience()); err != nil {
		return errors.WithStack(oauth2.ErrInvalidTarget.WithDebugError(err).WithWrap(err))
	}

	if err = oauth2.GetResourceStrategy(ctx, config, client)(original.GetGrantedResource(), request.GetRequestedResource()); err != nil {
		return errors.WithStack(oauth2.ErrInvalidTarget.WithDebugError(err).WithWrap(err))
	}

	return nil
}

func restrictsOwnAccessTokenTargets(client oauth2.Client) bool {
	c, ok := client.(OwnAccessTokenExchangeTargetClient)

	return ok && c.GetRestrictOwnAccessTokenExchangeTargets()
}

func allowsOwnAccessTokenExchange(client oauth2.Client) bool {
	c, ok := client.(OwnAccessTokenExchangeClient)

	return ok && c.GetAllowOwnAccessTokenExchange()
}

func allowsRefreshTokenIssuance(client oauth2.Client) bool {
	c, ok := client.(RefreshTokenIssuanceClient)

	return ok && c.GetAllowTokenExchangeRefreshToken()
}

func rotatesSubjectRefreshToken(ctx context.Context, config oauth2.RFC8693ConfigProvider, request oauth2.Requester) bool {
	if c, ok := request.GetClient().(RefreshTokenRotationOverrideClient); ok && c.GetOverrideTokenExchangeRefreshTokenRotation() {
		return c.GetTokenExchangeRefreshTokenRotation()
	}

	provider, _ := config.(oauth2.DisableRefreshTokenRotationProvider)

	return !oauth2.IsRefreshTokenRotationDisabledForRequest(ctx, provider, request)
}

func beginSubjectRefreshTokenRotation(ctx context.Context, strategy hoauth2.RefreshTokenStrategy, store hoauth2.TokenRevocationStorage, request oauth2.AccessRequester) (signature string, err error) {
	if store == nil {
		return "", errors.WithStack(oauth2.ErrServerError.WithDebug("The refresh token 'subject_token' must be rotated but the handler has no TokenRevocationStorage."))
	}

	signature = strategy.RefreshTokenSignature(ctx, request.GetRequestForm().Get(consts.FormParameterSubjectToken))

	var original oauth2.Requester

	switch original, err = store.GetRefreshTokenSession(ctx, signature, nil); {
	case err == nil:
		request.SetID(original.GetID())

		return signature, nil
	case errors.Is(err, oauth2.ErrInactiveToken) && original != nil:
		request.SetID(original.GetID())

		return "", errSubjectRefreshTokenReplay(ctx, store, signature, request, err)
	case errors.Is(err, oauth2.ErrNotFound), errors.Is(err, oauth2.ErrInactiveToken):
		return "", errors.WithStack(oauth2.ErrInvalidRequest.WithHint("Token is not valid or has expired.").WithDebugError(err))
	default:
		return "", errors.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}
}

func commitSubjectRefreshTokenRotation(ctx context.Context, store hoauth2.TokenRevocationStorage, request oauth2.AccessRequester, signature string, create func(ctx context.Context) error) (err error) {
	parent := ctx

	if ctx, err = storage.MaybeBeginTx(ctx, store); err != nil {
		return errors.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	if err = store.RotateRefreshToken(ctx, request.GetID(), signature); err == nil {
		if err = create(ctx); err == nil {
			err = storage.MaybeCommitTx(ctx, store)
		}
	}

	if err == nil {
		return nil
	}

	if rollback := storage.MaybeRollbackTx(ctx, store); rollback != nil {
		return errRollback(err, rollback)
	}

	// oauth2.ErrSerializationFailure does not show the refresh token was replayed, as a store may also return it for lock
	// contention, so the refresh token is read again now the transaction has rolled back.
	if errors.Is(err, oauth2.ErrSerializationFailure) {
		if _, e := store.GetRefreshTokenSession(parent, signature, nil); errors.Is(e, oauth2.ErrInactiveToken) {
			return errSubjectRefreshTokenReplay(parent, store, signature, request, e)
		}
	}

	var rfc *oauth2.RFC6749Error

	switch {
	case errors.Is(err, oauth2.ErrInactiveToken):
		return errSubjectRefreshTokenReplay(parent, store, signature, request, err)
	case errors.Is(err, oauth2.ErrNotFound), errors.Is(err, oauth2.ErrSerializationFailure):
		return errors.WithStack(oauth2.ErrInvalidRequest.WithHint("Failed to exchange the refresh token because of multiple concurrent requests using the same token which is not allowed.").WithDebugError(err))
	case errors.As(err, &rfc):
		return errors.WithStack(err)
	default:
		return errors.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}
}

func createInTransaction(ctx context.Context, store any, create func(ctx context.Context) error) (err error) {
	if ctx, err = storage.MaybeBeginTx(ctx, store); err != nil {
		return errors.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	if err = create(ctx); err == nil {
		err = storage.MaybeCommitTx(ctx, store)
	}

	if err == nil {
		return nil
	}

	if rollback := storage.MaybeRollbackTx(ctx, store); rollback != nil {
		return errRollback(err, rollback)
	}

	var rfc *oauth2.RFC6749Error

	if errors.As(err, &rfc) {
		return errors.WithStack(err)
	}

	return errors.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
}

func errRollback(err, rollback error) error {
	cause := err.Error()

	var rfc *oauth2.RFC6749Error

	if errors.As(err, &rfc) && rfc.DebugField != "" {
		cause = rfc.DebugField
	}

	return errors.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugf("error: %s; rollback error: %s", cause, rollback))
}

func errSubjectRefreshTokenReplay(ctx context.Context, store hoauth2.TokenRevocationStorage, signature string, request oauth2.Requester, replay error) (err error) {
	if err = hoauth2.RevokeRefreshTokenFamily(ctx, store, signature, request); err != nil {
		return errors.WithStack(err)
	}

	return errors.WithStack(oauth2.ErrInvalidRequest.WithHint("Token is not valid or has expired.").WithWrap(replay).WithDebugError(replay))
}

func allowsAuthorizationGrantIssuance(client oauth2.Client) bool {
	c, ok := client.(AuthorizationGrantIssuanceClient)

	return ok && c.GetAllowTokenExchangeAuthorizationGrant()
}

func errRefreshTokenIssuance() error {
	return errors.WithStack(oauth2.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not permitted to be issued a refresh token via token exchange."))
}

func validateExchangeOwner(ctx context.Context, request oauth2.AccessRequester, config oauth2.RFC8693ConfigProvider, store oauth2.ClientGetter, original oauth2.Client, role tokenRole) (err error) {
	var owner oauth2.Client

	if owner, err = exchangeOwner(ctx, config, store, original); err != nil {
		return err
	}

	if !permitsExchange(owner, request.GetClient(), resolveRequestedTokenType(ctx, request, config), role) {
		return errors.WithStack(oauth2.ErrInvalidRequest.WithHintf("The OAuth 2.0 client is not permitted to exchange %s issued to client %s", role.hint(), original.GetID()))
	}

	return nil
}

// exchangeOwner returns the client a token was issued to. A client which is not marked as resolved from a Client ID
// Metadata Document, but has a Client Identifier URL as its identifier while the feature is enabled, may be a document
// client a store rebuilt without oauth2.GetClient, so it is resolved again by oauth2.GetClient, where a registered
// client takes precedence.
func exchangeOwner(ctx context.Context, config any, store oauth2.ClientGetter, original oauth2.Client) (owner oauth2.Client, err error) {
	if store == nil || jwt.IsClientIDMetadataDocumentClient(original) || !oauth2.IsClientIdentifierURL(original.GetID()) {
		return original, nil
	}

	if provider, ok := config.(oauth2.ClientIDMetadataDocumentConfigProvider); !ok || provider.GetClientIDMetadataDocumentResolver(ctx) == nil {
		return original, nil
	}

	if owner, err = oauth2.GetClient(ctx, config, store, original.GetID()); err == nil {
		return owner, nil
	}

	if errors.Is(err, oauth2.ErrTemporarilyUnavailable) {
		return nil, err
	}

	return nil, errors.WithStack(oauth2.ErrInvalidRequest.WithHintf("The OAuth 2.0 client %s the token was issued to could not be resolved.", original.GetID()).WithWrap(err).WithDebugError(err))
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

// GrantTypesSupported returns the grant types this handler serves.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
func (c *TokenExchangeGrantHandler) GrantTypesSupported(ctx context.Context) (types []string) {
	return []string{consts.GrantTypeOAuthTokenExchange}
}

// CodeChallengeMethodsSupported returns nil because the handler does not enforce PKCE.
//
// See: https://datatracker.ietf.org/doc/html/rfc7636#section-4.3
func (c *TokenExchangeGrantHandler) CodeChallengeMethodsSupported(ctx context.Context) (methods []string) {
	return nil
}

// IDTokenSigningAlgValuesSupported returns nil because the handler does not issue ID Tokens.
//
// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
func (c *TokenExchangeGrantHandler) IDTokenSigningAlgValuesSupported(ctx context.Context) (algs []string) {
	return nil
}

// RFC8693TokenTypesSupported returns nil because the token types are reported by the handlers which issue them.
//
// See: https://datatracker.ietf.org/doc/html/rfc8693#section-3
func (c *TokenExchangeGrantHandler) RFC8693TokenTypesSupported(ctx context.Context) (types []string) {
	return nil
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
			return &storedTokenSession{Session: s}
		}
	}

	return session.Clone()
}

type storedTokenSession struct {
	oauth2.Session
}

func (s *storedTokenSession) UnmarshalJSON(data []byte) (err error) {
	if err = json.Unmarshal(data, s.Session); err != nil {
		return err
	}

	var stored struct {
		ExpiresAt                   map[oauth2.TokenType]time.Time `json:"ExpiresAt"`
		JWKThumbprint               string                         `json:"JWKThumbprint"`
		ClientCertificateThumbprint string                         `json:"ClientCertificateThumbprint"`
	}

	if err = json.Unmarshal(data, &stored); err != nil {
		return err
	}

	for key, expires := range stored.ExpiresAt {
		s.SetExpiresAt(key, expires)
	}

	if bound, ok := s.Session.(oauth2.DPoPBoundSession); ok && stored.JWKThumbprint != "" {
		bound.SetDPoPJWKThumbprint(stored.JWKThumbprint)
	}

	if bound, ok := s.Session.(oauth2.MTLSBoundSession); ok && stored.ClientCertificateThumbprint != "" {
		bound.SetClientCertificateSHA256Thumbprint(stored.ClientCertificateThumbprint)
	}

	return nil
}

func restoreTokenSession(request oauth2.Requester) {
	if request == nil {
		return
	}

	if stored, ok := request.GetSession().(*storedTokenSession); ok {
		request.SetSession(stored.Session)
	}
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

// carryIDTokenSubject records the End-User on the ID Token claims of the exchange when the claims grant the 'openid'
// scope, as the refresh token it issues refreshes an ID Token from these.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse
func carryIDTokenSubject(session any, claims map[string]any) {
	scopes, _ := claims[consts.ClaimScope].(oauth2.Arguments)
	if !scopes.Has(consts.ScopeOpenID) {
		return
	}

	if target, ok := session.(openid.Session); ok {
		target.IDTokenClaims().Subject = target.GetSubject()
	}
}

// carryAuthenticationContext replaces the 'auth_time', 'acr' and 'amr' claims of the session with those of the subject
// token authentication, clearing them when login is nil. OpenID Connect Core 1.0 Section 12.2 requires the 'auth_time'
// claim of a refreshed ID Token to be the original one.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse and
// https://datatracker.ietf.org/doc/html/rfc9068#section-2.2.1
func carryAuthenticationContext(session any, login *jwt.IDTokenClaims) {
	target, ok := session.(openid.Session)
	if !ok {
		return
	}

	var (
		authTime *jwt.NumericDate
		acr      string
		amr      []string
	)

	if login != nil {
		if login.AuthTime != nil {
			authTime = jwt.NewNumericDate(login.AuthTime.Time)
		}

		acr, amr = login.AuthenticationContextClassReference, slices.Clone(login.AuthenticationMethodsReferences)
	}

	issued := target.IDTokenClaims()

	issued.AuthTime, issued.AuthenticationContextClassReference, issued.AuthenticationMethodsReferences = authTime, acr, amr
}

// sessionAuthentication returns the ID Token claims recording the authentication of the session, or nil when it has none.
func sessionAuthentication(session oauth2.Session) (login *jwt.IDTokenClaims) {
	if s, ok := session.(interface{ IDTokenClaims() *jwt.IDTokenClaims }); ok {
		return s.IDTokenClaims()
	}

	return nil
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

func validateBindingVerifiable(ctx context.Context, config any, binding tokenBinding, role tokenRole) (err error) {
	provider, _ := config.(oauth2.ConfirmationConfigProvider)

	if binding.jkt != "" && (provider == nil || !provider.GetDPoPEnabled(ctx)) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("Unable to exchange %s bound to a DPoP key because DPoP is not enabled.", role.hint()))
	}

	if binding.x5t != "" && (provider == nil || !provider.GetMTLSEnabled(ctx)) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("Unable to exchange %s bound to a client certificate because mutual-TLS is not enabled.", role.hint()))
	}

	return nil
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

func inheritTokenBinding(ctx context.Context, config any, request oauth2.AccessRequester, incoming tokenBinding, role tokenRole, prior tokenBinding) (err error) {
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

	// The binding phase verifies a binding only for an enabled method, so a binding of a disabled method could not be
	// proven. Section 2.2.2 mandates 'invalid_request' for a token that is unacceptable based on policy.
	if err = validateBindingVerifiable(ctx, config, incoming, role); err != nil {
		return err
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
		WithDebugf("The '%s' value '%s' is registered in the token types configuration but no token type handler validated a subject token for it, so the '%s' was never read. A registered type must be claimed by one of the token type handlers, being one of the three built-in types, a '*rfc8693.JWTType', or on a request for a Transaction Token a '*rfc8693.SelfSignedTokenType' or '*rfc8693.UnsignedJSONTokenType'.", consts.FormParameterSubjectTokenType, subjectTokenType, consts.FormParameterSubjectToken))
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
	// The comparison is of seconds, as a time.Time beyond its range compares as earlier than any other.
	if limit := subjectTokenExpiry(request); !limit.IsZero() && limit.Unix() <= expires.Unix() {
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

// IssuableTokenTypes returns the sorted identifiers of the configured token types which pass IsIssuable and which
// issues reports the handler issues, or nil when config is nil. A handler which issues a token type reports it with
// this function so the advertised types match those it issues.
//
// See: https://datatracker.ietf.org/doc/html/rfc8693#section-3
func IssuableTokenTypes(ctx context.Context, config oauth2.RFC8693ConfigProvider, issues func(identifier string, tokenType oauth2.RFC8693TokenType) bool) (types []string) {
	if config == nil {
		return nil
	}

	for identifier, t := range config.GetRFC8693TokenTypes(ctx) {
		if IsIssuable(t) && issues(identifier, t) {
			types = append(types, identifier)
		}
	}

	slices.Sort(types)

	return types
}

// IsIssuable reports whether a token type can be requested as the 'requested_token_type'. A nil type, a nil
// *DefaultTokenType, a *SelfSignedTokenType, a *UnsignedJSONTokenType and a *JWTType without an issue configuration
// cannot.
//
// See: https://datatracker.ietf.org/doc/html/rfc8693#section-2.1
func IsIssuable(t oauth2.RFC8693TokenType) bool {
	switch tokenType := t.(type) {
	case nil, *SelfSignedTokenType, *UnsignedJSONTokenType:
		return false
	case *DefaultTokenType:
		return tokenType != nil
	case *JWTType:
		return tokenType != nil && tokenType.Issue != nil
	}

	return true
}

var _ oauth2.TokenEndpointHandler = (*TokenExchangeGrantHandler)(nil)
