// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"context"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// TokenExchangeGrantHandler is the grant handler for RFC8693
type TokenExchangeGrantHandler struct {
	Config oauth2.RFC8693ConfigProvider

	ScopeStrategy    oauth2.ScopeStrategy
	AudienceStrategy oauth2.AudienceStrategy
	ResourceStrategy oauth2.ResourceStrategy
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

	return oauth2.DefaultResourceStrategy
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

	if act := buildActClaim(session); act != nil {
		session.SetClaimActor(act)
	}

	return nil
}

// buildActClaim derives the RFC 8693 §4.1 'act' claim for the issued token from the session populated by the upstream
// token-type handlers. It returns nil when no actor_token was supplied (i.e. impersonation, where no 'act' claim is
// required).
//
// The actor's identity is taken from the actor_token's identifying claims ('sub' and, when present, 'client_id'). If
// the subject_token already carried an 'act' claim, that prior actor is nested under the new 'act' to express the
// chain of delegation per §4.1: "the outermost act claim represents the current actor while nested act claims
// represent prior actors".
//
// The function does not mutate any of the input maps; the returned map is a fresh allocation safe for the caller to
// store on the session.
func buildActClaim(session Session) map[string]any {
	actorToken := session.GetActorToken()
	if actorToken == nil {
		return nil
	}

	act := map[string]any{}

	if sub, ok := actorToken[consts.ClaimSubject].(string); ok && sub != "" {
		act[consts.ClaimSubject] = sub
	}

	if clientID, ok := actorToken[consts.ClaimClientIdentifier].(string); ok && clientID != "" {
		act[consts.ClaimClientIdentifier] = clientID
	}

	subjectToken := session.GetSubjectToken()
	if subjectToken != nil {
		if existing, ok := subjectToken[consts.ClaimActor].(map[string]any); ok && len(existing) > 0 {
			act[consts.ClaimActor] = copyClaimMap(existing)
		}
	}

	if len(act) == 0 {
		return nil
	}

	return act
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

	for _, scope := range request.GetRequestedScopes() {
		if !strategy(original.GetGrantedScopes(), scope) {
			return errors.WithStack(oauth2.ErrInvalidScope.WithHintf("The subject token is not granted '%s' and so this scope cannot be requested.", scope))
		}
	}

	return nil
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

// bindingOfConfirmation reads the proof-of-possession binding a stateless presented token asserts in its own RFC 7800
// 'cnf' claim.
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

// clearInheritedKeyBinding removes the OpenID Connect Key Binding state a restored token session may have deposited on
// the exchange request's session.
func clearInheritedKeyBinding(session oauth2.Session) {
	bound, ok := session.(oauth2.DPoPBoundSession)
	if !ok {
		return
	}

	bound.SetOIDCKeyBindingGranted(false)
	bound.SetDPoPPublicKeyJWK(nil)
	bound.SetRequestedDPoPJWKThumbprint("")
}

// inheritTokenBinding carries a subject or actor token's proof-of-possession binding onto the exchange request, so the
// issued token inherits the sender constraint rather than silently shedding it.
//
// It records the binding only. Enforcement is left to the token endpoint binding phase, which already implements it:
// both rfc9449.Handler and rfc8705.Handler treat a binding recorded on the session as making the corresponding proof
// or certificate mandatory, reject one that does not match, and record the presented key onto the issued token. That
// phase runs after every handler that calls this one, so recording here is enough.
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
