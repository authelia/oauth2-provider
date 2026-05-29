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

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-4.3.3
func (c *TokenExchangeGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) error {
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

	// chain `act` if necessary
	subjectTokenObject := session.GetSubjectToken()
	if mayAct, _ := subjectTokenObject[consts.ClaimAuthorizedActor].(map[string]any); mayAct != nil {
		if subjectActor, _ := subjectTokenObject[consts.ClaimActor].(map[string]any); subjectActor != nil {
			mayAct[consts.ClaimActor] = subjectActor
		}

		session.SetClaimActor(mayAct)
	}

	return nil
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
