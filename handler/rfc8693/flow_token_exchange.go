package rfc8693

import (
	"context"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/errorsx"
)

// TokenExchangeGrantHandler is the grant handler for RFC8693
type TokenExchangeGrantHandler struct {
	Config                   oauth2.RFC8693ConfigProvider
	ScopeStrategy            oauth2.ScopeStrategy
	AudienceMatchingStrategy oauth2.AudienceMatchingStrategy
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.3.2
func (c *TokenExchangeGrantHandler) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	client := request.GetClient()
	if client.IsPublic() {
		return errors.WithStack(oauth2.ErrInvalidGrant.WithHint("The OAuth 2.0 Client is marked as public and is thus not allowed to use authorization grant \"urn:ietf:params:oauth:grant-type:token-exchange\"."))
	}

	// Check whether client is allowed to use token exchange
	if !client.GetGrantTypes().Has("urn:ietf:params:oauth:grant-type:token-exchange") {
		return errors.WithStack(oauth2.ErrUnauthorizedClient.WithHintf(
			"The OAuth 2.0 Client is not allowed to use authorization grant '%s'.", "urn:ietf:params:oauth:grant-type:token-exchange"))
	}

	session, _ := request.GetSession().(Session)
	if session == nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to perform token exchange because the session is not of the right type."))
	}

	form := request.GetRequestForm()
	configTypesSupported := c.Config.GetTokenTypes(ctx)
	var supportedSubjectTypes, supportedActorTypes, supportedRequestTypes oauth2.Arguments
	if teClient, ok := client.(Client); ok {
		supportedRequestTypes = teClient.GetSupportedRequestTokenTypes()
		supportedActorTypes = teClient.GetSupportedActorTokenTypes()
		supportedSubjectTypes = teClient.GetSupportedSubjectTokenTypes()
	}

	// From https://tools.ietf.org/html/rfc8693#section-2.1:
	//
	//	subject_token
	//		REQUIRED.  A security token that represents the identity of the
	//		party on behalf of whom the request is being made.  Typically, the
	//		subject of this token will be the subject of the security token
	//		issued in response to the request.
	subjectToken := form.Get(consts.FormParameterSubjectToken)
	if subjectToken == "" {
		return errors.WithStack(oauth2.ErrInvalidRequest.WithHintf("Mandatory parameter '%s' is missing.", "subject_token"))
	}

	// From https://tools.ietf.org/html/rfc8693#section-2.1:
	//
	//	subject_token_type
	//		REQUIRED.  An identifier, as described in Section 3, that
	//		indicates the type of the security token in the "subject_token"
	//		parameter.
	subjectTokenType := form.Get(consts.FormParameterSubjectTokenType)
	if subjectTokenType == "" {
		return errors.WithStack(oauth2.ErrInvalidRequest.WithHintf("Mandatory parameter '%s' is missing.", consts.FormParameterSubjectTokenType))
	}

	if tt := configTypesSupported[subjectTokenType]; tt == nil {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' token type is not supported as a '%s'.", subjectTokenType, consts.FormParameterSubjectTokenType))
	}

	if len(supportedSubjectTypes) > 0 && !supportedSubjectTypes.Has(subjectTokenType) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf(
			"The OAuth 2.0 client is not allowed to use '%s' as '%s'.", subjectTokenType, consts.FormParameterSubjectTokenType))
	}

	// From https://tools.ietf.org/html/rfc8693#section-2.1:
	//
	//	actor_token
	//		OPTIONAL . A security token that represents the identity of the acting party.
	//		Typically, this will be the party that is authorized to use the requested security
	//		token and act on behalf of the subject.
	actorToken := form.Get(consts.FormParameterActorToken)
	actorTokenType := form.Get(consts.FormParameterActorTokenType)
	if actorToken != "" {
		// From https://tools.ietf.org/html/rfc8693#section-2.1:
		//
		//	actor_token_type
		//		An identifier, as described in Section 3, that indicates the type of the security token
		//		in the actor_token parameter. This is REQUIRED when the actor_token parameter is present
		//		in the request but MUST NOT be included otherwise.
		if actorTokenType == "" {
			return errors.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' is empty even though the '%s' is not empty.", consts.FormParameterActorTokenType, consts.FormParameterActorToken))
		}

		if tt := configTypesSupported[actorTokenType]; tt == nil {
			return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf(
				"The '%s' token type is not supported as a '%s'.", actorTokenType, consts.FormParameterActorTokenType))
		}

		if len(supportedActorTypes) > 0 && !supportedActorTypes.Has(actorTokenType) {
			return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf(
				"The OAuth 2.0 client is not allowed to use '%s' as '%s'.", actorTokenType, consts.FormParameterActorTokenType))
		}
	} else if actorTokenType != "" {
		return errors.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' is not empty even though the '%s' is empty.", consts.FormParameterActorTokenType, consts.FormParameterActorToken))
	}

	// check if supported
	requestedTokenType := form.Get(consts.FormParameterRequestedTokenType)
	if requestedTokenType == "" {
		requestedTokenType = c.Config.GetDefaultRequestedTokenType(ctx)
	}

	if tt := configTypesSupported[requestedTokenType]; tt == nil {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf(
			"The '%s' token type is not supported as a '%s'.", requestedTokenType, consts.FormParameterRequestedTokenType))
	}

	if len(supportedRequestTypes) > 0 && !supportedRequestTypes.Has(requestedTokenType) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The OAuth 2.0 client is not allowed to use '%s' as '%s'.", requestedTokenType, consts.FormParameterRequestedTokenType))
	}

	// Check scope
	for _, scope := range request.GetRequestedScopes() {
		if !c.ScopeStrategy(client.GetScopes(), scope) {
			return errors.WithStack(oauth2.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
	}

	// Check audience
	if err := c.AudienceMatchingStrategy(client.GetAudience(), request.GetRequestedAudience()); err != nil {
		// TODO: Need to convert to using invalid_target
		return err
	}

	return nil
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-4.3.3
func (c *TokenExchangeGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, responder oauth2.AccessResponder) error {
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
		requestedTokenType = c.Config.GetDefaultRequestedTokenType(ctx)
	}

	configTypesSupported := c.Config.GetTokenTypes(ctx)
	if tt := configTypesSupported[requestedTokenType]; tt == nil {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf(
			"The '%s' token type is not supported as a '%s'.", requestedTokenType, consts.FormParameterRequestedTokenType))
	}

	// chain `act` if necessary
	subjectTokenObject := session.GetSubjectToken()
	if mayAct, _ := subjectTokenObject[consts.ClaimAuthorizedActor].(map[string]any); mayAct != nil {
		if subjectActor, _ := subjectTokenObject[consts.ClaimActor].(map[string]any); subjectActor != nil {
			mayAct[consts.ClaimActor] = subjectActor
		}

		session.SetAct(mayAct)
	}

	return nil
}

// CanSkipClientAuth indicates if client auth can be skipped
func (c *TokenExchangeGrantHandler) CanSkipClientAuth(ctx context.Context, requester oauth2.AccessRequester) bool {
	return false
}

// CanHandleTokenEndpointRequest indicates if the token endpoint request can be handled
func (c *TokenExchangeGrantHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester oauth2.AccessRequester) bool {
	// grant_type REQUIRED.
	return requester.GetGrantTypes().ExactOne(consts.GrantTypeOAuthTokenExchange)
}
