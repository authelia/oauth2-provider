package rfc8693

import (
	"context"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/errorsx"
)

type ActorTokenValidationHandler struct{}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.3.2
func (c *ActorTokenValidationHandler) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	client := request.GetClient()
	session, _ := request.GetSession().(Session)
	if session == nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to perform token exchange because the session is not of the right type."))
	}

	// Validate that the actor or client is allowed to make this request
	subjectTokenObject := session.GetSubjectToken()
	if mayAct, _ := subjectTokenObject[consts.ClaimAuthorizedActor].(map[string]any); mayAct != nil {
		actorTokenObject := session.GetActorToken()
		if actorTokenObject == nil {
			actorTokenObject = map[string]any{
				consts.ClaimSubject:          client.GetID(),
				consts.ClaimClientIdentifier: client.GetID(),
			}
		}

		for k, v := range mayAct {
			if actorTokenObject[k] != v {
				return errors.WithStack(oauth2.ErrInvalidRequest.WithHint("The actor or client is not authorized to act on behalf of the subject."))
			}
		}
	}

	return nil
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-4.3.3
func (c *ActorTokenValidationHandler) PopulateTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, responder oauth2.AccessResponder) error {
	return nil
}

// CanSkipClientAuth indicates if client auth can be skipped
func (c *ActorTokenValidationHandler) CanSkipClientAuth(ctx context.Context, requester oauth2.AccessRequester) bool {
	return false
}

// CanHandleTokenEndpointRequest indicates if the token endpoint request can be handled
func (c *ActorTokenValidationHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester oauth2.AccessRequester) bool {
	// grant_type REQUIRED.
	// Value MUST be set to "password".
	return requester.GetGrantTypes().ExactOne(consts.GrantTypeOAuthTokenExchange)
}
