// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"context"
	"reflect"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

type ActorTokenValidationHandler struct{}

// HandleTokenEndpointRequest enforces RFC 8693 §4.4 'may_act' authorization for delegation requests.
//
// The validation matrix:
//
//   - No actor_token and no may_act → impersonation; nothing to validate at this layer.
//   - may_act present (with or without actor_token) → the actor (or the client itself, when no actor_token is
//     supplied) MUST match every constraint in may_act.
//   - actor_token present but no may_act → the subject token carries no in-token authorization for delegation.
//     The request is rejected with invalid_grant unless the client implements ActorTokenPolicyClient and opts
//     into externally-gated authorization via GetAllowActorTokenWithoutMayAct.
//
// See https://datatracker.ietf.org/doc/html/rfc8693#section-4.4.
func (c *ActorTokenValidationHandler) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	client := request.GetClient()

	var (
		session Session
		ok      bool
	)

	if session, ok = request.GetSession().(Session); !ok || session == nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to perform token exchange because the session is not of the right type."))
	}

	subjectTokenObject := session.GetSubjectToken()
	actorTokenObject := session.GetActorToken()

	mayAct, _ := subjectTokenObject[consts.ClaimAuthorizedActor].(map[string]any)

	switch {
	case actorTokenObject == nil && mayAct == nil:
		// Impersonation. No authorization check required at this layer.
		return nil
	case mayAct != nil:
		// may_act constraint present. Build a virtual actor from the authenticated client when no actor_token was
		// supplied, then enforce that the actor satisfies every may_act member.
		actor := actorTokenObject
		if actor == nil {
			actor = map[string]any{
				consts.ClaimSubject:          client.GetID(),
				consts.ClaimClientIdentifier: client.GetID(),
			}
		}

		for k, v := range mayAct {
			// reflect.DeepEqual handles non-comparable dynamic types (slices, maps, nested objects) which
			// interface == would panic on per Go spec; may_act values are not constrained to scalars.
			if !reflect.DeepEqual(actor[k], v) {
				return errors.WithStack(oauth2.ErrInvalidGrant.WithHint("The actor or client is not authorized to act on behalf of the subject."))
			}
		}

		return nil
	default:
		// actor_token supplied without may_act on the subject token. Reject unless the client has explicitly opted
		// into externally-gated authorization.
		var policy ActorTokenPolicyClient

		if policy, ok = client.(ActorTokenPolicyClient); ok && policy.GetAllowActorTokenWithoutMayAct() {
			return nil
		}

		return errors.WithStack(oauth2.ErrInvalidGrant.
			WithHint("The subject token does not authorize delegation: no 'may_act' claim is present.").
			WithDebug("The OAuth 2.0 client supplied an 'actor_token' but the subject token does not contain a 'may_act' claim authorizing the actor to act on behalf of the subject. Either set the 'may_act' claim on the subject token, or configure the client to use an out-of-band authorization policy by implementing the ActorTokenPolicyClient interface."))
	}
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-4.3.3
func (c *ActorTokenValidationHandler) PopulateTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
	return nil
}

// CanSkipClientAuth indicates if client auth can be skipped
func (c *ActorTokenValidationHandler) CanSkipClientAuth(ctx context.Context, request oauth2.AccessRequester) bool {
	return false
}

// CanHandleTokenEndpointRequest indicates if the token endpoint request can be handled
func (c *ActorTokenValidationHandler) CanHandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) bool {
	// The parameter 'grant_type' is REQUIRED. Value MUST be set to "urn:ietf:params:oauth:grant-type:token-exchange".
	return request.GetGrantTypes().ExactOne(consts.GrantTypeOAuthTokenExchange)
}
