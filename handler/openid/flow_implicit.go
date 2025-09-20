// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

type OpenIDConnectImplicitHandler struct {
	*IDTokenHandleHelper

	AuthorizeImplicitGrantTypeHandler *hoauth2.AuthorizeImplicitGrantTypeHandler
	OpenIDConnectRequestValidator     *OpenIDConnectRequestValidator
	RS256JWTStrategy                  *jwt.DefaultStrategy

	Config interface {
		oauth2.IDTokenLifespanProvider
		oauth2.MinParameterEntropyProvider
		oauth2.ScopeStrategyProvider
	}
}

var (
	_ oauth2.AuthorizeEndpointHandler = (*OpenIDConnectImplicitHandler)(nil)
)

// HandleAuthorizeEndpointRequest implements oauth2.AuthorizeEndpointHandler.
//
// TODO: Refactor time permitting.
//
//nolint:gocyclo
func (c *OpenIDConnectImplicitHandler) HandleAuthorizeEndpointRequest(ctx context.Context, requester oauth2.AuthorizeRequester, responder oauth2.AuthorizeResponder) (err error) {
	if !(requester.GetGrantedScopes().Has(consts.ScopeOpenID) && (requester.GetResponseTypes().Has(consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeImplicitFlowIDToken) || requester.GetResponseTypes().ExactOne(consts.ResponseTypeImplicitFlowIDToken))) {
		return nil
	} else if requester.GetResponseTypes().Has(consts.ResponseTypeAuthorizationCodeFlow) {
		// hybrid flow
		return nil
	}

	requester.SetDefaultResponseMode(oauth2.ResponseModeFragment)

	if !requester.GetClient().GetGrantTypes().Has(consts.GrantTypeImplicit) {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The OAuth 2.0 Client is not allowed to use the authorization grant 'implicit'."))
	}

	if err = c.OpenIDConnectRequestValidator.ValidateRedirectURIs(ctx, requester); err != nil {
		return err
	}

	var session Session

	if session, err = c.OpenIDConnectRequestValidator.ValidatePrompt(ctx, requester); err != nil {
		return err
	}

	if nonce := requester.GetRequestForm().Get(consts.FormParameterNonce); len(nonce) == 0 {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Parameter 'nonce' must be set when using the OpenID Connect Implicit Flow."))
	} else if len(nonce) < c.Config.GetMinParameterEntropy(ctx) {
		return errorsx.WithStack(oauth2.ErrInsufficientEntropy.WithHintf("Parameter 'nonce' is set but does not satisfy the minimum entropy of %d characters.", c.Config.GetMinParameterEntropy(ctx)))
	}

	client := requester.GetClient()
	for _, scope := range requester.GetRequestedScopes() {
		if !c.Config.GetScopeStrategy(ctx)(client.GetScopes(), scope) {
			return errorsx.WithStack(oauth2.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
	}

	claims := session.IDTokenClaims()
	if requester.GetResponseTypes().Has(consts.ResponseTypeImplicitFlowToken) {
		if err = c.AuthorizeImplicitGrantTypeHandler.IssueImplicitAccessToken(ctx, requester, responder); err != nil {
			return errorsx.WithStack(err)
		}

		requester.SetResponseTypeHandled(consts.ResponseTypeImplicitFlowToken)

		var hash string

		if hash, err = c.ComputeHash(ctx, session, responder.GetParameters().Get(consts.AccessResponseAccessToken)); err != nil {
			return err
		}

		claims.AccessTokenHash = hash
	} else {
		responder.AddParameter(consts.FormParameterState, requester.GetState())
	}

	lifespan := oauth2.GetEffectiveLifespan(requester.GetClient(), oauth2.GrantTypeImplicit, oauth2.IDToken, c.Config.GetIDTokenLifespan(ctx))

	if err = c.IssueImplicitIDToken(ctx, lifespan, requester, responder); err != nil {
		return errorsx.WithStack(err)
	}

	requester.SetResponseTypeHandled(consts.ResponseTypeImplicitFlowIDToken)

	// There is no need to check for https, because implicit flow does not require https,
	// See: https://datatracker.ietf.org/doc/html/rfc6819#section-4.4.2
	return nil
}
