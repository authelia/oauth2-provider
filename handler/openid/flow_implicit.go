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
func (c *OpenIDConnectImplicitHandler) HandleAuthorizeEndpointRequest(ctx context.Context, requester oauth2.AuthorizeRequester, responder oauth2.AuthorizeResponder) error {
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

	// There is no need to check response types here as this is validated in the oauth2.AuthorizeRequestHandler.

	// This ensures that the 'redirect_uri' parameter is present for OpenID Connect 1.0 authorization requests as per:
	//
	// Authorization Code Flow - https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
	// Implicit Flow - https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthRequest
	// Hybrid Flow - https://openid.net/specs/openid-connect-core-1_0.html#HybridAuthRequest
	//
	// Note: as per the Hybrid Flow documentation the Hybrid Flow has the same requirements as the Authorization Code Flow.
	if len(requester.GetRequestForm().Get(consts.FormParameterRedirectURI)) == 0 {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The 'redirect_uri' parameter is required when using OpenID Connect 1.0."))
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

	session, ok := requester.GetSession().(Session)
	if !ok {
		return errorsx.WithStack(ErrInvalidSession)
	}

	if err := c.OpenIDConnectRequestValidator.ValidatePrompt(ctx, requester); err != nil {
		return err
	}

	claims := session.IDTokenClaims()
	if requester.GetResponseTypes().Has(consts.ResponseTypeImplicitFlowToken) {
		if err := c.AuthorizeImplicitGrantTypeHandler.IssueImplicitAccessToken(ctx, requester, responder); err != nil {
			return errorsx.WithStack(err)
		}

		requester.SetResponseTypeHandled(consts.ResponseTypeImplicitFlowToken)
		hash, err := c.ComputeHash(ctx, session, responder.GetParameters().Get(consts.AccessResponseAccessToken))
		if err != nil {
			return err
		}

		claims.AccessTokenHash = hash
	} else {
		responder.AddParameter(consts.FormParameterState, requester.GetState())
	}

	idTokenLifespan := oauth2.GetEffectiveLifespan(requester.GetClient(), oauth2.GrantTypeImplicit, oauth2.IDToken, c.Config.GetIDTokenLifespan(ctx))
	if err := c.IssueImplicitIDToken(ctx, idTokenLifespan, requester, responder); err != nil {
		return errorsx.WithStack(err)
	}

	// there is no need to check for https, because implicit flow does not require https
	// https://datatracker.ietf.org/doc/html/rfc6819#section-4.4.2

	requester.SetResponseTypeHandled(consts.ResponseTypeImplicitFlowIDToken)

	return nil
}
