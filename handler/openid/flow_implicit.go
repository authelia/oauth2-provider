// SPDX-FileCopyrightText: 2026 Authelia
//
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
func (c *OpenIDConnectImplicitHandler) HandleAuthorizeEndpointRequest(ctx context.Context, request oauth2.AuthorizeRequester, response oauth2.AuthorizeResponder) (err error) {
	if !(request.GetGrantedScopes().Has(consts.ScopeOpenID) && (request.GetResponseTypes().Has(consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeImplicitFlowIDToken) || request.GetResponseTypes().ExactOne(consts.ResponseTypeImplicitFlowIDToken))) {
		return nil
	} else if request.GetResponseTypes().Has(consts.ResponseTypeAuthorizationCodeFlow) {
		// hybrid flow
		return nil
	}

	request.SetDefaultResponseMode(oauth2.ResponseModeFragment)

	if !request.GetClient().GetGrantTypes().Has(consts.GrantTypeImplicit) {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The OAuth 2.0 Client is not allowed to use the authorization grant 'implicit'."))
	}

	if err = c.OpenIDConnectRequestValidator.ValidateRedirectURIs(ctx, request); err != nil {
		return err
	}

	var session Session

	if session, err = c.OpenIDConnectRequestValidator.ValidatePrompt(ctx, request); err != nil {
		return err
	}

	if nonce := request.GetRequestForm().Get(consts.FormParameterNonce); len(nonce) == 0 {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Parameter 'nonce' must be set when using the OpenID Connect Implicit Flow."))
	} else if len(nonce) < c.Config.GetMinParameterEntropy(ctx) {
		return errorsx.WithStack(oauth2.ErrInsufficientEntropy.WithHintf("Parameter 'nonce' is set but does not satisfy the minimum entropy of %d characters.", c.Config.GetMinParameterEntropy(ctx)))
	}

	client := request.GetClient()
	strategy := oauth2.GetScopeStrategy(ctx, c.Config, client)

	for _, scope := range request.GetRequestedScopes() {
		if !strategy(client.GetScopes(), scope) {
			return errorsx.WithStack(oauth2.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
	}

	claims := session.IDTokenClaims()
	if request.GetResponseTypes().Has(consts.ResponseTypeImplicitFlowToken) {
		if err = c.AuthorizeImplicitGrantTypeHandler.IssueImplicitAccessToken(ctx, request, response); err != nil {
			return errorsx.WithStack(err)
		}

		request.SetResponseTypeHandled(consts.ResponseTypeImplicitFlowToken)

		var hash string

		if hash, err = c.ComputeHash(ctx, session, response.GetParameters().Get(consts.AccessResponseAccessToken)); err != nil {
			return err
		}

		claims.AccessTokenHash = hash
	} else {
		response.AddParameter(consts.FormParameterState, request.GetState())
	}

	lifespan := oauth2.GetEffectiveLifespan(request.GetClient(), oauth2.GrantTypeImplicit, oauth2.IDToken, c.Config.GetIDTokenLifespan(ctx))

	if err = c.IssueImplicitIDToken(ctx, lifespan, request, response); err != nil {
		return errorsx.WithStack(err)
	}

	request.SetResponseTypeHandled(consts.ResponseTypeImplicitFlowIDToken)

	// There is no need to check for https, because implicit flow does not require https,
	// See: https://datatracker.ietf.org/doc/html/rfc6819#section-4.4.2
	return nil
}
