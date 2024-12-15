// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"time"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

type OpenIDConnectHybridHandler struct {
	AuthorizeImplicitGrantTypeHandler *hoauth2.AuthorizeImplicitGrantTypeHandler
	AuthorizeExplicitGrantHandler     *hoauth2.AuthorizeExplicitGrantHandler
	IDTokenHandleHelper               *IDTokenHandleHelper
	OpenIDConnectRequestValidator     *OpenIDConnectRequestValidator
	OpenIDConnectRequestStorage       OpenIDConnectRequestStorage

	Enigma *jwt.DefaultStrategy

	Config interface {
		oauth2.IDTokenLifespanProvider
		oauth2.MinParameterEntropyProvider
		oauth2.ScopeStrategyProvider
	}
}

var (
	_ oauth2.AuthorizeEndpointHandler = (*OpenIDConnectHybridHandler)(nil)
)

// HandleAuthorizeEndpointRequest implements oauth2.AuthorizeEndpointHandler.
//
// TODO: Refactor time permitting.
//
//nolint:gocyclo
func (c *OpenIDConnectHybridHandler) HandleAuthorizeEndpointRequest(ctx context.Context, requester oauth2.AuthorizeRequester, responder oauth2.AuthorizeResponder) error {
	if len(requester.GetResponseTypes()) < 2 {
		return nil
	}

	if !(requester.GetResponseTypes().Matches(consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeImplicitFlowIDToken, consts.ResponseTypeAuthorizationCodeFlow) || requester.GetResponseTypes().Matches(consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeAuthorizationCodeFlow) || requester.GetResponseTypes().Matches(consts.ResponseTypeImplicitFlowIDToken, consts.ResponseTypeAuthorizationCodeFlow)) {
		return nil
	}

	requester.SetDefaultResponseMode(oauth2.ResponseModeFragment)

	// There is no requirement to check response types here as they are validated in the AuthorizeRequestHandler.

	// The nonce is actually not required for hybrid flows. It fails the OpenID Connect Conformity
	// Test Module "oidcc-ensure-request-without-nonce-succeeds-for-code-flow" if enabled.
	//
	nonce := requester.GetRequestForm().Get(consts.FormParameterNonce)

	if len(nonce) == 0 && requester.GetResponseTypes().Has(consts.ResponseTypeImplicitFlowIDToken) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Parameter 'nonce' must be set when requesting an ID Token using the OpenID Connect Hybrid Flow."))
	}

	if len(nonce) > 0 && len(nonce) < c.Config.GetMinParameterEntropy(ctx) {
		return errorsx.WithStack(oauth2.ErrInsufficientEntropy.WithHintf("Parameter 'nonce' is set but does not satisfy the minimum entropy of %d characters.", c.Config.GetMinParameterEntropy(ctx)))
	}

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

	sess, ok := requester.GetSession().(Session)
	if !ok {
		return errorsx.WithStack(ErrInvalidSession)
	}

	if err := c.OpenIDConnectRequestValidator.ValidatePrompt(ctx, requester); err != nil {
		return err
	}

	client := requester.GetClient()
	for _, scope := range requester.GetRequestedScopes() {
		if !c.Config.GetScopeStrategy(ctx)(client.GetScopes(), scope) {
			return errorsx.WithStack(oauth2.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
	}

	claims := sess.IDTokenClaims()

	var (
		hash string
		err  error
	)

	// FAPI 1.0 Advanced. This fulfills the ID Token as a detached signature requirement. It should be noted that in
	// the FAPI 2.0 profile this is replaced by PKCE and PAR.
	//
	// See Also:
	//	- https://openid.net/specs/openid-financial-api-part-2-1_0.html#id-token-as-detached-signature-2
	//  - https://openid.bitbucket.io/fapi/fapi-2_0-security-profile.html#section-5.6
	if requester.GetResponseTypes().Matches(consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowIDToken) {
		if state := requester.GetState(); len(state) != 0 && claims != nil {
			if hash, err = c.IDTokenHandleHelper.ComputeHash(ctx, sess, requester.GetState()); err != nil {
				return err
			}

			claims.StateHash = hash
		}
	}

	if requester.GetResponseTypes().Has(consts.ResponseTypeAuthorizationCodeFlow) {
		if !requester.GetClient().GetGrantTypes().Has(consts.GrantTypeAuthorizationCode) {
			return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant 'authorization_code'."))
		}

		var (
			code, signature string
		)

		if code, signature, err = c.AuthorizeExplicitGrantHandler.AuthorizeCodeStrategy.GenerateAuthorizeCode(ctx, requester); err != nil {
			return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
		}

		// This is not required because the auth code flow is being handled by oauth2/flow_authorize_code_token which in turn
		// sets the proper access/refresh token lifetimes.
		//
		// if c.AuthorizeExplicitGrantHandler.RefreshTokenLifespan > -1 {
		// 	 requester.GetSession().SetExpiresAt(oauth2.RefreshToken, time.Now().UTC().Add(c.AuthorizeExplicitGrantHandler.RefreshTokenLifespan).Truncate(jwt.TimePrecision))
		// }

		// This is required because we must limit the authorize code lifespan.
		requester.GetSession().SetExpiresAt(oauth2.AuthorizeCode, time.Now().UTC().Add(c.AuthorizeExplicitGrantHandler.Config.GetAuthorizeCodeLifespan(ctx)).Truncate(jwt.TimePrecision))

		if err = c.AuthorizeExplicitGrantHandler.CoreStorage.CreateAuthorizeCodeSession(ctx, signature, requester.Sanitize(c.AuthorizeExplicitGrantHandler.GetSanitationWhiteList(ctx))); err != nil {
			return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
		}

		responder.AddParameter(consts.FormParameterAuthorizationCode, code)
		requester.SetResponseTypeHandled(consts.ResponseTypeAuthorizationCodeFlow)

		if hash, err = c.IDTokenHandleHelper.ComputeHash(ctx, sess, responder.GetParameters().Get(consts.FormParameterAuthorizationCode)); err != nil {
			return err
		}

		claims.CodeHash = hash

		if requester.GetGrantedScopes().Has(consts.ScopeOpenID) {
			if err = c.OpenIDConnectRequestStorage.CreateOpenIDConnectSession(ctx, responder.GetCode(), requester.Sanitize(oidcParameters)); err != nil {
				return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
			}
		}
	}

	if requester.GetResponseTypes().Has(consts.ResponseTypeImplicitFlowToken) {
		if !requester.GetClient().GetGrantTypes().Has(consts.GrantTypeImplicit) {
			return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The OAuth 2.0 Client is not allowed to use the authorization grant 'implicit'."))
		} else if err = c.AuthorizeImplicitGrantTypeHandler.IssueImplicitAccessToken(ctx, requester, responder); err != nil {
			return errorsx.WithStack(err)
		}

		requester.SetResponseTypeHandled(consts.ResponseTypeImplicitFlowToken)

		if hash, err = c.IDTokenHandleHelper.ComputeHash(ctx, sess, responder.GetParameters().Get(consts.AccessResponseAccessToken)); err != nil {
			return err
		}

		claims.AccessTokenHash = hash
	}

	if _, ok = responder.GetParameters()[consts.FormParameterState]; !ok {
		responder.AddParameter(consts.FormParameterState, requester.GetState())
	}

	if !requester.GetGrantedScopes().Has(consts.ScopeOpenID) || !requester.GetResponseTypes().Has(consts.ResponseTypeImplicitFlowIDToken) {
		requester.SetResponseTypeHandled(consts.ResponseTypeImplicitFlowIDToken)

		return nil
	}

	// Hybrid flow uses implicit flow config for the id token's lifespan
	idTokenLifespan := oauth2.GetEffectiveLifespan(requester.GetClient(), oauth2.GrantTypeImplicit, oauth2.IDToken, c.Config.GetIDTokenLifespan(ctx))
	if err = c.IDTokenHandleHelper.IssueImplicitIDToken(ctx, idTokenLifespan, requester, responder); err != nil {
		return errorsx.WithStack(err)
	}

	requester.SetResponseTypeHandled(consts.ResponseTypeImplicitFlowIDToken)

	// there is no need to check for https, because implicit flow does not require https
	// https://datatracker.ietf.org/doc/html/rfc6819#section-4.4.2
	return nil
}
