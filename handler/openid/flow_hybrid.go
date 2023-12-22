// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"time"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/errorsx"
	"authelia.com/provider/oauth2/token/jwt"
)

type OpenIDConnectHybridHandler struct {
	AuthorizeImplicitGrantTypeHandler *hoauth2.AuthorizeImplicitGrantTypeHandler
	AuthorizeExplicitGrantHandler     *hoauth2.AuthorizeExplicitGrantHandler
	IDTokenHandleHelper               *IDTokenHandleHelper
	OpenIDConnectRequestValidator     *OpenIDConnectRequestValidator
	OpenIDConnectRequestStorage       OpenIDConnectRequestStorage

	Enigma *jwt.DefaultSigner

	Config interface {
		oauth2.IDTokenLifespanProvider
		oauth2.MinParameterEntropyProvider
		oauth2.ScopeStrategyProvider
	}
}

var (
	_ oauth2.AuthorizeEndpointHandler = (*OpenIDConnectHybridHandler)(nil)
)

func (c *OpenIDConnectHybridHandler) HandleAuthorizeEndpointRequest(ctx context.Context, ar oauth2.AuthorizeRequester, resp oauth2.AuthorizeResponder) error {
	if len(ar.GetResponseTypes()) < 2 {
		return nil
	}

	if !(ar.GetResponseTypes().Matches(consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeImplicitFlowIDToken, consts.ResponseTypeAuthorizationCodeFlow) || ar.GetResponseTypes().Matches(consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeAuthorizationCodeFlow) || ar.GetResponseTypes().Matches(consts.ResponseTypeImplicitFlowIDToken, consts.ResponseTypeAuthorizationCodeFlow)) {
		return nil
	}

	ar.SetDefaultResponseMode(oauth2.ResponseModeFragment)

	// Disabled because this is already handled at the authorize_request_handler
	//if ar.GetResponseTypes().Matches("token") && !ar.GetClient().GetResponseTypes().Has("token") {
	//	return errorsx.WithStack(oauth2.ErrInvalidGrant.WithDebug("The client is not allowed to use the token response type"))
	//} else if ar.GetResponseTypes().Matches("code") && !ar.GetClient().GetResponseTypes().Has("code") {
	//	return errorsx.WithStack(oauth2.ErrInvalidGrant.WithDebug("The client is not allowed to use the code response type"))
	//} else if ar.GetResponseTypes().Matches("id_token") && !ar.GetClient().GetResponseTypes().Has("id_token") {
	//	return errorsx.WithStack(oauth2.ErrInvalidGrant.WithDebug("The client is not allowed to use the id_token response type"))
	//}

	// The nonce is actually not required for hybrid flows. It fails the OpenID Connect Conformity
	// Test Module "oidcc-ensure-request-without-nonce-succeeds-for-code-flow" if enabled.
	//
	nonce := ar.GetRequestForm().Get(consts.FormParameterNonce)

	if len(nonce) == 0 && ar.GetResponseTypes().Has(consts.ResponseTypeImplicitFlowIDToken) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Parameter 'nonce' must be set when requesting an ID Token using the OpenID Connect Hybrid Flow."))
	}

	if len(nonce) > 0 && len(nonce) < c.Config.GetMinParameterEntropy(ctx) {
		return errorsx.WithStack(oauth2.ErrInsufficientEntropy.WithHintf("Parameter 'nonce' is set but does not satisfy the minimum entropy of %d characters.", c.Config.GetMinParameterEntropy(ctx)))
	}

	sess, ok := ar.GetSession().(Session)
	if !ok {
		return errorsx.WithStack(ErrInvalidSession)
	}

	if err := c.OpenIDConnectRequestValidator.ValidatePrompt(ctx, ar); err != nil {
		return err
	}

	client := ar.GetClient()
	for _, scope := range ar.GetRequestedScopes() {
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
	if ar.GetResponseTypes().Matches(consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowIDToken) {
		if state := ar.GetState(); len(state) != 0 && claims != nil {
			if hash, err = c.IDTokenHandleHelper.ComputeHash(ctx, sess, ar.GetState()); err != nil {
				return err
			}

			claims.StateHash = hash
		}
	}

	if ar.GetResponseTypes().Has(consts.ResponseTypeAuthorizationCodeFlow) {
		if !ar.GetClient().GetGrantTypes().Has(consts.GrantTypeAuthorizationCode) {
			return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant 'authorization_code'."))
		}

		var (
			code, signature string
		)

		if code, signature, err = c.AuthorizeExplicitGrantHandler.AuthorizeCodeStrategy.GenerateAuthorizeCode(ctx, ar); err != nil {
			return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}

		// This is not required because the auth code flow is being handled by oauth2/flow_authorize_code_token which in turn
		// sets the proper access/refresh token lifetimes.
		//
		// if c.AuthorizeExplicitGrantHandler.RefreshTokenLifespan > -1 {
		// 	 ar.GetSession().SetExpiresAt(oauth2.RefreshToken, time.Now().UTC().Add(c.AuthorizeExplicitGrantHandler.RefreshTokenLifespan).Round(time.Second))
		// }

		// This is required because we must limit the authorize code lifespan.
		ar.GetSession().SetExpiresAt(oauth2.AuthorizeCode, time.Now().UTC().Add(c.AuthorizeExplicitGrantHandler.Config.GetAuthorizeCodeLifespan(ctx)).Round(time.Second))

		if err = c.AuthorizeExplicitGrantHandler.CoreStorage.CreateAuthorizeCodeSession(ctx, signature, ar.Sanitize(c.AuthorizeExplicitGrantHandler.GetSanitationWhiteList(ctx))); err != nil {
			return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}

		resp.AddParameter(consts.FormParameterAuthorizationCode, code)
		ar.SetResponseTypeHandled(consts.ResponseTypeAuthorizationCodeFlow)

		if hash, err = c.IDTokenHandleHelper.ComputeHash(ctx, sess, resp.GetParameters().Get(consts.FormParameterAuthorizationCode)); err != nil {
			return err
		}

		claims.CodeHash = hash

		if ar.GetGrantedScopes().Has(consts.ScopeOpenID) {
			if err = c.OpenIDConnectRequestStorage.CreateOpenIDConnectSession(ctx, resp.GetCode(), ar.Sanitize(oidcParameters)); err != nil {
				return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
			}
		}
	}

	if ar.GetResponseTypes().Has(consts.ResponseTypeImplicitFlowToken) {
		if !ar.GetClient().GetGrantTypes().Has(consts.GrantTypeImplicit) {
			return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The OAuth 2.0 Client is not allowed to use the authorization grant 'implicit'."))
		} else if err = c.AuthorizeImplicitGrantTypeHandler.IssueImplicitAccessToken(ctx, ar, resp); err != nil {
			return errorsx.WithStack(err)
		}

		ar.SetResponseTypeHandled(consts.ResponseTypeImplicitFlowToken)

		if hash, err = c.IDTokenHandleHelper.ComputeHash(ctx, sess, resp.GetParameters().Get(consts.AccessResponseAccessToken)); err != nil {
			return err
		}

		claims.AccessTokenHash = hash
	}

	if _, ok = resp.GetParameters()[consts.FormParameterState]; !ok {
		resp.AddParameter(consts.FormParameterState, ar.GetState())
	}

	if !ar.GetGrantedScopes().Has(consts.ScopeOpenID) || !ar.GetResponseTypes().Has(consts.ResponseTypeImplicitFlowIDToken) {
		ar.SetResponseTypeHandled(consts.ResponseTypeImplicitFlowIDToken)

		return nil
	}

	// Hybrid flow uses implicit flow config for the id token's lifespan
	idTokenLifespan := oauth2.GetEffectiveLifespan(ar.GetClient(), oauth2.GrantTypeImplicit, oauth2.IDToken, c.Config.GetIDTokenLifespan(ctx))
	if err = c.IDTokenHandleHelper.IssueImplicitIDToken(ctx, idTokenLifespan, ar, resp); err != nil {
		return errorsx.WithStack(err)
	}

	ar.SetResponseTypeHandled(consts.ResponseTypeImplicitFlowIDToken)

	// there is no need to check for https, because implicit flow does not require https
	// https://datatracker.ietf.org/doc/html/rfc6819#section-4.4.2
	return nil
}
