// SPDX-FileCopyrightText: 2026 Authelia
//
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

// HandleAuthorizeEndpointRequest implements oauth2.AuthorizeEndpointHandler.
//
// TODO: Refactor time permitting.
//
//nolint:gocyclo
func (c *OpenIDConnectHybridHandler) HandleAuthorizeEndpointRequest(ctx context.Context, request oauth2.AuthorizeRequester, response oauth2.AuthorizeResponder) (err error) {
	if len(request.GetResponseTypes()) < 2 {
		return nil
	}

	if !(request.GetResponseTypes().Matches(consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeImplicitFlowIDToken, consts.ResponseTypeAuthorizationCodeFlow) || request.GetResponseTypes().Matches(consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeAuthorizationCodeFlow) || request.GetResponseTypes().Matches(consts.ResponseTypeImplicitFlowIDToken, consts.ResponseTypeAuthorizationCodeFlow)) {
		return nil
	}

	request.SetDefaultResponseMode(oauth2.ResponseModeFragment)

	// The client must be registered for the 'implicit' grant to receive an ID Token or Access Token from the
	// authorization endpoint.
	//
	// See: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
	if request.GetResponseTypes().HasOneOf(consts.ResponseTypeImplicitFlowIDToken, consts.ResponseTypeImplicitFlowToken) && !request.GetClient().GetGrantTypes().Has(consts.GrantTypeImplicit) {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The OAuth 2.0 Client is not allowed to use the authorization grant 'implicit'."))
	}

	// OpenID Connect Core 1.0 Section 3.3.2.1: the 'id_token' response type issues an ID Token, which needs the
	// 'openid' scope; checked before any code or token is issued.
	if request.GetResponseTypes().Has(consts.ResponseTypeImplicitFlowIDToken) && !request.GetGrantedScopes().Has(consts.ScopeOpenID) {
		if request.GetRequestedScopes().Has(consts.ScopeOpenID) {
			return errorsx.WithStack(oauth2.ErrAccessDenied.WithHint("The 'id_token' response type requires the 'openid' scope, which was not granted."))
		}

		return errorsx.WithStack(oauth2.ErrInvalidScope.WithHint("The 'id_token' response type requires the 'openid' scope."))
	}

	// There is no requirement to check response types here as they are validated in the AuthorizeRequestHandler.

	if err = c.OpenIDConnectRequestValidator.ValidateRedirectURIs(ctx, request); err != nil {
		return err
	}

	var session Session

	if session, err = c.OpenIDConnectRequestValidator.ValidatePrompt(ctx, request); err != nil {
		return err
	}

	if err = c.OpenIDConnectRequestValidator.ValidateClaims(ctx, request); err != nil {
		return err
	}

	// The nonce is actually not required for hybrid flows. It fails the OpenID Connect Conformity
	// Test Module "oidcc-ensure-request-without-nonce-succeeds-for-code-flow" if enabled.
	//
	nonce := request.GetRequestForm().Get(consts.FormParameterNonce)

	if len(nonce) == 0 && request.GetResponseTypes().Has(consts.ResponseTypeImplicitFlowIDToken) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Parameter 'nonce' must be set when requesting an ID Token using the OpenID Connect Hybrid Flow."))
	}

	if len(nonce) > 0 && len(nonce) < c.Config.GetMinParameterEntropy(ctx) {
		return errorsx.WithStack(oauth2.ErrInsufficientEntropy.WithHintf("Parameter 'nonce' is set but does not satisfy the minimum entropy of %d characters.", c.Config.GetMinParameterEntropy(ctx)))
	}

	client := request.GetClient()
	strategy := oauth2.GetScopeStrategy(ctx, c.Config, client)

	for _, scope := range request.GetRequestedScopes() {
		if !strategy(client.GetScopes(), scope) {
			return errorsx.WithStack(oauth2.ErrInvalidScope.WithHint("The OAuth 2.0 Client is not allowed to request one or more of the values of the 'scope' parameter.").WithDebugf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
	}

	// See: https://www.rfc-editor.org/rfc/rfc9396#section-5
	if request.GetResponseTypes().Has(consts.ResponseTypeImplicitFlowToken) {
		if err = oauth2.ValidateAuthorizationDetailsTypes(ctx, c.Config, client, request.GetGrantedAuthorizationDetails()); err != nil {
			return err
		}
	}

	if err = oauth2.ValidateRedirectURISecurity(ctx, c.AuthorizeExplicitGrantHandler.Config, client, request.GetRedirectURI()); err != nil {
		return err
	}

	if request.GetResponseTypes().Has(consts.ResponseTypeAuthorizationCodeFlow) && !client.GetGrantTypes().Has(consts.GrantTypeAuthorizationCode) {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant 'authorization_code'."))
	}

	if request.GetResponseTypes().Has(consts.ResponseTypeImplicitFlowToken) && !client.GetGrantTypes().Has(consts.GrantTypeImplicit) {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The OAuth 2.0 Client is not allowed to use the authorization grant 'implicit'."))
	}

	// Hybrid flow uses implicit flow config for the ID Token's lifespan.
	lifespan := oauth2.GetEffectiveLifespan(client, oauth2.GrantTypeImplicit, oauth2.IDToken, c.Config.GetIDTokenLifespan(ctx))

	idTokenExpiresAt := getIDTokenExpiresAt(session, lifespan)

	if err = setNonceUsed(ctx, c.OpenIDConnectRequestStorage, request, c.getNonceExpiresAt(ctx, request, idTokenExpiresAt)); err != nil {
		return err
	}

	claims := session.IDTokenClaims()

	var hash string

	// FAPI 1.0 Advanced. This fulfills the ID Token as a detached signature requirement. It should be noted that in
	// the FAPI 2.0 profile this is replaced by PKCE and PAR.
	//
	// See Also:
	//	- https://openid.net/specs/openid-financial-api-part-2-1_0.html#id-token-as-detached-signature-2
	//  - https://openid.bitbucket.io/fapi/fapi-2_0-security-profile.html#section-5.6
	if request.GetResponseTypes().Matches(consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowIDToken) {
		if state := request.GetState(); len(state) != 0 && claims != nil {
			if hash, err = c.IDTokenHandleHelper.ComputeHash(ctx, request.GetClient(), request.GetState()); err != nil {
				return err
			}

			claims.StateHash = hash
		}
	}

	if request.GetResponseTypes().Has(consts.ResponseTypeAuthorizationCodeFlow) {
		var (
			code, signature string
		)

		if code, signature, err = c.AuthorizeExplicitGrantHandler.AuthorizeCodeStrategy.GenerateAuthorizeCode(ctx, request); err != nil {
			return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
		}

		// This is required because we must limit the authorize code lifespan.
		request.GetSession().SetExpiresAt(oauth2.AuthorizeCode, time.Now().UTC().Add(c.AuthorizeExplicitGrantHandler.Config.GetAuthorizeCodeLifespan(ctx)).Truncate(jwt.TimePrecision))

		if err = c.AuthorizeExplicitGrantHandler.CoreStorage.CreateAuthorizeCodeSession(ctx, signature, request.Sanitize(c.AuthorizeExplicitGrantHandler.GetAuthorizeCodeSessionParameters(ctx))); err != nil {
			return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
		}

		response.AddParameter(consts.FormParameterAuthorizationCode, code)
		request.SetResponseTypeHandled(consts.ResponseTypeAuthorizationCodeFlow)

		if hash, err = c.IDTokenHandleHelper.ComputeHash(ctx, request.GetClient(), response.GetParameters().Get(consts.FormParameterAuthorizationCode)); err != nil {
			return err
		}

		claims.CodeHash = hash

		if request.GetGrantedScopes().Has(consts.ScopeOpenID) {
			if err = c.OpenIDConnectRequestStorage.CreateOpenIDConnectSession(ctx, response.GetCode(), request.Sanitize(oidcParameters)); err != nil {
				return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
			}
		}
	}

	if request.GetResponseTypes().Has(consts.ResponseTypeImplicitFlowToken) {
		if err = c.AuthorizeImplicitGrantTypeHandler.IssueImplicitAccessToken(ctx, request, response); err != nil {
			return errorsx.WithStack(err)
		}

		request.SetResponseTypeHandled(consts.ResponseTypeImplicitFlowToken)

		if hash, err = c.IDTokenHandleHelper.ComputeHash(ctx, request.GetClient(), response.GetParameters().Get(consts.AccessResponseAccessToken)); err != nil {
			return err
		}

		claims.AccessTokenHash = hash
	}

	if _, ok := response.GetParameters()[consts.FormParameterState]; !ok && len(request.GetState()) != 0 {
		response.AddParameter(consts.FormParameterState, request.GetState())
	}

	if !request.GetResponseTypes().Has(consts.ResponseTypeImplicitFlowIDToken) {
		return nil
	}

	setIDTokenExpiresAt(session, idTokenExpiresAt)

	if err = c.IDTokenHandleHelper.IssueImplicitIDToken(ctx, lifespan, request, response); err != nil {
		return errorsx.WithStack(err)
	}

	request.SetResponseTypeHandled(consts.ResponseTypeImplicitFlowIDToken)

	return nil
}

func (c *OpenIDConnectHybridHandler) getNonceExpiresAt(ctx context.Context, request oauth2.AuthorizeRequester, idTokenExpiresAt time.Time) (expiresAt time.Time) {
	now := time.Now().UTC()

	if request.GetResponseTypes().Has(consts.ResponseTypeImplicitFlowIDToken) {
		expiresAt = idTokenExpiresAt
	}

	if request.GetResponseTypes().Has(consts.ResponseTypeAuthorizationCodeFlow) {
		if code := now.Add(c.AuthorizeExplicitGrantHandler.Config.GetAuthorizeCodeLifespan(ctx)); code.After(expiresAt) {
			expiresAt = code
		}
	}

	return expiresAt
}

// ResponseTypesSupported returns the response types this handler serves.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
func (c *OpenIDConnectHybridHandler) ResponseTypesSupported(ctx context.Context) (types []string) {
	return []string{consts.ResponseTypeHybridFlowIDToken, consts.ResponseTypeHybridFlowToken, consts.ResponseTypeHybridFlowBoth}
}

// GrantTypesSupported returns the grant types this handler serves.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
func (c *OpenIDConnectHybridHandler) GrantTypesSupported(ctx context.Context) (types []string) {
	return []string{consts.GrantTypeImplicit}
}

// CodeChallengeMethodsSupported returns nil because the handler does not enforce PKCE.
//
// See: https://datatracker.ietf.org/doc/html/rfc7636#section-4.3
func (c *OpenIDConnectHybridHandler) CodeChallengeMethodsSupported(ctx context.Context) (methods []string) {
	return nil
}

// IDTokenSigningAlgValuesSupported returns the JWS algorithms this handler can sign an ID Token with.
//
// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
func (c *OpenIDConnectHybridHandler) IDTokenSigningAlgValuesSupported(ctx context.Context) (algs []string) {
	return c.IDTokenHandleHelper.IDTokenSigningAlgValuesSupported(ctx)
}

var (
	_ oauth2.AuthorizeEndpointHandler = (*OpenIDConnectHybridHandler)(nil)
)
