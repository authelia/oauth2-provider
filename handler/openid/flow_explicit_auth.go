// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

type OpenIDConnectExplicitHandler struct {
	// OpenIDConnectRequestStorage is the storage for open id connect sessions.
	OpenIDConnectRequestStorage   OpenIDConnectRequestStorage
	OpenIDConnectRequestValidator *OpenIDConnectRequestValidator

	Config interface {
		oauth2.IDTokenLifespanProvider
		oauth2.MinParameterEntropyProvider
	}

	*IDTokenHandleHelper
}

// HandleAuthorizeEndpointRequest handles an authorize request whose 'response_type' is exactly 'code' and which was
// granted the 'openid' scope. It validates the 'redirect_uri', 'prompt', 'claims', and 'nonce' parameters and persists
// the OpenID Connect 1.0 session under the authorization code, which must already have been issued. A 'nonce' the client
// already used while the authorization code issued for it could still be redeemed is rejected.
func (c *OpenIDConnectExplicitHandler) HandleAuthorizeEndpointRequest(ctx context.Context, request oauth2.AuthorizeRequester, response oauth2.AuthorizeResponder) (err error) {
	if !(request.GetGrantedScopes().Has(consts.ScopeOpenID) && request.GetResponseTypes().ExactOne(consts.ResponseTypeAuthorizationCodeFlow)) {
		return nil
	}

	if len(response.GetCode()) == 0 {
		return errorsx.WithStack(oauth2.ErrMisconfiguration.WithDebug("The authorization code has not been issued yet, indicating a broken code configuration."))
	}

	if err = c.OpenIDConnectRequestValidator.ValidateRedirectURIs(ctx, request); err != nil {
		return err
	}

	if _, err = c.OpenIDConnectRequestValidator.ValidatePrompt(ctx, request); err != nil {
		return err
	}

	if err = c.OpenIDConnectRequestValidator.ValidateClaims(ctx, request); err != nil {
		return err
	}

	if nonce := request.GetRequestForm().Get(consts.FormParameterNonce); len(nonce) > 0 && len(nonce) < c.Config.GetMinParameterEntropy(ctx) {
		return errorsx.WithStack(oauth2.ErrInsufficientEntropy.WithHintf("Parameter 'nonce' is set but does not satisfy the minimum entropy of %d characters.", c.Config.GetMinParameterEntropy(ctx)))
	}

	if err = setNonceUsed(ctx, c.OpenIDConnectRequestStorage, request, getSessionExpiresAt(request, oauth2.AuthorizeCode, c.Config.GetIDTokenLifespan(ctx))); err != nil {
		return err
	}

	if err = c.OpenIDConnectRequestStorage.CreateOpenIDConnectSession(ctx, response.GetCode(), request.Sanitize(oidcParameters)); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	return nil
}

// ResponseTypesSupported returns nil because the handler only augments another flow.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
func (c *OpenIDConnectExplicitHandler) ResponseTypesSupported(ctx context.Context) (types []string) {
	return nil
}

// GrantTypesSupported returns nil because the handler only augments another grant.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
func (c *OpenIDConnectExplicitHandler) GrantTypesSupported(ctx context.Context) (types []string) {
	return nil
}

// CodeChallengeMethodsSupported returns nil because the handler does not enforce PKCE.
//
// See: https://datatracker.ietf.org/doc/html/rfc7636#section-4.3
func (c *OpenIDConnectExplicitHandler) CodeChallengeMethodsSupported(ctx context.Context) (methods []string) {
	return nil
}

// RFC8693TokenTypesSupported returns nil because the handler does not issue RFC 8693 tokens.
//
// See: https://datatracker.ietf.org/doc/html/rfc8693#section-3
func (c *OpenIDConnectExplicitHandler) RFC8693TokenTypesSupported(ctx context.Context) (types []string) {
	return nil
}

var oidcParameters = []string{
	consts.FormParameterGrantType,
	consts.FormParameterMaximumAge,
	consts.FormParameterPrompt,
	consts.FormParameterAuthenticationContextClassReferenceValues,
	consts.FormParameterIDTokenHint,
	consts.FormParameterNonce,
}

var (
	_ oauth2.AuthorizeEndpointHandler = (*OpenIDConnectExplicitHandler)(nil)
	_ oauth2.TokenEndpointHandler     = (*OpenIDConnectExplicitHandler)(nil)
)

// IsOpenIDConnectHandler marks this handler as an OpenID Connect authorization flow handler.
//
// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
func (c *OpenIDConnectExplicitHandler) IsOpenIDConnectHandler() {}
