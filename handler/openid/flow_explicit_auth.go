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
	}

	*IDTokenHandleHelper
}

// HandleAuthorizeEndpointRequest handles an authorize request whose 'response_type' is exactly 'code' and which was
// granted the 'openid' scope. It validates the 'redirect_uri' and 'prompt' parameters and persists the OpenID Connect
// 1.0 session under the authorization code, which must already have been issued.
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

	if err = c.OpenIDConnectRequestStorage.CreateOpenIDConnectSession(ctx, response.GetCode(), request.Sanitize(oidcParameters)); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

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
