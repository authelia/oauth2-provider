// Copyright © 2023 Ory Corp
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

var (
	_ oauth2.AuthorizeEndpointHandler = (*OpenIDConnectExplicitHandler)(nil)
	_ oauth2.TokenEndpointHandler     = (*OpenIDConnectExplicitHandler)(nil)
)

var oidcParameters = []string{
	consts.FormParameterGrantType,
	consts.FormParameterMaximumAge,
	consts.FormParameterPrompt,
	consts.FormParameterAuthenticationContextClassReferenceValues,
	consts.FormParameterIDTokenHint,
	consts.FormParameterNonce,
}

func (c *OpenIDConnectExplicitHandler) HandleAuthorizeEndpointRequest(ctx context.Context, requester oauth2.AuthorizeRequester, responder oauth2.AuthorizeResponder) error {
	if !(requester.GetGrantedScopes().Has(consts.ScopeOpenID) && requester.GetResponseTypes().ExactOne(consts.ResponseTypeAuthorizationCodeFlow)) {
		return nil
	}

	if len(responder.GetCode()) == 0 {
		return errorsx.WithStack(oauth2.ErrMisconfiguration.WithDebug("The authorization code has not been issued yet, indicating a broken code configuration."))
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

	if err := c.OpenIDConnectRequestValidator.ValidatePrompt(ctx, requester); err != nil {
		return err
	}

	if err := c.OpenIDConnectRequestStorage.CreateOpenIDConnectSession(ctx, responder.GetCode(), requester.Sanitize(oidcParameters)); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	return nil
}
