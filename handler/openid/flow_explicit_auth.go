// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"

	"github.com/ory/x/errorsx"

	"github.com/authelia/goauth2"
)

type OpenIDConnectExplicitHandler struct {
	// OpenIDConnectRequestStorage is the storage for open id connect sessions.
	OpenIDConnectRequestStorage   OpenIDConnectRequestStorage
	OpenIDConnectRequestValidator *OpenIDConnectRequestValidator

	Config interface {
		goauth2.IDTokenLifespanProvider
	}

	*IDTokenHandleHelper
}

var (
	_ goauth2.AuthorizeEndpointHandler = (*OpenIDConnectExplicitHandler)(nil)
	_ goauth2.TokenEndpointHandler     = (*OpenIDConnectExplicitHandler)(nil)
)

var oidcParameters = []string{"grant_type",
	"max_age",
	"prompt",
	"acr_values",
	"id_token_hint",
	"nonce",
}

func (c *OpenIDConnectExplicitHandler) HandleAuthorizeEndpointRequest(ctx context.Context, ar goauth2.AuthorizeRequester, resp goauth2.AuthorizeResponder) error {
	if !(ar.GetGrantedScopes().Has("openid") && ar.GetResponseTypes().ExactOne("code")) {
		return nil
	}

	//if !ar.GetClient().GetResponseTypes().Has("id_token", "code") {
	//	return errorsx.WithStack(goauth2.ErrInvalidRequest.WithDebug("The client is not allowed to use response type id_token and code"))
	//}

	if len(resp.GetCode()) == 0 {
		return errorsx.WithStack(goauth2.ErrMisconfiguration.WithDebug("The authorization code has not been issued yet, indicating a broken code configuration."))
	}

	if err := c.OpenIDConnectRequestValidator.ValidatePrompt(ctx, ar); err != nil {
		return err
	}

	if err := c.OpenIDConnectRequestStorage.CreateOpenIDConnectSession(ctx, resp.GetCode(), ar.Sanitize(oidcParameters)); err != nil {
		return errorsx.WithStack(goauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	// there is no need to check for https, because it has already been checked by core.explicit

	return nil
}
