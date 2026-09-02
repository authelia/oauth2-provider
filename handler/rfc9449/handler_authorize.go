// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc9449

import (
	"context"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// AuthorizeHandler implements the RFC 9449 Section 10.1 'dpop_jkt' authorize-request parameter.
//
// It is a distinct handler from Handler because the two bind at different endpoints. This one is dispatched by
// oauth2.(*Fosite).NewAuthorizeResponse ahead of every oauth2.AuthorizeEndpointHandler, so the thumbprint is on the
// session before the handlers that issue an authorization code persist a copy of it. Registration order does not
// affect that.
type AuthorizeHandler struct {
	Config interface {
		oauth2.DPoPConfigProvider
	}
}

// BindAuthorizeRequest records the 'dpop_jkt' authorize-request parameter onto the session so the authorization code
// becomes bound to the client's DPoP proof-of-possession key. The bound thumbprint is later enforced by
// Handler.BindAccessRequest against the DPoP proof presented at the token endpoint.
func (h *AuthorizeHandler) BindAuthorizeRequest(ctx context.Context, request oauth2.AuthorizeRequester) (err error) {
	if !h.Config.GetDPoPEnabled(ctx) {
		return nil
	}

	jkt := request.GetRequestForm().Get(consts.FormParameterDPoPJKT)
	if jkt == "" {
		return nil
	}

	// Checked before the response type gates below, as a malformed parameter is malformed whether or not this flow
	// goes on to use it.
	if !oauth2.IsValidDPoPJWKThumbprint(jkt) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The 'dpop_jkt' parameter must be the base64url encoded SHA-256 JWK Thumbprint of the DPoP proof-of-possession public key, which is %d characters long.", oauth2.DPoPJWKThumbprintLength))
	}

	types := request.GetResponseTypes()

	// RFC 9449 Section 10 binds an authorization code, so a flow that issues none records nothing.
	if !types.Has(consts.ResponseTypeAuthorizationCodeFlow) {
		return nil
	}

	session, ok := request.GetSession().(oauth2.DPoPBoundSession)
	if !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithHint("The session does not support DPoP binding."))
	}

	// Section 10: recorded for every flow that issues a code, so Handler.BindAccessRequest rejects a redemption whose
	// proof key does not match it. Section 10.1 keeps it separate from the binding below, because the token endpoint
	// overwrites that from the presented proof and OpenID Connect Key Binding 1.0 Section 2.3 needs to know what the
	// authentication request asked for.
	session.SetRequestedDPoPJWKThumbprint(jkt)

	// The binding itself is withheld from a hybrid flow that also issues an access token straight from the
	// authorization endpoint. ApplyConfirmation reads it, so recording it here would put a 'cnf.jkt' on that token
	// while the authorization response still advertises 'token_type=bearer', and Section 7.1 would then oblige the
	// resource server to reject it. The code remains bound by the requested thumbprint above.
	if types.Has(consts.ResponseTypeImplicitFlowToken) {
		return nil
	}

	session.SetDPoPJWKThumbprint(jkt)

	return nil
}

var (
	_ oauth2.AuthorizeEndpointBindingHandler = (*AuthorizeHandler)(nil)
)
