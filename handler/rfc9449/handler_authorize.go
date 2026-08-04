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

	// Only record the binding for flows that issue an authorization code; an implicit-only flow never presents a
	// code at the token endpoint, so it would never pass through Handler.BindAccessRequest's proof check and
	// would otherwise end up with an unenforceable cnf.jkt on its (directly issued) token.
	if !types.Has(consts.ResponseTypeAuthorizationCodeFlow) {
		return nil
	}

	// A hybrid flow that also issues an access token straight from the authorization endpoint is skipped for the same
	// reason. The binding lives on the session shared by every authorize handler, so it cannot be applied to the code
	// alone: the directly issued access token would pick up a cnf.jkt that no proof was ever checked against, while
	// still being advertised as 'token_type=bearer' in the authorization response. RFC 9449 Section 7.1 requires a
	// DPoP bound access token to be presented under the DPoP scheme, so a conforming client would present that token
	// as a bearer token and the resource server would be obliged to reject it.
	if types.Has(consts.ResponseTypeImplicitFlowToken) {
		return nil
	}

	session, ok := request.GetSession().(oauth2.DPoPBoundSession)
	if !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithHint("The session does not support DPoP binding."))
	}

	session.SetDPoPJWKThumbprint(jkt)

	return nil
}

var (
	_ oauth2.AuthorizeEndpointBindingHandler = (*AuthorizeHandler)(nil)
)
