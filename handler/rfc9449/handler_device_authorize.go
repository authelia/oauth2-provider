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

// DeviceAuthorizeHandler implements the RFC 9449 Section 10.1 'dpop_jkt' parameter at the RFC 8628 device
// authorization endpoint.
//
// It is a distinct handler from AuthorizeHandler because the two bind at different endpoints and the device
// authorization request is not an oauth2.AuthorizeRequester. There is no response type gate here: a device
// authorization request issues a device code that is always redeemed at the token endpoint, so the binding is always
// enforceable by Handler.BindAccessRequest.
type DeviceAuthorizeHandler struct {
	Config interface {
		oauth2.DPoPConfigProvider
	}
}

// BindRFC8628DeviceAuthorizeRequest records the 'dpop_jkt' parameter onto the session so the device code becomes
// bound to the client's DPoP proof-of-possession key.
func (h *DeviceAuthorizeHandler) BindRFC8628DeviceAuthorizeRequest(ctx context.Context, request oauth2.DeviceAuthorizeRequester) (err error) {
	if !h.Config.GetDPoPEnabled(ctx) {
		return nil
	}

	jkt := request.GetRequestForm().Get(consts.FormParameterDPoPJKT)
	if jkt == "" {
		return nil
	}

	if !oauth2.IsValidDPoPJWKThumbprint(jkt) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The 'dpop_jkt' parameter must be the base64url encoded SHA-256 JWK Thumbprint of the DPoP proof-of-possession public key, which is %d characters long.", oauth2.DPoPJWKThumbprintLength))
	}

	session, ok := request.GetSession().(oauth2.DPoPBoundSession)
	if !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithHint("The session does not support DPoP binding."))
	}

	session.SetDPoPJWKThumbprint(jkt)

	// Section 10.1: recorded separately from the binding itself, because the token endpoint overwrites the binding
	// from the presented proof and OpenID Connect Key Binding 1.0 Section 2.3 needs to know what the authentication
	// request asked for.
	session.SetRequestedDPoPJWKThumbprint(jkt)

	return nil
}

var (
	_ oauth2.RFC8628DeviceAuthorizeEndpointBindingHandler = (*DeviceAuthorizeHandler)(nil)
)
