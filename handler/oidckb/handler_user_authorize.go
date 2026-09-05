// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oidckb

import (
	"context"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// UserAuthorizeHandler records that the 'bound_key' scope was granted for a device flow.
//
// The Device Authorization Flow grants its scopes here rather than at the device authorization endpoint, because the
// end user approves the request at this endpoint. DeviceAuthorizeHandler therefore cannot record the marker: at the
// point it runs, consent has not happened.
//
// It MUST be registered before rfc8628.UserAuthorizeHandler, which persists the device code session; registered after
// it, the marker would be recorded onto a session already written. compose.Compose panics on the wrong order.
type UserAuthorizeHandler struct {
	Config interface {
		oauth2.OIDCKeyBindingConfigProvider
		oauth2.DPoPConfigProvider
	}
}

// HandleRFC8628UserAuthorizeEndpointRequest is not implemented by this handler, which only records a binding onto a
// request another handler owns.
func (h *UserAuthorizeHandler) HandleRFC8628UserAuthorizeEndpointRequest(ctx context.Context, request oauth2.DeviceAuthorizeRequester) (err error) {
	return errorsx.WithStack(oauth2.ErrUnknownRequest)
}

// PopulateRFC8628UserAuthorizeEndpointResponse records the marker once the end user has approved a request whose
// granted scopes include 'bound_key'.
func (h *UserAuthorizeHandler) PopulateRFC8628UserAuthorizeEndpointResponse(ctx context.Context, request oauth2.DeviceAuthorizeRequester, _ oauth2.DeviceUserAuthorizeResponder) (err error) {
	if !h.Config.GetOIDCKeyBindingEnabled(ctx) || !h.Config.GetDPoPEnabled(ctx) {
		return nil
	}

	if !request.GetGrantedScopes().Has(consts.ScopeBoundKey) {
		return nil
	}

	session, ok := request.GetSession().(oauth2.DPoPBoundSession)
	if !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithHint("The session does not support DPoP key binding."))
	}

	session.SetOIDCKeyBindingGranted(true)

	return nil
}

var (
	_ oauth2.RFC8628UserAuthorizeEndpointHandler = (*UserAuthorizeHandler)(nil)
)
