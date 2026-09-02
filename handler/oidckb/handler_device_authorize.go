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

// DeviceAuthorizeHandler enforces the OpenID Connect Key Binding 1.0 Section 3.1 rules that apply to a device
// authorization request.
//
// There is no response type gate as there is in AuthorizeHandler: a device authorization request has no response
// type, and the device code it issues is always redeemed at the token endpoint.
type DeviceAuthorizeHandler struct {
	Config interface {
		oauth2.OIDCKeyBindingConfigProvider
		oauth2.DPoPConfigProvider
	}
}

// BindRFC8628DeviceAuthorizeRequest requires the 'dpop_jkt' parameter when the 'bound_key' scope is requested.
func (h *DeviceAuthorizeHandler) BindRFC8628DeviceAuthorizeRequest(ctx context.Context, request oauth2.DeviceAuthorizeRequester) (err error) {
	if !h.Config.GetOIDCKeyBindingEnabled(ctx) || !h.Config.GetDPoPEnabled(ctx) {
		return nil
	}

	if !request.GetRequestedScopes().Has(consts.ScopeBoundKey) {
		return nil
	}

	// Section 3.1: the scope parameter MUST contain both 'openid' and 'bound_key'. Without 'openid' no ID Token is
	// issued at all, so there is nothing for a 'cnf' claim to bind.
	if !request.GetRequestedScopes().Has(consts.ScopeOpenID) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The scope 'bound_key' must not be requested without the scope 'openid' because no ID Token would be issued to bind."))
	}

	if request.GetRequestForm().Get(consts.FormParameterDPoPJKT) == "" {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The 'dpop_jkt' parameter is required when the 'bound_key' scope is requested."))
	}

	return nil
}

var (
	_ oauth2.RFC8628DeviceAuthorizeEndpointBindingHandler = (*DeviceAuthorizeHandler)(nil)
)
