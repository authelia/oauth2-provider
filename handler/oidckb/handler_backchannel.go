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

// BindBackChannelAuthenticationRequest applies OpenID Connect Key Binding 1.0 to an OpenID Connect CIBA authentication
// request that requests the 'bound_key' scope, and records that key binding was granted so that its ID Tokens carry
// the 'cnf' claim. The key is the DPoP proof key rfc9449.Handler verified and recorded at the backchannel
// authentication endpoint, so it MUST be registered after rfc9449.Handler. A 'dpop_jkt' parameter alone is rejected,
// as it records no public key for the 'cnf' claim to carry.
//
// See: https://openid.net/specs/openid-connect-key-binding-1_0.html#section-3.1
func (h *Handler) BindBackChannelAuthenticationRequest(ctx context.Context, request oauth2.BackChannelAuthenticationRequester) (err error) {
	if !h.Config.GetOIDCKeyBindingEnabled(ctx) || !h.Config.GetDPoPEnabled(ctx) {
		return nil
	}

	if !request.GetRequestedScopes().Has(consts.ScopeBoundKey) {
		return nil
	}

	// Section 3.1: the scope parameter MUST contain both 'openid' and 'bound_key'.
	if !request.GetRequestedScopes().Has(consts.ScopeOpenID) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The scope 'bound_key' must not be requested without the scope 'openid' because no ID Token would be issued to bind."))
	}

	session, ok := request.GetSession().(oauth2.DPoPBoundSession)
	if !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithHint("The session does not support DPoP key binding."))
	}

	if session.GetDPoPJWKThumbprint() == "" || len(session.GetDPoPPublicKeyJWK()) == 0 {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("A DPoP proof is required at the backchannel authentication endpoint when the 'bound_key' scope is requested."))
	}

	session.SetOIDCKeyBindingGranted(true)

	return nil
}

var (
	_ oauth2.BackChannelAuthenticationEndpointBindingHandler = (*Handler)(nil)
)
