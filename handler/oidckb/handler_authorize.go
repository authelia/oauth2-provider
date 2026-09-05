// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oidckb

import (
	"context"
	"strings"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// AuthorizeHandler enforces the OpenID Connect Key Binding 1.0 rules that apply to an authentication request.
//
// It rejects a request that cannot produce the key-bound ID Token it asks for, and records that the 'bound_key' scope
// was granted. It does not record the 'dpop_jkt' parameter: rfc9449.AuthorizeHandler already does.
type AuthorizeHandler struct {
	Config interface {
		oauth2.OIDCKeyBindingConfigProvider
		oauth2.DPoPConfigProvider
	}
}

// BindAuthorizeRequest applies Section 1.4 and Section 2.1 to an authentication request that requests the 'bound_key'
// scope.
//
// The requested scope is read rather than the granted scope: this rejects a request asking for a security property the
// flow cannot deliver, which the client asked for whether or not the deployment goes on to grant it.
func (h *AuthorizeHandler) BindAuthorizeRequest(ctx context.Context, request oauth2.AuthorizeRequester) (err error) {
	if !h.Config.GetOIDCKeyBindingEnabled(ctx) || !h.Config.GetDPoPEnabled(ctx) {
		return nil
	}

	if !request.GetRequestedScopes().Has(consts.ScopeBoundKey) {
		return nil
	}

	// Section 2.1 describes the key binding request as one whose scope already contains 'openid'. Without it no ID
	// Token is issued at all, so there is nothing for a 'cnf' claim to bind, and a client asking to bind one has
	// asked for something this request can never produce.
	if !request.GetRequestedScopes().Has(consts.ScopeOpenID) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The scope 'bound_key' must not be requested without the scope 'openid' because no ID Token would be issued to bind."))
	}

	types := request.GetResponseTypes()

	// Section 1.4: key binding is defined for the Authorization Code Flow and the Device Authorization Flow only, and
	// the device flow binds at its own endpoint. The Implicit and Hybrid Flows MUST NOT be used to obtain a key-bound
	// ID Token, and support for any other flow is out of scope, so exactly 'code' is required here: every other
	// response type either returns an ID Token from this endpoint that no proof was presented for, or returns none
	// that a Token Request could bind.
	if !types.ExactOne(consts.ResponseTypeAuthorizationCodeFlow) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The scope 'bound_key' must not be requested with the response type '%s' because only the Authorization Code Flow can produce a key-bound ID Token.", strings.Join(types, " ")))
	}

	// Section 2.1 and Section 3.1: the request MUST include the 'dpop_jkt' parameter.
	if request.GetRequestForm().Get(consts.FormParameterDPoPJKT) == "" {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The 'dpop_jkt' parameter is required when the 'bound_key' scope is requested."))
	}

	// The granted scopes decide whether this grant's ID Tokens are key bound, and this is the last point at which
	// that answer is known and can still be persisted with the authorization code: the token endpoint's binding
	// phase runs before the authorization code grant copies its granted scopes onto the request.
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
	_ oauth2.AuthorizeEndpointBindingHandler = (*AuthorizeHandler)(nil)
)
