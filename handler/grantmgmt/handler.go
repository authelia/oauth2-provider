// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package grantmgmt

import (
	"context"

	"authelia.com/provider/oauth2"
)

// Handler implements OpenID Grant Management for OAuth 2.0. It is inert unless Config implements
// oauth2.GrantManagementConfigProvider and returns a configuration.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-5
type Handler struct {
	Config  oauth2.Configurator
	Storage oauth2.GrantManagementStorage
}

// HandlesGrantManagement returns true if grant management is configured.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-7.1
func (h *Handler) HandlesGrantManagement(ctx context.Context) (enabled bool) {
	return h.config(ctx) != nil
}

func (h *Handler) config(ctx context.Context) (config *oauth2.GrantManagementConfig) {
	provider, ok := h.Config.(oauth2.GrantManagementConfigProvider)
	if !ok {
		return nil
	}

	return provider.GetGrantManagementConfig(ctx)
}

var (
	_ oauth2.GrantManagementHandler                          = (*Handler)(nil)
	_ oauth2.AuthorizeEndpointBindingHandler                 = (*Handler)(nil)
	_ oauth2.AuthorizeRequestValidator                       = (*Handler)(nil)
	_ oauth2.RFC8628DeviceAuthorizeEndpointBindingHandler    = (*Handler)(nil)
	_ oauth2.BackChannelAuthenticationEndpointBindingHandler = (*Handler)(nil)
	_ oauth2.BackChannelAuthenticationDecisionHandler        = (*Handler)(nil)
	_ oauth2.TokenEndpointBindingHandler                     = (*Handler)(nil)
	_ oauth2.TokenEndpointBindingCommitHandler               = (*Handler)(nil)
)
