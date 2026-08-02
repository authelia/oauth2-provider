// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/rfc7591"
)

// RFC7591ClientRegistrationFactory creates the OAuth 2.0 Dynamic Client Registration (RFC 7591) endpoint handler.
func RFC7591ClientRegistrationFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &rfc7591.ClientRegistrationHandler{
		Store:    storage.(rfc7591.Storage),
		Strategy: strategy.(hoauth2.AccessTokenStrategy),
		Config:   config,
	}
}

// RFC7592ClientConfigurationFactory creates the OAuth 2.0 Dynamic Client Registration Management (RFC 7592) endpoint
// handler.
func RFC7592ClientConfigurationFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &rfc7591.ClientConfigurationHandler{
		Store:    storage.(rfc7591.Storage),
		Strategy: strategy.(hoauth2.AccessTokenStrategy),
		Config:   config,
	}
}
