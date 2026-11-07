// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package cimd

import (
	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/rfc7523"
	"authelia.com/provider/oauth2/handler/rfc8693"
)

func newTestValidatorConfig() *oauth2.Config {
	config := &oauth2.Config{}

	explicit := &hoauth2.AuthorizeExplicitGrantHandler{}

	config.AuthorizeEndpointHandlers.Append(explicit)
	config.TokenEndpointHandlers.Append(explicit)
	config.TokenEndpointHandlers.Append(&hoauth2.ClientCredentialsGrantHandler{})
	config.TokenEndpointHandlers.Append(&hoauth2.RefreshTokenGrantHandler{})
	config.TokenEndpointHandlers.Append(&rfc8693.TokenExchangeGrantHandler{})
	config.TokenEndpointHandlers.Append(&rfc7523.Handler{})

	return config
}
