// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/handler/rfc7523"
	"authelia.com/provider/oauth2/handler/rfc8628"
	"authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/token/jwt"
)

func withTestCapabilities(config *oauth2.Config) *oauth2.Config {
	explicit := &hoauth2.AuthorizeExplicitGrantHandler{}
	implicit := &hoauth2.AuthorizeImplicitGrantTypeHandler{}
	oidcImplicit := &openid.OpenIDConnectImplicitHandler{}

	config.AuthorizeEndpointHandlers.Append(explicit)
	config.AuthorizeEndpointHandlers.Append(implicit)
	config.AuthorizeEndpointHandlers.Append(oidcImplicit)

	config.TokenEndpointHandlers.Append(explicit)
	config.TokenEndpointHandlers.Append(&hoauth2.ClientCredentialsGrantHandler{})
	config.TokenEndpointHandlers.Append(&hoauth2.RefreshTokenGrantHandler{})
	config.TokenEndpointHandlers.Append(&hoauth2.ResourceOwnerPasswordCredentialsGrantHandler{}) //nolint:staticcheck
	config.TokenEndpointHandlers.Append(&rfc8693.TokenExchangeGrantHandler{})
	config.TokenEndpointHandlers.Append(&rfc7523.Handler{})
	config.TokenEndpointHandlers.Append(&rfc8628.DeviceAuthorizeTokenEndpointHandler{})

	return config
}

type signingAlgValuesStrategy struct {
	jwt.Strategy

	algs []string
}

func (s signingAlgValuesStrategy) SigningAlgValues(_ context.Context) []string {
	return s.algs
}
