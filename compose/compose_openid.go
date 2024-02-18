// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/handler/rfc8628"
	"authelia.com/provider/oauth2/token/jwt"
)

// OpenIDConnectExplicitFactory creates an OpenID Connect explicit ("authorize code flow") grant handler.
//
// **Important note:** You must add this handler *after* you have added an OAuth2 authorize code handler!
func OpenIDConnectExplicitFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &openid.OpenIDConnectExplicitHandler{
		OpenIDConnectRequestStorage: storage.(openid.OpenIDConnectRequestStorage),
		IDTokenHandleHelper: &openid.IDTokenHandleHelper{
			IDTokenStrategy: strategy.(openid.OpenIDConnectTokenStrategy),
		},
		OpenIDConnectRequestValidator: openid.NewOpenIDConnectRequestValidator(strategy.(jwt.Signer), config),
		Config:                        config,
	}
}

// OpenIDConnectRefreshFactory creates a handler for refreshing openid connect tokens.
//
// **Important note:** You must add this handler *after* you have added an OAuth2 authorize code handler!
func OpenIDConnectRefreshFactory(config oauth2.Configurator, _ any, strategy any) any {
	return &openid.OpenIDConnectRefreshHandler{
		IDTokenHandleHelper: &openid.IDTokenHandleHelper{
			IDTokenStrategy: strategy.(openid.OpenIDConnectTokenStrategy),
		},
		Config: config,
	}
}

// OpenIDConnectImplicitFactory creates an OpenID Connect implicit ("implicit flow") grant handler.
//
// **Important note:** You must add this handler *after* you have added an OAuth2 authorize code handler!
func OpenIDConnectImplicitFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &openid.OpenIDConnectImplicitHandler{
		AuthorizeImplicitGrantTypeHandler: &hoauth2.AuthorizeImplicitGrantTypeHandler{
			AccessTokenStrategy: strategy.(hoauth2.AccessTokenStrategy),
			AccessTokenStorage:  storage.(hoauth2.AccessTokenStorage),
			Config:              config,
		},
		Config: config,
		IDTokenHandleHelper: &openid.IDTokenHandleHelper{
			IDTokenStrategy: strategy.(openid.OpenIDConnectTokenStrategy),
		},
		OpenIDConnectRequestValidator: openid.NewOpenIDConnectRequestValidator(strategy.(jwt.Signer), config),
	}
}

// OpenIDConnectHybridFactory creates an OpenID Connect hybrid grant handler.
//
// **Important note:** You must add this handler *after* you have added an OAuth2 authorize code handler!
func OpenIDConnectHybridFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &openid.OpenIDConnectHybridHandler{
		AuthorizeExplicitGrantHandler: &hoauth2.AuthorizeExplicitGrantHandler{
			AccessTokenStrategy:   strategy.(hoauth2.AccessTokenStrategy),
			RefreshTokenStrategy:  strategy.(hoauth2.RefreshTokenStrategy),
			AuthorizeCodeStrategy: strategy.(hoauth2.AuthorizeCodeStrategy),
			CoreStorage:           storage.(hoauth2.CoreStorage),
			Config:                config,
		},
		Config: config,
		AuthorizeImplicitGrantTypeHandler: &hoauth2.AuthorizeImplicitGrantTypeHandler{
			AccessTokenStrategy: strategy.(hoauth2.AccessTokenStrategy),
			AccessTokenStorage:  storage.(hoauth2.AccessTokenStorage),
			Config:              config,
		},
		IDTokenHandleHelper: &openid.IDTokenHandleHelper{
			IDTokenStrategy: strategy.(openid.OpenIDConnectTokenStrategy),
		},
		OpenIDConnectRequestStorage:   storage.(openid.OpenIDConnectRequestStorage),
		OpenIDConnectRequestValidator: openid.NewOpenIDConnectRequestValidator(strategy.(jwt.Signer), config),
	}
}

func OpenIDConnectDeviceAuthorizeFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &openid.OpenIDConnectDeviceAuthorizeHandler{
		OpenIDConnectRequestStorage:   storage.(openid.OpenIDConnectRequestStorage),
		OpenIDConnectRequestValidator: openid.NewOpenIDConnectRequestValidator(strategy.(jwt.Signer), config),
		CodeTokenEndpointHandler: &rfc8628.DeviceCodeTokenHandler{
			Strategy: strategy.(rfc8628.RFC8628CodeStrategy),
			Storage:  storage.(rfc8628.RFC8628Storage),
			Config:   config,
		},
		Config: config,
		IDTokenHandleHelper: &openid.IDTokenHandleHelper{
			IDTokenStrategy: strategy.(openid.OpenIDConnectTokenStrategy),
		},
	}
}
