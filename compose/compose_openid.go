// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"github.com/authelia/goauth2"
	"github.com/authelia/goauth2/handler/oauth2"
	"github.com/authelia/goauth2/handler/openid"
	"github.com/authelia/goauth2/token/jwt"
)

// OpenIDConnectExplicitFactory creates an OpenID Connect explicit ("authorize code flow") grant handler.
//
// **Important note:** You must add this handler *after* you have added an OAuth2 authorize code handler!
func OpenIDConnectExplicitFactory(config goauth2.Configurator, storage interface{}, strategy interface{}) interface{} {
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
func OpenIDConnectRefreshFactory(config goauth2.Configurator, _ interface{}, strategy interface{}) interface{} {
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
func OpenIDConnectImplicitFactory(config goauth2.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &openid.OpenIDConnectImplicitHandler{
		AuthorizeImplicitGrantTypeHandler: &oauth2.AuthorizeImplicitGrantTypeHandler{
			AccessTokenStrategy: strategy.(oauth2.AccessTokenStrategy),
			AccessTokenStorage:  storage.(oauth2.AccessTokenStorage),
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
func OpenIDConnectHybridFactory(config goauth2.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &openid.OpenIDConnectHybridHandler{
		AuthorizeExplicitGrantHandler: &oauth2.AuthorizeExplicitGrantHandler{
			AccessTokenStrategy:   strategy.(oauth2.AccessTokenStrategy),
			RefreshTokenStrategy:  strategy.(oauth2.RefreshTokenStrategy),
			AuthorizeCodeStrategy: strategy.(oauth2.AuthorizeCodeStrategy),
			CoreStorage:           storage.(oauth2.CoreStorage),
			Config:                config,
		},
		Config: config,
		AuthorizeImplicitGrantTypeHandler: &oauth2.AuthorizeImplicitGrantTypeHandler{
			AccessTokenStrategy: strategy.(oauth2.AccessTokenStrategy),
			AccessTokenStorage:  storage.(oauth2.AccessTokenStorage),
			Config:              config,
		},
		IDTokenHandleHelper: &openid.IDTokenHandleHelper{
			IDTokenStrategy: strategy.(openid.OpenIDConnectTokenStrategy),
		},
		OpenIDConnectRequestStorage:   storage.(openid.OpenIDConnectRequestStorage),
		OpenIDConnectRequestValidator: openid.NewOpenIDConnectRequestValidator(strategy.(jwt.Signer), config),
	}
}
