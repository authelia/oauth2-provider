// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/token/jwt"
)

// OAuth2AuthorizeExplicitFactory creates an OAuth2 authorize code grant ("authorize explicit flow") handler and registers
// an access token, refresh token and authorize code validator.
func OAuth2AuthorizeExplicitFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &hoauth2.AuthorizeExplicitGrantHandler{
		AccessTokenStrategy:    strategy.(hoauth2.AccessTokenStrategy),
		RefreshTokenStrategy:   strategy.(hoauth2.RefreshTokenStrategy),
		AuthorizeCodeStrategy:  strategy.(hoauth2.AuthorizeCodeStrategy),
		CoreStorage:            storage.(hoauth2.CoreStorage),
		TokenRevocationStorage: storage.(hoauth2.TokenRevocationStorage),
		Config:                 config,
	}
}

// OAuth2ClientCredentialsGrantFactory creates an OAuth2 client credentials grant handler and registers
// an access token, refresh token and authorize code validator.
func OAuth2ClientCredentialsGrantFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &hoauth2.ClientCredentialsGrantHandler{
		HandleHelper: &hoauth2.HandleHelper{
			AccessTokenStrategy: strategy.(hoauth2.AccessTokenStrategy),
			AccessTokenStorage:  storage.(hoauth2.AccessTokenStorage),
			Config:              config,
		},
		Config: config,
	}
}

// OAuth2RefreshTokenGrantFactory creates an OAuth2 refresh grant handler and registers
// an access token, refresh token and authorize code validator.nmj
func OAuth2RefreshTokenGrantFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &hoauth2.RefreshTokenGrantHandler{
		AccessTokenStrategy:    strategy.(hoauth2.AccessTokenStrategy),
		RefreshTokenStrategy:   strategy.(hoauth2.RefreshTokenStrategy),
		TokenRevocationStorage: storage.(hoauth2.TokenRevocationStorage),
		Config:                 config,
	}
}

// OAuth2AuthorizeImplicitFactory creates an OAuth2 implicit grant ("authorize implicit flow") handler and registers
// an access token, refresh token and authorize code validator.
func OAuth2AuthorizeImplicitFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &hoauth2.AuthorizeImplicitGrantTypeHandler{
		AccessTokenStrategy: strategy.(hoauth2.AccessTokenStrategy),
		AccessTokenStorage:  storage.(hoauth2.AccessTokenStorage),
		Config:              config,
	}
}

// OAuth2ResourceOwnerPasswordCredentialsFactory creates an OAuth2 resource owner password credentials grant handler and registers
// an access token, refresh token and authorize code validator.
//
// Deprecated: This factory is deprecated as a means to communicate that the ROPC grant type is widely discouraged and
// is at the time of this writing going to be omitted in the OAuth 2.1 spec. For more information on why this grant type
// is discouraged see: https://www.scottbrady91.com/oauth/why-the-resource-owner-password-credentials-grant-type-is-not-authentication-nor-suitable-for-modern-applications
func OAuth2ResourceOwnerPasswordCredentialsFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &hoauth2.ResourceOwnerPasswordCredentialsGrantHandler{
		ResourceOwnerPasswordCredentialsGrantStorage: storage.(hoauth2.ResourceOwnerPasswordCredentialsGrantStorage),
		HandleHelper: &hoauth2.HandleHelper{
			AccessTokenStrategy: strategy.(hoauth2.AccessTokenStrategy),
			AccessTokenStorage:  storage.(hoauth2.AccessTokenStorage),
			Config:              config,
		},
		RefreshTokenStrategy: strategy.(hoauth2.RefreshTokenStrategy),
		Config:               config,
	}
}

// OAuth2TokenRevocationFactory creates an OAuth2 token revocation handler.
func OAuth2TokenRevocationFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &hoauth2.TokenRevocationHandler{
		TokenRevocationStorage: storage.(hoauth2.TokenRevocationStorage),
		AccessTokenStrategy:    strategy.(hoauth2.AccessTokenStrategy),
		RefreshTokenStrategy:   strategy.(hoauth2.RefreshTokenStrategy),
		Config:                 config,
	}
}

// OAuth2TokenIntrospectionFactory creates an OAuth2 token introspection handler and registers
// an access token and refresh token validator.
func OAuth2TokenIntrospectionFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &hoauth2.CoreValidator{
		CoreStrategy: strategy.(hoauth2.CoreStrategy),
		CoreStorage:  storage.(hoauth2.CoreStorage),
		Config:       config,
	}
}

// OAuth2StatelessJWTIntrospectionFactory creates an OAuth2 token introspection handler and
// registers an access token validator. This can only be used to validate JWTs and does so
// statelessly, meaning it uses only the data available in the JWT itself, and does not access the
// storage implementation at all.
//
// Due to the stateless nature of this factory, THE BUILT-IN REVOCATION MECHANISMS WILL NOT WORK.
// If you need revocation, you can validate JWTs statefully, using the other factories.
func OAuth2StatelessJWTIntrospectionFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &hoauth2.StatelessJWTValidator{
		Signer: strategy.(jwt.Signer),
		Config: config,
	}
}
