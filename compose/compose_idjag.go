// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/idjag"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/token/jwt"
)

// IDJAGIssueFactory creates the handler that issues an Identity Assertion JWT Authorization Grant through RFC 8693
// token exchange. It MUST be registered after RFC8693TokenExchangeGrantFactory and before
// RFC8693ActorTokenValidationFactory, and 'urn:ietf:params:oauth:token-type:id-jag' MUST be registered in
// oauth2.Config.RFC8693TokenTypes as an *rfc8693.DefaultTokenType.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.3
func IDJAGIssueFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &idjag.IssueHandler{
		Config:   config.(idjag.IssueConfig),
		Strategy: strategy.(jwt.Strategy),
		Storage:  storage.(idjag.IssueStorage),
	}
}

// IDJAGRedeemFactory creates the handler that redeems an Identity Assertion JWT Authorization Grant through the
// 'urn:ietf:params:oauth:grant-type:jwt-bearer' grant, or through the 'urn:ietf:params:oauth:grant-type:jwt-dpop'
// grant Section 9.8.1.2.1 uses for a DPoP-bound grant. The handler is also a token endpoint binding handler, so the
// factory MUST be registered after DPoPTokenFactory.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4
// See: https://datatracker.ietf.org/doc/html/draft-parecki-oauth-jwt-dpop-grant-01
func IDJAGRedeemFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &idjag.RedeemHandler{
		Config:  config.(idjag.RedeemConfig),
		Storage: storage.(idjag.RedeemStorage),
		HandleHelper: &hoauth2.HandleHelper{
			AccessTokenStrategy: strategy.(hoauth2.AccessTokenStrategy),
			AccessTokenStorage:  storage.(hoauth2.AccessTokenStorage),
			Config:              config,
		},
	}
}
