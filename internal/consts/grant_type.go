// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package consts

// Grant Type strings.
const (
	GrantTypeImplicit                         = valueImplicit
	GrantTypeRefreshToken                     = valueRefreshToken
	GrantTypeAuthorizationCode                = "authorization_code"
	GrantTypeClientCredentials                = "client_credentials"
	GrantTypeResourceOwnerPasswordCredentials = valuePassword
	GrantTypeOAuthJWTBearer                   = "urn:ietf:params:oauth:grant-type:jwt-bearer"     //nolint:gosec
	GrantTypeOAuthJWTDPoP                     = "urn:ietf:params:oauth:grant-type:jwt-dpop"       //nolint:gosec
	GrantTypeOAuthDeviceCode                  = "urn:ietf:params:oauth:grant-type:device_code"    //nolint:gosec
	GrantTypeOAuthTokenExchange               = "urn:ietf:params:oauth:grant-type:token-exchange" //nolint:gosec
)

// Authorization grant profile identifiers.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-10.2
const (
	GrantProfileIDJAG = "urn:ietf:params:oauth:grant-profile:id-jag"
)
