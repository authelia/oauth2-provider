// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package consts

const (
	TokenTypeAccessToken  = "access_token"
	TokenTypeRefreshToken = "refresh_token"
)

// OAuth 2.0 Token Exchange (RFC 8693) token type identifiers.
//
// See https://datatracker.ietf.org/doc/html/rfc8693#section-3.
const (
	TokenTypeRFC8693AccessToken  = "urn:ietf:params:oauth:token-type:access_token"  //nolint:gosec // This is a credential type, not a credential.
	TokenTypeRFC8693RefreshToken = "urn:ietf:params:oauth:token-type:refresh_token" //nolint:gosec // This is a credential type, not a credential.
	TokenTypeRFC8693IDToken      = "urn:ietf:params:oauth:token-type:id_token"      //nolint:gosec // This is a credential type, not a credential.
	TokenTypeRFC8693JWT          = "urn:ietf:params:oauth:token-type:jwt"           //nolint:gosec // This is a credential type, not a credential.
	TokenTypeRFC8693SAML1        = "urn:ietf:params:oauth:token-type:saml1"         //nolint:gosec // This is a credential type, not a credential.
	TokenTypeRFC8693SAML2        = "urn:ietf:params:oauth:token-type:saml2"         //nolint:gosec // This is a credential type, not a credential.
)
