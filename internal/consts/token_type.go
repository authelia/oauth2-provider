// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package consts

const (
	// TokenTypeAccessToken is the access_token token type hint value from RFC 7009.
	TokenTypeAccessToken = "access_token"
	// TokenTypeRefreshToken is the refresh_token token type hint value from RFC 7009.
	TokenTypeRefreshToken = "refresh_token"
	// TokenTypeClientRegistrationToken is the client_registration_token token type value.
	TokenTypeClientRegistrationToken = "client_registration_token"
)

// OAuth 2.0 Token Exchange (RFC 8693) token type identifiers.
//
// See https://datatracker.ietf.org/doc/html/rfc8693#section-3.
const (
	TokenTypeRFC8693AccessToken  = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeRFC8693RefreshToken = "urn:ietf:params:oauth:token-type:refresh_token"
	TokenTypeRFC8693IDToken      = "urn:ietf:params:oauth:token-type:id_token"
	TokenTypeRFC8693JWT          = "urn:ietf:params:oauth:token-type:jwt"
	TokenTypeRFC8693SAML1        = "urn:ietf:params:oauth:token-type:saml1"
	TokenTypeRFC8693SAML2        = "urn:ietf:params:oauth:token-type:saml2"
	TokenTypeRFC8693IDJAG        = "urn:ietf:params:oauth:token-type:id-jag"

	// TokenTypeRFC8693TxnToken identifies a Transaction Token.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-11.1
	TokenTypeRFC8693TxnToken = "urn:ietf:params:oauth:token-type:txn_token"

	// TokenTypeRFC8693SelfSigned identifies a self-signed JWT subject token.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-11.2.1
	TokenTypeRFC8693SelfSigned = "urn:ietf:params:oauth:token-type:self_signed"

	// TokenTypeRFC8693UnsignedJSON identifies an unsigned JSON subject token.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-11.2.2
	TokenTypeRFC8693UnsignedJSON = "urn:ietf:params:oauth:token-type:unsigned_json"
)
