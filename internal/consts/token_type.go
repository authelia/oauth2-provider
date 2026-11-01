// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package consts

const (
	TokenTypeAccessToken             = "access_token"
	TokenTypeRefreshToken            = "refresh_token"
	TokenTypeClientRegistrationToken = "client_registration_token"
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
	TokenTypeRFC8693IDJAG        = "urn:ietf:params:oauth:token-type:id-jag"        //nolint:gosec // This is a credential type, not a credential.

	// TokenTypeRFC8693TxnToken identifies a Transaction Token.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-11.1
	TokenTypeRFC8693TxnToken = "urn:ietf:params:oauth:token-type:txn_token" //nolint:gosec // This is a credential type, not a credential.

	// TokenTypeRFC8693SelfSigned identifies a self-signed JWT subject token.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-11.2.1
	TokenTypeRFC8693SelfSigned = "urn:ietf:params:oauth:token-type:self_signed" //nolint:gosec // This is a credential type, not a credential.

	// TokenTypeRFC8693UnsignedJSON identifies an unsigned JSON subject token.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-11.2.2
	TokenTypeRFC8693UnsignedJSON = "urn:ietf:params:oauth:token-type:unsigned_json" //nolint:gosec // This is a credential type, not a credential.
)
