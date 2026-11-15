// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package consts

const (
	// JSONWebTokenHeaderKeyIdentifier is the JOSE header parameter "kid" from RFC 7515.
	JSONWebTokenHeaderKeyIdentifier = "kid"
	// JSONWebTokenHeaderAlgorithm is the JOSE header parameter "alg" from RFC 7515.
	JSONWebTokenHeaderAlgorithm = "alg"
	// JSONWebTokenHeaderEncryptionAlgorithm is the JOSE header parameter "enc" from RFC 7516.
	JSONWebTokenHeaderEncryptionAlgorithm = valueEnc
	// JSONWebTokenHeaderCompressionAlgorithm is the JOSE header parameter "zip" from RFC 7516.
	JSONWebTokenHeaderCompressionAlgorithm = "zip"
	// JSONWebTokenHeaderPBES2Count is the JOSE header parameter "p2c" from RFC 7518.
	JSONWebTokenHeaderPBES2Count = "p2c"

	// JSONWebTokenHeaderType is the JOSE header parameter "typ" from RFC 7515.
	JSONWebTokenHeaderType = "typ"
	// JSONWebTokenHeaderContentType is the JOSE header parameter "cty" from RFC 7515.
	JSONWebTokenHeaderContentType = "cty"
)

const (
	// JSONWebTokenUseSignature is the JWK "use" value for signature keys from RFC 7517.
	JSONWebTokenUseSignature = "sig"
	// JSONWebTokenUseEncryption is the JWK "use" value for encryption keys from RFC 7517.
	JSONWebTokenUseEncryption = valueEnc
)

const (
	// JSONWebTokenTypeJWT is the JWT type header value.
	JSONWebTokenTypeJWT = "JWT"

	// JSONWebTokenTypeAccessToken represents the JWT type value for a JWT Profile Access Token.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc9068#section-2.1
	JSONWebTokenTypeAccessToken = "at+jwt"

	// JSONWebTokenTypeSoftwareStatement is the JWT type value suggested for an RFC 7591 Section 2.3 software statement,
	// following the RFC 8725 Section 3.11 naming convention. No type is registered for software statements, so which
	// types are accepted is configurable; this one is allowed by default alongside 'JWT'.
	JSONWebTokenTypeSoftwareStatement = "software-statement+jwt"

	// JSONWebTokenTypeLogoutToken represents the JWT type value for OpenID Connect Back-Channel Logout 1.0.
	//
	// See: https://openid.net/specs/openid-connect-backchannel-1_0.html#Security
	JSONWebTokenTypeLogoutToken = "logout+jwt"

	// JSONWebTokenTypeJWTSecuredAuthorizationRequest represents the JWT type value for JWT Secured Authorization Requests.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9101.html#section-4
	JSONWebTokenTypeJWTSecuredAuthorizationRequest = "oauth-authz-req+jwt"

	// JSONWebTokenTypeClientAuthentication represents the JWT type value for Client Assertions.
	//
	// See: https://www.rfc-editor.org/rfc/rfc10070#section-4
	JSONWebTokenTypeClientAuthentication = "client-authentication+jwt"

	// JSONWebTokenTypeTokenIntrospection represents the JWT type value for a JWT Response for OAuth Token Introspection.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9701.html#section-5
	JSONWebTokenTypeTokenIntrospection = "token-introspection+jwt"

	// JSONWebTokenTypeDPoP represents the JWT type value for a DPoP proof JWT.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9449#section-4.2
	JSONWebTokenTypeDPoP = "dpop+jwt"

	// JSONWebTokenTypeDPoPIDToken represents the JWT type value for a key-bound ID Token.
	//
	// See: https://openid.net/specs/openid-connect-key-binding-1_0.html#section-4
	JSONWebTokenTypeDPoPIDToken = "dpop+id_token"

	// JSONWebTokenTypeIDJAG represents the JWT type value for an Identity Assertion JWT Authorization Grant.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-3.1
	JSONWebTokenTypeIDJAG = "oauth-id-jag+jwt"

	// JSONWebTokenTypeTxnToken represents the JWT type value for a Transaction Token.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-9.1
	JSONWebTokenTypeTxnToken = "txntoken+jwt"

	// JSONWebTokenTypeSecurityEventToken represents the JWT type value for a Security Event Token.
	//
	// See: https://www.rfc-editor.org/rfc/rfc8417.html#section-2.3
	JSONWebTokenTypeSecurityEventToken = "secevent+jwt"
)

const (
	// JSONWebTokenAlgNone is the "none" JWS algorithm, meaning an unsecured JWT.
	JSONWebTokenAlgNone = valueNone
	// JSONWebTokenAlgHMACSHA256 is the HMAC using SHA-256 JWS algorithm from RFC 7518.
	JSONWebTokenAlgHMACSHA256 = "HS256"
	// JSONWebTokenAlgHMACSHA384 is the HMAC using SHA-384 JWS algorithm from RFC 7518.
	JSONWebTokenAlgHMACSHA384 = "HS384"
	// JSONWebTokenAlgHMACSHA512 is the HMAC using SHA-512 JWS algorithm from RFC 7518.
	JSONWebTokenAlgHMACSHA512 = "HS512"
)
