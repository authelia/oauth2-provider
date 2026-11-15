// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2/internal/consts"
)

const (
	// SigningMethodNone is the none signature algorithm, meaning an unsecured JWT.
	SigningMethodNone = jose.SignatureAlgorithm(JSONWebTokenAlgNone)

	// UnsafeAllowNoneSignatureType is unsafe to use and should be use to correctly sign and verify alg:none JWT tokens.
	UnsafeAllowNoneSignatureType unsafeNoneMagicConstant = "none signing method allowed"
)

type unsafeNoneMagicConstant string

// Keyfunc is used by parsing methods to supply the key for verification.  The function receives the parsed, but
// unverified Token. This allows you to use properties in the Header of the token (such as `kid`) to identify which key
// to use.
type Keyfunc func(token *Token) (key any, err error)

var (
	// SignatureAlgorithmsNone contain all algorithms including 'none'.
	SignatureAlgorithmsNone = []jose.SignatureAlgorithm{JSONWebTokenAlgNone, jose.HS256, jose.HS384, jose.HS512, jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512, jose.EdDSA, jose.Ed25519}

	// SignatureAlgorithms contain all algorithms excluding 'none'. 'EdDSA' is the polymorphic identifier of RFC 8037
	// Section 3.1 and 'Ed25519' the fully-specified identifier of RFC 9864 Table 2. 'Ed448' is absent as
	// authelia.com/provider/jose has no Ed448 implementation.
	SignatureAlgorithms = []jose.SignatureAlgorithm{jose.HS256, jose.HS384, jose.HS512, jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512, jose.EdDSA, jose.Ed25519}

	// EncryptionKeyAlgorithms contains all valid JWE's for OAuth 2.0 and OpenID Connect 1.0. 'RSA1_5' is absent as it
	// is only permitted when an EnableRSA15KeyManagementProvider enables it.
	EncryptionKeyAlgorithms = []jose.KeyAlgorithm{jose.RSA_OAEP, jose.RSA_OAEP_256, jose.A128KW, jose.A192KW, jose.A256KW, jose.DIRECT, jose.ECDH_ES, jose.ECDH_ES_A128KW, jose.ECDH_ES_A192KW, jose.ECDH_ES_A256KW, jose.A128GCMKW, jose.A192GCMKW, jose.A256GCMKW, jose.PBES2_HS256_A128KW, jose.PBES2_HS384_A192KW, jose.PBES2_HS512_A256KW}

	// ContentEncryptionAlgorithms contains all valid JWE content encryption algorithms for OAuth 2.0 and OpenID Connect 1.0.
	ContentEncryptionAlgorithms = []jose.ContentEncryption{jose.A128CBC_HS256, jose.A192CBC_HS384, jose.A256CBC_HS512, jose.A128GCM, jose.A192GCM, jose.A256GCM}
)

const (
	// ClaimJWTID is the jti claim name.
	ClaimJWTID = consts.ClaimJWTID
	// ClaimSessionID is the sid claim name.
	ClaimSessionID = consts.ClaimSessionID
	// ClaimIssuedAt is the iat claim name.
	ClaimIssuedAt = consts.ClaimIssuedAt
	// ClaimNotBefore is the nbf claim name.
	ClaimNotBefore = consts.ClaimNotBefore
	// ClaimRequestedAt is the rat claim name.
	ClaimRequestedAt = consts.ClaimRequestedAt
	// ClaimExpirationTime is the exp claim name.
	ClaimExpirationTime = consts.ClaimExpirationTime
	// ClaimAuthenticationTime is the auth_time claim name.
	ClaimAuthenticationTime = consts.ClaimAuthenticationTime
	// ClaimIssuer is the iss claim name.
	ClaimIssuer = consts.ClaimIssuer
	// ClaimSubject is the sub claim name.
	ClaimSubject = consts.ClaimSubject
	// ClaimAudience is the aud claim name.
	ClaimAudience = consts.ClaimAudience
	// ClaimGroups is the groups claim name.
	ClaimGroups = consts.ClaimGroups
	// ClaimFullName is the name claim name.
	ClaimFullName = consts.ClaimFullName
	// ClaimPreferredUsername is the preferred_username claim name.
	ClaimPreferredUsername = consts.ClaimPreferredUsername
	// ClaimPreferredEmail is the email claim name.
	ClaimPreferredEmail = consts.ClaimPreferredEmail
	// ClaimEmailVerified is the email_verified claim name.
	ClaimEmailVerified = consts.ClaimEmailVerified
	// ClaimAuthorizedParty is the azp claim name.
	ClaimAuthorizedParty = consts.ClaimAuthorizedParty
	// ClaimAuthenticationContextClassReference is the acr claim name.
	ClaimAuthenticationContextClassReference = consts.ClaimAuthenticationContextClassReference
	// ClaimAuthenticationMethodsReference is the amr claim name.
	ClaimAuthenticationMethodsReference = consts.ClaimAuthenticationMethodsReference
	// ClaimClientIdentifier is the client_id claim name.
	ClaimClientIdentifier = consts.ClaimClientIdentifier
	// ClaimScope is the scope claim name.
	ClaimScope = consts.ClaimScope
	// ClaimScopeNonStandard is the scp claim name.
	ClaimScopeNonStandard = consts.ClaimScopeNonStandard
	// ClaimExtra is the ext claim name.
	ClaimExtra = consts.ClaimExtra
	// ClaimActive is the active claim name.
	ClaimActive = consts.ClaimActive
	// ClaimUsername is the username claim name.
	ClaimUsername = consts.ClaimUsername
	// ClaimTokenIntrospection is the token_introspection claim name.
	ClaimTokenIntrospection = consts.ClaimTokenIntrospection
	// ClaimAccessTokenHash is the at_hash claim name.
	ClaimAccessTokenHash = consts.ClaimAccessTokenHash
	// ClaimCodeHash is the c_hash claim name.
	ClaimCodeHash = consts.ClaimCodeHash
	// ClaimStateHash is the s_hash claim name.
	ClaimStateHash = consts.ClaimStateHash
	// ClaimNonce is the nonce claim name.
	ClaimNonce = consts.ClaimNonce
	// ClaimAuthorizedActor is the may_act claim name.
	ClaimAuthorizedActor = consts.ClaimAuthorizedActor
	// ClaimActor is the act claim name.
	ClaimActor = consts.ClaimActor
	// ClaimEvents is the events claim name.
	ClaimEvents = consts.ClaimEvents
	// ClaimSubjectIdentifier is the sub_id claim name.
	ClaimSubjectIdentifier = consts.ClaimSubjectIdentifier
	// ClaimTransaction is the txn claim name.
	ClaimTransaction = consts.ClaimTransaction
	// ClaimEventBackChannelLogout is the back-channel logout event identifier used as a key of the events claim.
	ClaimEventBackChannelLogout = consts.ClaimEventBackChannelLogout
	// ClaimConfirmation is the cnf claim name.
	ClaimConfirmation = consts.ClaimConfirmation
	// ClaimAuthorizationDetails is the authorization_details claim name.
	ClaimAuthorizationDetails = consts.ClaimAuthorizationDetails
	// ClaimConfirmationJWKThumbprint is the jkt claim name.
	ClaimConfirmationJWKThumbprint = consts.ClaimConfirmationJWKThumbprint
	// ClaimConfirmationX509SHA256Thumbprint is the x5t#S256 claim name.
	ClaimConfirmationX509SHA256Thumbprint = consts.ClaimConfirmationX509SHA256Thumbprint
	// ClaimHTTPMethod is the htm claim name.
	ClaimHTTPMethod = consts.ClaimHTTPMethod
	// ClaimHTTPURI is the htu claim name.
	ClaimHTTPURI = consts.ClaimHTTPURI
	// ClaimDPoPAccessTokenHash is the ath claim name.
	ClaimDPoPAccessTokenHash = consts.ClaimDPoPAccessTokenHash
	// ClaimConfirmationJWK is the jwk claim name.
	ClaimConfirmationJWK = consts.ClaimConfirmationJWK
	// ClaimDPoPCodeHash is the c_s256 claim name.
	ClaimDPoPCodeHash = consts.ClaimDPoPCodeHash
)

const (
	// JSONWebTokenHeaderKeyIdentifier is the kid header parameter name.
	JSONWebTokenHeaderKeyIdentifier = consts.JSONWebTokenHeaderKeyIdentifier
	// JSONWebTokenHeaderAlgorithm is the alg header parameter name.
	JSONWebTokenHeaderAlgorithm = consts.JSONWebTokenHeaderAlgorithm
	// JSONWebTokenHeaderEncryptionAlgorithm is the enc header parameter name.
	JSONWebTokenHeaderEncryptionAlgorithm = consts.JSONWebTokenHeaderEncryptionAlgorithm
	// JSONWebTokenHeaderCompressionAlgorithm is the zip header parameter name.
	JSONWebTokenHeaderCompressionAlgorithm = consts.JSONWebTokenHeaderCompressionAlgorithm
	// JSONWebTokenHeaderPBES2Count is the p2c header parameter name.
	JSONWebTokenHeaderPBES2Count = consts.JSONWebTokenHeaderPBES2Count

	// JSONWebTokenHeaderType is the typ header parameter name.
	JSONWebTokenHeaderType = consts.JSONWebTokenHeaderType
	// JSONWebTokenHeaderContentType is the cty header parameter name.
	JSONWebTokenHeaderContentType = consts.JSONWebTokenHeaderContentType
)

const (
	// JSONWebTokenUseSignature is the sig public key use value.
	JSONWebTokenUseSignature = consts.JSONWebTokenUseSignature
	// JSONWebTokenUseEncryption is the enc public key use value.
	JSONWebTokenUseEncryption = consts.JSONWebTokenUseEncryption
)

const (
	// JSONWebTokenTypeJWT is the JWT type header value.
	JSONWebTokenTypeJWT = consts.JSONWebTokenTypeJWT

	// JSONWebTokenTypeAccessToken represents the JWT type value for a JWT Profile Access Token.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc9068#section-2.1
	JSONWebTokenTypeAccessToken = consts.JSONWebTokenTypeAccessToken

	// JSONWebTokenTypeLogoutToken represents the JWT type value for OpenID Connect Back-Channel Logout 1.0.
	//
	// See: https://openid.net/specs/openid-connect-backchannel-1_0.html#Security
	JSONWebTokenTypeLogoutToken = consts.JSONWebTokenTypeLogoutToken

	// JSONWebTokenTypeJWTSecuredAuthorizationRequest represents the JWT type value for JWT Secured Authorization Requests.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9101.html#section-4
	JSONWebTokenTypeJWTSecuredAuthorizationRequest = consts.JSONWebTokenTypeJWTSecuredAuthorizationRequest

	// JSONWebTokenTypeClientAuthentication represents the JWT type value for Client Assertions.
	//
	// See: https://www.rfc-editor.org/rfc/rfc10070#section-4
	JSONWebTokenTypeClientAuthentication = consts.JSONWebTokenTypeClientAuthentication

	// JSONWebTokenTypeTokenIntrospection represents the JWT type value for a JWT Response for OAuth Token Introspection.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9701.html#section-5
	JSONWebTokenTypeTokenIntrospection = consts.JSONWebTokenTypeTokenIntrospection

	// JSONWebTokenTypeDPoP represents the JWT type value for a DPoP proof JWT.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9449#section-4.2
	JSONWebTokenTypeDPoP = consts.JSONWebTokenTypeDPoP

	// JSONWebTokenTypeDPoPIDToken represents the JWT type value for a key-bound ID Token.
	//
	// See: https://openid.net/specs/openid-connect-key-binding-1_0.html#section-4
	JSONWebTokenTypeDPoPIDToken = consts.JSONWebTokenTypeDPoPIDToken

	// JSONWebTokenTypeSecurityEventToken represents the JWT type value for a Security Event Token.
	//
	// See: https://www.rfc-editor.org/rfc/rfc8417.html#section-2.3
	JSONWebTokenTypeSecurityEventToken = consts.JSONWebTokenTypeSecurityEventToken
)

const (
	// JSONWebTokenAlgNone is the none algorithm value, meaning an unsecured JWT.
	JSONWebTokenAlgNone = consts.JSONWebTokenAlgNone
)
