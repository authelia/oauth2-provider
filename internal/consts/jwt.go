package consts

const (
	JSONWebTokenHeaderKeyIdentifier        = "kid"
	JSONWebTokenHeaderAlgorithm            = "alg"
	JSONWebTokenHeaderEncryptionAlgorithm  = valueEnc
	JSONWebTokenHeaderCompressionAlgorithm = "zip"
	JSONWebTokenHeaderPBES2Count           = "p2c"

	JSONWebTokenHeaderType        = "typ"
	JSONWebTokenHeaderContentType = "cty"
)

const (
	JSONWebTokenUseSignature  = "sig"
	JSONWebTokenUseEncryption = valueEnc
)

const (
	JSONWebTokenTypeJWT = "JWT"

	// JSONWebTokenTypeAccessToken represents the JWT type value for a JWT Profile Access Token.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc9068#section-2.1
	JSONWebTokenTypeAccessToken = "at+jwt"

	// JSONWebTokenTypeLogoutToken represents the JWT type value for OpenID Connect Back-Channel Logout 1.0.
	//
	// See: https://openid.net/specs/openid-connect-backchannel-1_0.html#Security
	JSONWebTokenTypeLogoutToken = "logout+jwt"

	// JSONWebTokenTypeJWTSecuredAuthorizationRequest represents the JWT type value for JWT Secured Authorization Requests.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9101.html#section-4
	JSONWebTokenTypeJWTSecuredAuthorizationRequest = "oauth-authz-req+jwt" //nolint:gosec // This is a credential type, not a credential.

	// JSONWebTokenTypeClientAuthentication represents the JWT type value for Client Assertions.
	//
	// See: https://www.ietf.org/archive/id/draft-ietf-oauth-rfc7523bis-02.html#section-4
	JSONWebTokenTypeClientAuthentication = "client-authentication+jwt"

	// JSONWebTokenTypeTokenIntrospection represents the JWT type value for a JWT Response for OAuth Token Introspection.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9701.html#section-5
	JSONWebTokenTypeTokenIntrospection = "token-introspection+jwt"
)

const (
	JSONWebTokenAlgNone       = valueNone
	JSONWebTokenAlgHMACSHA256 = "HS256"
	JSONWebTokenAlgHMACSHA384 = "HS384"
	JSONWebTokenAlgHMACSHA512 = "HS512"
)
