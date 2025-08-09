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
	JSONWebTokenTypeJWT                            = "JWT"
	JSONWebTokenTypeAccessToken                    = "at+jwt"
	JSONWebTokenTypeLogoutToken                    = "logout+jwt"
	JSONWebTokenTypeJWTSecuredAuthorizationRequest = "oauth-authz-req+jwt" //nolint:gosec // This is a credential type, not a credential.
	JSONWebTokenTypeAccessTokenAlternative         = "application/at+jwt"
	JSONWebTokenTypeTokenIntrospection             = "token-introspection+jwt"
)

const (
	JSONWebTokenAlgNone       = valueNone
	JSONWebTokenAlgHMACSHA256 = "HS256"
	JSONWebTokenAlgHMACSHA384 = "HS384"
	JSONWebTokenAlgHMACSHA512 = "HS512"
)
