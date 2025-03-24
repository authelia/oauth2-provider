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
	JSONWebTokenTypeJWTSecuredAuthorizationRequest = "oauth-authz-req+jwt"
	JSONWebTokenTypeAccessTokenAlternative         = "application/at+jwt"
	JSONWebTokenTypeTokenIntrospection             = "token-introspection+jwt"
)

const (
	JSONWebTokenAlgNone = valueNone
)
