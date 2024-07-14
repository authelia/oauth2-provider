package consts

const (
	JSONWebTokenHeaderKeyIdentifier       = "kid"
	JSONWebTokenHeaderAlgorithm           = "alg"
	JSONWebTokenHeaderEncryptionAlgorithm = "enc"

	JSONWebTokenHeaderUse         = "use"
	JSONWebTokenHeaderType        = "typ"
	JSONWebTokenHeaderContentType = "cty"
)

const (
	JSONWebTokenUseSignature  = "sig"
	JSONWebTokenUseEncryption = valueEnc
)

const (
	JSONWebTokenTypeJWT                = "JWT"
	JSONWebTokenTypeAccessToken        = "at+jwt"
	JSONWebTokenTypeTokenIntrospection = "token-introspection+jwt"
)

const (
	JSONWebTokenAlgNone = valueNone
)
