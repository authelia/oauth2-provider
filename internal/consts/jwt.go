package consts

const (
	JSONWebTokenHeaderKeyIdentifier = "kid"
	JSONWebTokenHeaderAlgorithm     = "alg"
	JSONWebTokenHeaderUse           = "use"
	JSONWebTokenHeaderType          = "typ"
)

const (
	JSONWebTokenUseSignature  = "sig"
	JSONWebTokenUseEncryption = "enc"
)

const (
	JSONWebTokenTypeJWT         = "JWT"
	JSONWebTokenTypeAccessToken = "at+jwt"
)
