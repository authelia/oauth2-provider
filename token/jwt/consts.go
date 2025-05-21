package jwt

import (
	"github.com/go-jose/go-jose/v4"

	"authelia.com/provider/oauth2/internal/consts"
)

const (
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
	SignatureAlgorithmsNone = []jose.SignatureAlgorithm{JSONWebTokenAlgNone, jose.HS256, jose.HS384, jose.HS512, jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512}

	// SignatureAlgorithms contain all algorithms excluding 'none'.
	SignatureAlgorithms = []jose.SignatureAlgorithm{jose.HS256, jose.HS384, jose.HS512, jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512}

	// EncryptionKeyAlgorithms contains all valid JWE's for OAuth 2.0 and OpenID Connect 1.0.
	EncryptionKeyAlgorithms = []jose.KeyAlgorithm{jose.RSA1_5, jose.RSA_OAEP, jose.RSA_OAEP_256, jose.A128KW, jose.A192KW, jose.A256KW, jose.DIRECT, jose.ECDH_ES, jose.ECDH_ES_A128KW, jose.ECDH_ES_A192KW, jose.ECDH_ES_A256KW, jose.A128GCMKW, jose.A192GCMKW, jose.A256GCMKW, jose.PBES2_HS256_A128KW, jose.PBES2_HS384_A192KW, jose.PBES2_HS512_A256KW}

	ContentEncryptionAlgorithms = []jose.ContentEncryption{jose.A128CBC_HS256, jose.A192CBC_HS384, jose.A256CBC_HS512, jose.A128GCM, jose.A192GCM, jose.A256GCM}
)

const (
	ClaimJWTID                               = consts.ClaimJWTID
	ClaimSessionID                           = consts.ClaimSessionID
	ClaimIssuedAt                            = consts.ClaimIssuedAt
	ClaimNotBefore                           = consts.ClaimNotBefore
	ClaimRequestedAt                         = consts.ClaimRequestedAt
	ClaimExpirationTime                      = consts.ClaimExpirationTime
	ClaimAuthenticationTime                  = consts.ClaimAuthenticationTime
	ClaimIssuer                              = consts.ClaimIssuer
	ClaimSubject                             = consts.ClaimSubject
	ClaimAudience                            = consts.ClaimAudience
	ClaimGroups                              = consts.ClaimGroups
	ClaimFullName                            = consts.ClaimFullName
	ClaimPreferredUsername                   = consts.ClaimPreferredUsername
	ClaimPreferredEmail                      = consts.ClaimPreferredEmail
	ClaimEmailVerified                       = consts.ClaimEmailVerified
	ClaimAuthorizedParty                     = consts.ClaimAuthorizedParty
	ClaimAuthenticationContextClassReference = consts.ClaimAuthenticationContextClassReference
	ClaimAuthenticationMethodsReference      = consts.ClaimAuthenticationMethodsReference
	ClaimClientIdentifier                    = consts.ClaimClientIdentifier
	ClaimScope                               = consts.ClaimScope
	ClaimScopeNonStandard                    = consts.ClaimScopeNonStandard
	ClaimExtra                               = consts.ClaimExtra
	ClaimActive                              = consts.ClaimActive
	ClaimUsername                            = consts.ClaimUsername
	ClaimTokenIntrospection                  = consts.ClaimTokenIntrospection
	ClaimAccessTokenHash                     = consts.ClaimAccessTokenHash
	ClaimCodeHash                            = consts.ClaimCodeHash
	ClaimStateHash                           = consts.ClaimStateHash
	ClaimNonce                               = consts.ClaimNonce
	ClaimAuthorizedActor                     = consts.ClaimAuthorizedActor
	ClaimActor                               = consts.ClaimActor
	ClaimEvents                              = consts.ClaimEvents
	ClaimEventBackChannelLogout              = consts.ClaimEventBackChannelLogout
)

const (
	JSONWebTokenHeaderKeyIdentifier        = consts.JSONWebTokenHeaderKeyIdentifier
	JSONWebTokenHeaderAlgorithm            = consts.JSONWebTokenHeaderAlgorithm
	JSONWebTokenHeaderEncryptionAlgorithm  = consts.JSONWebTokenHeaderEncryptionAlgorithm
	JSONWebTokenHeaderCompressionAlgorithm = consts.JSONWebTokenHeaderCompressionAlgorithm
	JSONWebTokenHeaderPBES2Count           = consts.JSONWebTokenHeaderPBES2Count

	JSONWebTokenHeaderType        = consts.JSONWebTokenHeaderType
	JSONWebTokenHeaderContentType = consts.JSONWebTokenHeaderContentType
)

const (
	JSONWebTokenUseSignature  = consts.JSONWebTokenUseSignature
	JSONWebTokenUseEncryption = consts.JSONWebTokenUseEncryption
)

const (
	JSONWebTokenTypeJWT                    = consts.JSONWebTokenTypeJWT
	JSONWebTokenTypeAccessToken            = consts.JSONWebTokenTypeAccessToken
	JSONWebTokenTypeAccessTokenAlternative = consts.JSONWebTokenTypeAccessTokenAlternative
	JSONWebTokenTypeTokenIntrospection     = consts.JSONWebTokenTypeTokenIntrospection
)

const (
	JSONWebTokenAlgNone = consts.JSONWebTokenAlgNone
)
