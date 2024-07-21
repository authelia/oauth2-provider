package jwt

import (
	"github.com/go-jose/go-jose/v4"

	"authelia.com/provider/oauth2/internal/consts"
)

const (
	SigningMethodNone = jose.SignatureAlgorithm(consts.JSONWebTokenAlgNone)

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
	SignatureAlgorithmsNone = []jose.SignatureAlgorithm{consts.JSONWebTokenAlgNone, jose.HS256, jose.HS384, jose.HS512, jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512}

	// SignatureAlgorithms contain all algorithms excluding 'none'.
	SignatureAlgorithms = []jose.SignatureAlgorithm{jose.HS256, jose.HS384, jose.HS512, jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512}
)
