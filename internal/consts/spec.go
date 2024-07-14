package consts

const (
	PromptTypeNone          = valueNone
	PromptTypeLogin         = "login"
	PromptTypeConsent       = "consent"
	PromptTypeSelectAccount = "select_account"
)

// Proof Key Code Exchange Challenge SignatureAlgorithm strings.
const (
	PKCEChallengeMethodPlain  = "plain"
	PKCEChallengeMethodSHA256 = "S256"
)

const (
	ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" //nolint:gosec
)

const (
	PrefixRequestURI = "urn:ietf:params:oauth:request_uri:"
)

const (
	CodeDevice = valueDeviceCode
	CodeUser   = "user_code"
)
