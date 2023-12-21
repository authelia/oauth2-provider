package consts

const (
	PromptTypeNone          = valueNone
	PromptTypeLogin         = "login"
	PromptTypeConsent       = "consent"
	PromptTypeSelectAccount = "select_account"
)

// Proof Key Code Exchange Challenge Method strings.
const (
	PKCEChallengeMethodPlain  = "plain"
	PKCEChallengeMethodSHA256 = "S256"
)

const (
	ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

const (
	PrefixRequestURI = "urn:ietf:params:oauth:request_uri:"
)

const (
	TokenTypeAccessToken  = "access_token"
	TokenTypeRefreshToken = "refresh_token"
)
