package consts

// Client Auth SignatureAlgorithm strings.
const (
	ClientAuthMethodClientSecretBasic = "client_secret_basic"
	ClientAuthMethodClientSecretPost  = "client_secret_post"
	ClientAuthMethodClientSecretJWT   = "client_secret_jwt"
	ClientAuthMethodPrivateKeyJWT     = "private_key_jwt"
	ClientAuthMethodNone              = valueNone
)
