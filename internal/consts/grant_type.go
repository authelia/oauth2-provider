package consts

// Grant Type strings.
const (
	GrantTypeImplicit                         = valueImplicit
	GrantTypeRefreshToken                     = valueRefreshToken
	GrantTypeAuthorizationCode                = "authorization_code"
	GrantTypeClientCredentials                = "client_credentials"
	GrantTypeResourceOwnerPasswordCredentials = valuePassword
	GrantTypeOAuthJWTBearer                   = "urn:ietf:params:oauth:grant-type:jwt-bearer" //nolint:gosec
)
