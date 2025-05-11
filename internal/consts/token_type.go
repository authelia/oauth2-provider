package consts

const (
	TokenTypeAccessToken  = "access_token"
	TokenTypeRefreshToken = "refresh_token"
)

const (
	TokenTypeRFC8693AccessToken  = "urn:ietf:params:oauth:token-type:access_token"  //nolint:gosec // This is a credential type, not a credential.
	TokenTypeRFC8693RefreshToken = "urn:ietf:params:oauth:token-type:refresh_token" //nolint:gosec // This is a credential type, not a credential.
	TokenTypeRFC8693IDToken      = "urn:ietf:params:oauth:token-type:id_token"      //nolint:gosec // This is a credential type, not a credential.
	TokenTypeRFC8693JWT          = "urn:ietf:params:oauth:token-type:jwt"           //nolint:gosec // This is a credential type, not a credential.
)
