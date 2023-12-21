package consts

// Registered Claim strings. See https://www.iana.org/assignments/jwt/jwt.xhtml.
const (
	ClaimJWTID                               = "jti"
	ClaimSessionID                           = "sid"
	ClaimIssuedAt                            = "iat"
	ClaimNotBefore                           = "nbf"
	ClaimRequestedAt                         = "rat"
	ClaimExpirationTime                      = "exp"
	ClaimAuthenticationTime                  = "auth_time"
	ClaimIssuer                              = valueIss
	ClaimSubject                             = "sub"
	ClaimAudience                            = "aud"
	ClaimGroups                              = "groups"
	ClaimFullName                            = "name"
	ClaimPreferredUsername                   = "preferred_username"
	ClaimPreferredEmail                      = "email"
	ClaimEmailVerified                       = "email_verified"
	ClaimAuthorizedParty                     = "azp"
	ClaimAuthenticationContextClassReference = "acr"
	ClaimAuthenticationMethodsReference      = "amr"
	ClaimClientIdentifier                    = valueClientID
	ClaimScope                               = valueScope
	ClaimScopeNonStandard                    = "scp"
	ClaimExtra                               = "ext"
	ClaimActive                              = "active"
	ClaimUsername                            = "username"
	ClaimTokenIntrospection                  = "token_introspection"
	ClaimAccessTokenHash                     = "at_hash"
	ClaimCodeHash                            = "c_hash"
	ClaimNonce                               = valueNonce
)
