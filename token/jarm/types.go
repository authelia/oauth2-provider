package jarm

import (
	"context"
	"time"

	"authelia.com/provider/oauth2/token/jwt"
)

type Configurator interface {
	GetJWTSecuredAuthorizeResponseModeIssuer(ctx context.Context) string
	GetJWTSecuredAuthorizeResponseModeSigner(ctx context.Context) jwt.Signer
	GetJWTSecuredAuthorizeResponseModeLifespan(ctx context.Context) time.Duration
}

type Client interface {
	// GetID returns the client ID.
	GetID() (id string)

	IsPublic() (public bool)

	// GetAuthorizationSignedResponseKeyID returns the specific key identifier used to satisfy JWS requirements of the
	// JWT-secured Authorization Response Method (JARM) specifications. If unspecified the other available parameters
	// will be utilized to select an appropriate key.
	GetAuthorizationSignedResponseKeyID() (kid string)

	// GetAuthorizationSignedResponseAlg is equivalent to the 'authorization_signed_response_alg' client metadata
	// value which determines the JWS [RFC7515] alg algorithm JWA [RFC7518] REQUIRED for signing authorization
	// responses. If this is specified, the response will be signed using JWS and the configured algorithm. The
	// algorithm none is not allowed. The default, if omitted, is RS256.
	GetAuthorizationSignedResponseAlg() (alg string)

	// GetAuthorizationEncryptedResponseKeyID returns the specific key identifier used to satisfy JWE requirements of
	// the JWT-secured Authorization Response Method (JARM) specifications. If unspecified the other available parameters will be
	// utilized to select an appropriate key.
	GetAuthorizationEncryptedResponseKeyID() (kid string)

	// GetAuthorizationEncryptedResponseAlg is equivalent to the 'authorization_encrypted_response_alg' client metadata
	// value which determines the JWE [RFC7516] alg algorithm JWA [RFC7518] REQUIRED for encrypting authorization
	// responses. If both signing and encryption are requested, the response will be signed then encrypted, with the
	// result being a Nested JWT, as defined in JWT [RFC7519]. The default, if omitted, is that no encryption is
	// performed.
	GetAuthorizationEncryptedResponseAlg() (alg string)

	// GetAuthorizationEncryptedResponseEnc is equivalent to the 'authorization_encrypted_response_enc' client
	// metadata value which determines the JWE [RFC7516] enc algorithm JWA [RFC7518] REQUIRED for encrypting
	// authorization responses. If authorization_encrypted_response_alg is specified, the default for this value is
	// A128CBC-HS256. When authorization_encrypted_response_enc is included, authorization_encrypted_response_alg MUST
	// also be provided.
	GetAuthorizationEncryptedResponseEnc() (alg string)
}

type OpenIDSession interface {
	IDTokenHeaders() *jwt.Headers
	IDTokenClaims() *jwt.IDTokenClaims
}

type JWTSessionContainer interface {
	GetJWTHeader() *jwt.Headers
	GetJWTClaims() jwt.JWTClaimsContainer
}
