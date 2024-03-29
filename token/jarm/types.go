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
	GetID() string

	// GetAuthorizationSignedResponseKeyID returns the 'authorization_signed_response_alg' key identifier instead of
	// using the alg.
	GetAuthorizationSignedResponseKeyID() (kid string)

	// GetAuthorizationSignedResponseAlg returns the 'authorization_signed_response_alg' value.
	GetAuthorizationSignedResponseAlg() (alg string)

	// GetAuthorizationEncryptedResponseAlg returns the 'authorization_encrypted_response_alg' value.
	GetAuthorizationEncryptedResponseAlg() (alg string)

	// GetAuthorizationEncryptedResponseEncryptionAlg returns the 'authorization_encrypted_response_enc' value.
	GetAuthorizationEncryptedResponseEncryptionAlg() (alg string)
}

type OpenIDSession interface {
	IDTokenHeaders() *jwt.Headers
	IDTokenClaims() *jwt.IDTokenClaims
}

type JWTSessionContainer interface {
	GetJWTHeader() *jwt.Headers
	GetJWTClaims() jwt.JWTClaimsContainer
}
