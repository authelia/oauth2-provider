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
	GetID() string
	GetAuthorizationSignedResponseKeyID() (kid string)
	GetAuthorizationSignedResponseAlg() (alg string)
	GetAuthorizationEncryptedResponseAlg() (alg string)
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
