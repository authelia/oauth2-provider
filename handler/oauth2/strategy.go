// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/token/jwt"
)

// NewCoreStrategy is a special constructor that if provided a signer will automatically decorate the HMACCoreStrategy
// with a JWTProfileCoreStrategy, otherwise it just returns the HMACCoreStrategy.
func NewCoreStrategy(config CoreStrategyConfigurator, prefix string, strategy jwt.Strategy) (core CoreStrategy) {
	if strategy == nil {
		return NewHMACCoreStrategy(config, prefix)
	}

	return &JWTProfileCoreStrategy{
		Strategy:         strategy,
		HMACCoreStrategy: NewHMACCoreStrategy(config, prefix),
		Config:           config,
	}
}

// CoreStrategy performs the major elements of token generation and validation.
type CoreStrategy interface {
	AccessTokenStrategy
	RefreshTokenStrategy
	AuthorizeCodeStrategy
	DeviceCodeStrategy
	UserCodeStrategy
}

type AccessTokenStrategy interface {
	// IsOpaqueAccessToken returns true if the provided token is possibly an opaque Access Token.
	//
	// This function is only effective if the token provided has a deterministic characteristic such as a prefix.
	IsOpaqueAccessToken(ctx context.Context, token string) (is bool)

	// AccessTokenSignature returns the signature of the provided Access Token.
	AccessTokenSignature(ctx context.Context, token string) (signature string)

	// GenerateAccessToken generates a new Access Token.
	GenerateAccessToken(ctx context.Context, requester oauth2.Requester) (token string, signature string, err error)

	// ValidateAccessToken validates the provided Access Token.
	ValidateAccessToken(ctx context.Context, requester oauth2.Requester, token string) (err error)
}

type RefreshTokenStrategy interface {
	// IsOpaqueRefreshToken returns true if the provided token is possibly an opaque Refresh Token.
	//
	// This function is only effective if the token provided has a deterministic characteristic such as a prefix.
	IsOpaqueRefreshToken(ctx context.Context, token string) (is bool)

	// RefreshTokenSignature returns the signature of the provided Refresh Token.
	RefreshTokenSignature(ctx context.Context, token string) (signature string)

	// GenerateRefreshToken generates a new Refresh Token.
	GenerateRefreshToken(ctx context.Context, requester oauth2.Requester) (token string, signature string, err error)

	// ValidateRefreshToken validates the provided Refresh Token.
	ValidateRefreshToken(ctx context.Context, requester oauth2.Requester, token string) (err error)
}

type AuthorizeCodeStrategy interface {
	// IsOpaqueAuthorizeCode returns true if the provided token is possibly an opaque Authorize Code.
	//
	// This function is only effective if the token provided has a deterministic characteristic such as a prefix.
	IsOpaqueAuthorizeCode(ctx context.Context, token string) bool

	// AuthorizeCodeSignature returns the signature of the provided Authorize Code.
	AuthorizeCodeSignature(ctx context.Context, token string) (signature string)

	// GenerateAuthorizeCode generates a new Authorize Code.
	GenerateAuthorizeCode(ctx context.Context, requester oauth2.Requester) (token string, signature string, err error)

	// ValidateAuthorizeCode validates the provided Authorize Code.
	ValidateAuthorizeCode(ctx context.Context, requester oauth2.Requester, token string) (err error)
}

type DeviceCodeStrategy interface {
	// IsOpaqueRFC8628DeviceCode returns true if the provided token is possibly an opaque RFC8628 Device Code.
	//
	// This function is only effective if the token provided has a deterministic characteristic such as a prefix.
	IsOpaqueRFC8628DeviceCode(ctx context.Context, token string) (is bool)

	// RFC8628DeviceCodeSignature returns the signature of the provided RFC8628 Device Code.
	RFC8628DeviceCodeSignature(ctx context.Context, code string) (signature string, err error)

	// GenerateRFC8628DeviceCode generates a new RFC8628 Device Code.
	GenerateRFC8628DeviceCode(ctx context.Context) (code string, signature string, err error)

	// ValidateRFC8628DeviceCode validates the provided RFC8628 Device Code.
	ValidateRFC8628DeviceCode(ctx context.Context, r oauth2.Requester, code string) (err error)
}

type UserCodeStrategy interface {
	// RFC8628UserCodeSignature returns the signature of the provided RFC8628 User Code.
	RFC8628UserCodeSignature(ctx context.Context, code string) (signature string, err error)

	// GenerateRFC8628UserCode generates a new RFC8628 User Code.
	GenerateRFC8628UserCode(ctx context.Context) (code string, signature string, err error)

	// ValidateRFC8628UserCode validates the provided RFC8628 User Code.
	ValidateRFC8628UserCode(ctx context.Context, r oauth2.Requester, code string) (err error)
}
