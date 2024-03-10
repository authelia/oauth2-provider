// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"

	"authelia.com/provider/oauth2"
)

type CoreStrategy interface {
	AccessTokenStrategy
	RefreshTokenStrategy
	AuthorizeCodeStrategy
	DeviceCodeStrategy
	UserCodeStrategy
}

type AccessTokenStrategy interface {
	AccessTokenSignature(ctx context.Context, token string) string
	GenerateAccessToken(ctx context.Context, requester oauth2.Requester) (token string, signature string, err error)
	ValidateAccessToken(ctx context.Context, requester oauth2.Requester, token string) (err error)
}

type RefreshTokenStrategy interface {
	RefreshTokenSignature(ctx context.Context, token string) string
	GenerateRefreshToken(ctx context.Context, requester oauth2.Requester) (token string, signature string, err error)
	ValidateRefreshToken(ctx context.Context, requester oauth2.Requester, token string) (err error)
}

type AuthorizeCodeStrategy interface {
	AuthorizeCodeSignature(ctx context.Context, token string) string
	GenerateAuthorizeCode(ctx context.Context, requester oauth2.Requester) (token string, signature string, err error)
	ValidateAuthorizeCode(ctx context.Context, requester oauth2.Requester, token string) (err error)
}

type DeviceCodeStrategy interface {
	RFC8628DeviceCodeSignature(ctx context.Context, code string) (signature string, err error)
	GenerateRFC8628DeviceCode(ctx context.Context) (code string, signature string, err error)
	ValidateRFC8628DeviceCode(ctx context.Context, r oauth2.Requester, code string) (err error)
}

type UserCodeStrategy interface {
	RFC8628UserCodeSignature(ctx context.Context, code string) (signature string, err error)
	GenerateRFC8628UserCode(ctx context.Context) (code string, signature string, err error)
	ValidateRFC8628UserCode(ctx context.Context, r oauth2.Requester, code string) (err error)
}
