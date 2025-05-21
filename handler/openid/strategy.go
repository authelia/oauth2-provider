// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/token/jwt"
)

type OpenIDConnectTokenStrategy interface {
	GenerateIDToken(ctx context.Context, lifespan time.Duration, requester oauth2.Requester) (token string, err error)
}

type OpenIDConnectBackChannelLogoutTokenStrategy interface {
	GenerateBackChannelLogoutToken(ctx context.Context, client oauth2.Client, lifespan time.Duration, subject, sid string, audience []string, extra map[string]any) (token string, err error)
}

type TokenValidationStrategy interface {
	ValidateIDToken(ctx context.Context, requester oauth2.Requester, token string) (jwt.MapClaims, error)
}
