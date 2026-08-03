// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"time"

	"authelia.com/provider/oauth2"
)

type OpenIDConnectTokenStrategy interface {
	GenerateIDToken(ctx context.Context, lifespan time.Duration, request oauth2.Requester) (token string, err error)
}

type OpenIDConnectBackChannelLogoutTokenStrategy interface {
	GenerateBackChannelLogoutToken(ctx context.Context, client oauth2.Client, lifespan time.Duration, subject, sid string, audience []string, extra map[string]any) (token string, err error)
}

// TokenValidationStrategy is an alias of oauth2.TokenValidationStrategy. The interface lives in the root package
// because *Fosite methods need it and the root package cannot import this one.
type TokenValidationStrategy = oauth2.TokenValidationStrategy
