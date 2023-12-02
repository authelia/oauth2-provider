// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"time"

	"github.com/authelia/goauth2"
)

type HandleHelperConfigProvider interface {
	goauth2.AccessTokenLifespanProvider
	goauth2.RefreshTokenLifespanProvider
}

type HandleHelper struct {
	AccessTokenStrategy AccessTokenStrategy
	AccessTokenStorage  AccessTokenStorage
	Config              HandleHelperConfigProvider
}

func (h *HandleHelper) IssueAccessToken(ctx context.Context, defaultLifespan time.Duration, requester goauth2.AccessRequester, responder goauth2.AccessResponder) error {
	token, signature, err := h.AccessTokenStrategy.GenerateAccessToken(ctx, requester)
	if err != nil {
		return err
	} else if err := h.AccessTokenStorage.CreateAccessTokenSession(ctx, signature, requester.Sanitize([]string{})); err != nil {
		return err
	}

	responder.SetAccessToken(token)
	responder.SetTokenType("bearer")
	responder.SetExpiresIn(getExpiresIn(requester, goauth2.AccessToken, defaultLifespan, time.Now().UTC()))
	responder.SetScopes(requester.GetGrantedScopes())
	return nil
}

func getExpiresIn(r goauth2.Requester, key goauth2.TokenType, defaultLifespan time.Duration, now time.Time) time.Duration {
	if r.GetSession().GetExpiresAt(key).IsZero() {
		return defaultLifespan
	}
	return time.Duration(r.GetSession().GetExpiresAt(key).UnixNano() - now.UnixNano())
}
