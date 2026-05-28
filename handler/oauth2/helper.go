// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"time"

	"authelia.com/provider/oauth2"
)

type HandleHelperConfigProvider interface {
	oauth2.AccessTokenLifespanProvider
	oauth2.RefreshTokenLifespanProvider
}

type HandleHelper struct {
	AccessTokenStrategy AccessTokenStrategy
	AccessTokenStorage  AccessTokenStorage
	Config              HandleHelperConfigProvider
}

func (h *HandleHelper) IssueAccessToken(ctx context.Context, defaultLifespan time.Duration, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
	var token, signature string

	if token, signature, err = h.AccessTokenStrategy.GenerateAccessToken(ctx, request); err != nil {
		return err
	}

	if err = h.AccessTokenStorage.CreateAccessTokenSession(ctx, signature, request.Sanitize([]string{})); err != nil {
		return err
	}

	response.SetAccessToken(token)
	response.SetTokenType(oauth2.BearerAccessToken)
	response.SetExpiresIn(getExpiresIn(request, oauth2.AccessToken, defaultLifespan, time.Now().UTC()))
	response.SetScopes(request.GetGrantedScopes())

	return nil
}

//nolint:unparam
func getExpiresIn(r oauth2.Requester, key oauth2.TokenType, defaultLifespan time.Duration, now time.Time) time.Duration {
	if r.GetSession().GetExpiresAt(key).IsZero() {
		return defaultLifespan
	}
	return time.Duration(r.GetSession().GetExpiresAt(key).UnixNano() - now.UnixNano())
}
