// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/base64"
	"errors"
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

// IssueAccessToken generates an access token, persists its session, and populates the response. It returns the
// signature of the issued access token so callers can associate a refresh token with it.
func (h *HandleHelper) IssueAccessToken(ctx context.Context, defaultLifespan time.Duration, request oauth2.AccessRequester, response oauth2.AccessResponder) (signature string, err error) {
	var token string

	if token, signature, err = h.AccessTokenStrategy.GenerateAccessToken(ctx, request); err != nil {
		return "", err
	}

	if err = h.AccessTokenStorage.CreateAccessTokenSession(ctx, signature, request.Sanitize([]string{})); err != nil {
		return "", err
	}

	response.SetAccessToken(token)
	response.SetTokenType(oauth2.BearerAccessToken)
	response.SetExpiresIn(getExpiresIn(request, oauth2.AccessToken, defaultLifespan, time.Now().UTC()))
	response.SetScopes(request.GetGrantedScopes())

	return signature, nil
}

//nolint:unparam
func getExpiresIn(r oauth2.Requester, key oauth2.TokenType, defaultLifespan time.Duration, now time.Time) time.Duration {
	if r.GetSession().GetExpiresAt(key).IsZero() {
		return defaultLifespan
	}
	return time.Duration(r.GetSession().GetExpiresAt(key).UnixNano() - now.UnixNano())
}

// IsIntactToken reports whether a token validation error leaves the token intact: it validated, or it failed only
// because it expired. A replayed token must be intact before the grant it belongs to is revoked.
//
// See: https://datatracker.ietf.org/doc/html/rfc9700#section-4.14.2
func IsIntactToken(err error) bool {
	return err == nil || errors.Is(err, oauth2.ErrTokenExpired) || errors.Is(err, oauth2.ErrDeviceExpiredToken)
}

// IsTokenRejection reports whether a token validation error rejects the token presented by the client, as opposed to
// a server error that must be answered as one.
func IsTokenRejection(err error) bool {
	var (
		rfc     *oauth2.RFC6749Error
		corrupt base64.CorruptInputError
	)

	switch {
	case errors.As(err, &corrupt):
		return true
	case errors.As(err, &rfc):
		return !errors.Is(err, oauth2.ErrServerError)
	default:
		return false
	}
}
