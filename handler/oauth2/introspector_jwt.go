// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

type StatelessJWTValidator struct {
	jwt.Signer
	Config interface {
		oauth2.ScopeStrategyProvider
	}
}

func (v *StatelessJWTValidator) IntrospectToken(ctx context.Context, token string, tokenUse oauth2.TokenUse, accessRequest oauth2.AccessRequester, scopes []string) (oauth2.TokenUse, error) {
	t, err := validateJWT(ctx, v.Signer, token)
	if err != nil {
		return "", err
	}

	if !IsJWTProfileAccessToken(t) {
		return "", errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithDebug("The provided token is not a valid RFC9068 JWT Profile Access Token as it is missing the header 'typ' value of 'at+jwt' "))
	}

	requester := AccessTokenJWTToRequest(t)

	if err := matchScopes(v.Config.GetScopeStrategy(ctx), requester.GetGrantedScopes(), scopes); err != nil {
		return oauth2.AccessToken, err
	}

	accessRequest.Merge(requester)

	return oauth2.AccessToken, nil
}

// IsJWTProfileAccessToken validates a *jwt.Token is actually a RFC9068 JWT Profile Access Token by checking the
// relevant header as per https://datatracker.ietf.org/doc/html/rfc9068#section-2.1 which explicitly states that
// the header MUST include a typ of 'at+jwt' or 'application/at+jwt' with a preference of 'at+jwt'.
func IsJWTProfileAccessToken(token *jwt.Token) bool {
	var (
		raw any
		typ string
		ok  bool
	)

	if raw, ok = token.Header[jwt.JWTHeaderKeyValueType]; !ok {
		return false
	}

	typ, ok = raw.(string)

	return ok && (typ == jwt.JWTHeaderTypeValueAccessTokenJWT || typ == "application/at+jwt")
}

// AccessTokenJWTToRequest tries to reconstruct oauth2.Request from a JWT.
func AccessTokenJWTToRequest(token *jwt.Token) oauth2.Requester {
	mapClaims := token.Claims
	claims := jwt.JWTClaims{}
	claims.FromMapClaims(mapClaims)

	requestedAt := claims.IssuedAt
	requestedAtClaim, ok := mapClaims[consts.ClaimRequestedAt]
	if ok {
		switch rat := requestedAtClaim.(type) {
		case float64:
			requestedAt = time.Unix(int64(rat), 0).UTC()
		case int64:
			requestedAt = time.Unix(rat, 0).UTC()
		}
	}

	clientId := ""
	clientIdClaim, ok := mapClaims[consts.ClaimClientIdentifier]
	if ok {
		if id, ok := clientIdClaim.(string); ok {
			clientId = id
		}
	}

	return &oauth2.Request{
		RequestedAt: requestedAt,
		Client: &oauth2.DefaultClient{
			ID: clientId,
		},
		// We do not really know which scopes were requested, so we set them to granted.
		RequestedScope: claims.Scope,
		GrantedScope:   claims.Scope,
		Session: &JWTSession{
			JWTClaims: &claims,
			JWTHeader: &jwt.Headers{
				Extra: token.Header,
			},
			ExpiresAt: map[oauth2.TokenType]time.Time{
				oauth2.AccessToken: claims.ExpiresAt,
			},
			Subject: claims.Subject,
		},
		// We do not really know which audiences were requested, so we set them to granted.
		RequestedAudience: claims.Audience,
		GrantedAudience:   claims.Audience,
	}
}
