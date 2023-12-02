// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"time"

	"github.com/authelia/goauth2"
	"github.com/authelia/goauth2/token/jwt"
)

type StatelessJWTValidator struct {
	jwt.Signer
	Config interface {
		goauth2.ScopeStrategyProvider
	}
}

// AccessTokenJWTToRequest tries to reconstruct goauth2.Request from a JWT.
func AccessTokenJWTToRequest(token *jwt.Token) goauth2.Requester {
	mapClaims := token.Claims
	claims := jwt.JWTClaims{}
	claims.FromMapClaims(mapClaims)

	requestedAt := claims.IssuedAt
	requestedAtClaim, ok := mapClaims["rat"]
	if ok {
		switch rat := requestedAtClaim.(type) {
		case float64:
			requestedAt = time.Unix(int64(rat), 0).UTC()
		case int64:
			requestedAt = time.Unix(rat, 0).UTC()
		}
	}

	clientId := ""
	clientIdClaim, ok := mapClaims["client_id"]
	if ok {
		switch id := clientIdClaim.(type) {
		case string:
			clientId = id
		}
	}

	return &goauth2.Request{
		RequestedAt: requestedAt,
		Client: &goauth2.DefaultClient{
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
			ExpiresAt: map[goauth2.TokenType]time.Time{
				goauth2.AccessToken: claims.ExpiresAt,
			},
			Subject: claims.Subject,
		},
		// We do not really know which audiences were requested, so we set them to granted.
		RequestedAudience: claims.Audience,
		GrantedAudience:   claims.Audience,
	}
}

func (v *StatelessJWTValidator) IntrospectToken(ctx context.Context, token string, tokenUse goauth2.TokenUse, accessRequest goauth2.AccessRequester, scopes []string) (goauth2.TokenUse, error) {
	t, err := validate(ctx, v.Signer, token)
	if err != nil {
		return "", err
	}

	// TODO: From here we assume it is an access token, but how do we know it is really and that is not an ID token?

	requester := AccessTokenJWTToRequest(t)

	if err := matchScopes(v.Config.GetScopeStrategy(ctx), requester.GetGrantedScopes(), scopes); err != nil {
		return goauth2.AccessToken, err
	}

	accessRequest.Merge(requester)

	return goauth2.AccessToken, nil
}
