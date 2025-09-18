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

type StatelessJWTStrategy interface {
	jwt.Strategy
	AccessTokenStrategy
	RefreshTokenStrategy
}

type StatelessJWTValidator struct {
	StatelessJWTStrategy
	Config interface {
		oauth2.ScopeStrategyProvider
	}
}

func (v *StatelessJWTValidator) IntrospectToken(ctx context.Context, tokenString string, tokenUse oauth2.TokenUse, requester oauth2.AccessRequester, scopes []string) (use oauth2.TokenUse, err error) {
	// This context value allows skipping the StatelessJWTValidator and continuing to the next.
	if val := ctx.Value(ContextKeySkipStatelessIntrospection); val != nil {
		if skip, ok := val.(bool); ok && skip {
			return "", oauth2.ErrUnknownRequest
		}
	}

	if v.IsOpaqueAccessToken(ctx, tokenString) || v.IsOpaqueRefreshToken(ctx, tokenString) {
		return "", oauth2.ErrUnknownRequest
	}

	var token *jwt.Token

	if token, err = validateJWT(ctx, v.StatelessJWTStrategy, jwt.NewStatelessJWTProfileIntrospectionClient(requester.GetClient()), tokenString); err != nil {
		return "", err
	}

	if err = token.Valid(jwt.ValidateTypes(jwt.JSONWebTokenTypeAccessToken)); err != nil {
		return "", errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithDebug("The provided token is not a valid RFC9068 JWT Profile Access Token as it is missing the header 'typ' value of 'at+jwt'."))
	}

	r := AccessTokenJWTToRequest(token)

	if err = matchScopes(v.Config.GetScopeStrategy(ctx), r.GetGrantedScopes(), scopes); err != nil {
		return oauth2.AccessToken, err
	}

	requester.Merge(r)

	return oauth2.AccessToken, nil
}

// AccessTokenJWTToRequest tries to reconstruct oauth2.Request from a JWT.
func AccessTokenJWTToRequest(token *jwt.Token) oauth2.Requester {
	mapClaims := token.Claims.ToMapClaims()
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

// SetSkipStatelessIntrospection sets the ContextKeySkipStatelessIntrospection to true.
func SetSkipStatelessIntrospection(ctx context.Context) context.Context {
	return context.WithValue(ctx, ContextKeySkipStatelessIntrospection, true)
}
