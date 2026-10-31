// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestTokenExchangeReadsTheJWTSessionOfASubjectToken(t *testing.T) {
	kinds := []struct {
		name      string
		tokenType string
		mint      func(ctx context.Context, strategy hoauth2.CoreStrategy, store rfc8693ExchangeStore, client oauth2.Client, session *hoauth2.JWTSession) string
		handler   func(config *oauth2.Config, strategy hoauth2.CoreStrategy, store rfc8693ExchangeStore) oauth2.TokenEndpointHandler
	}{
		{
			name:      "AccessToken",
			tokenType: consts.TokenTypeRFC8693AccessToken,
			mint:      mintJWTSessionAccessToken,
			handler: func(config *oauth2.Config, strategy hoauth2.CoreStrategy, store rfc8693ExchangeStore) oauth2.TokenEndpointHandler {
				return &AccessTokenTypeHandler{
					Config:               config,
					AccessTokenLifespan:  5 * time.Minute,
					RefreshTokenLifespan: 5 * time.Minute,
					CoreStrategy:         strategy,
					ScopeStrategy:        config.ScopeStrategy,
					Storage:              store,
				}
			},
		},
		{
			name:      "RefreshToken",
			tokenType: consts.TokenTypeRFC8693RefreshToken,
			mint:      mintJWTSessionRefreshToken,
			handler: func(config *oauth2.Config, strategy hoauth2.CoreStrategy, store rfc8693ExchangeStore) oauth2.TokenEndpointHandler {
				return &RefreshTokenTypeHandler{
					Config:               config,
					RefreshTokenLifespan: 24 * time.Hour,
					CoreStrategy:         strategy,
					ScopeStrategy:        config.ScopeStrategy,
					Storage:              store,
				}
			},
		},
	}

	for _, sc := range bindingExchangeStores() {
		for _, kind := range kinds {
			t.Run(sc.name+"/"+kind.name, func(t *testing.T) {
				exchange := func(t *testing.T, session *hoauth2.JWTSession) (*DefaultSession, error) {
					t.Helper()

					store := sc.newStore()
					config, strategy := newBindingExchangeConfig()
					client := store.GetClients()["my-client"]
					if kind.tokenType == consts.TokenTypeRFC8693AccessToken {
						client = store.GetClients()["custom-lifespan-client"]
					}

					request := newLifetimeExchangeRequest(store, kind.tokenType, kind.mint(t.Context(), strategy, store, client, session), "")

					return request.GetSession().(*DefaultSession), kind.handler(config, strategy, store).HandleTokenEndpointRequest(t.Context(), request)
				}

				valid := time.Now().UTC().Add(time.Hour)

				t.Run("ShouldInheritADPoPBinding", func(t *testing.T) {
					session, err := exchange(t, &hoauth2.JWTSession{Subject: "peter", JWKThumbprint: bindingJKT, ExpiresAt: jwtSessionExpiry(valid)})

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
					assert.Equal(t, bindingJKT, session.GetDPoPJWKThumbprint())
				})

				t.Run("ShouldInheritACertificateBinding", func(t *testing.T) {
					session, err := exchange(t, &hoauth2.JWTSession{Subject: "peter", ClientCertificateThumbprint: bindingX5T, ExpiresAt: jwtSessionExpiry(valid)})

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
					assert.Equal(t, bindingX5T, session.GetClientCertificateSHA256Thumbprint())
				})

				t.Run("ShouldCarryTheSubjectTokenExpiry", func(t *testing.T) {
					session, err := exchange(t, &hoauth2.JWTSession{Subject: "peter", ExpiresAt: jwtSessionExpiry(valid)})

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
					assert.Equal(t, valid.Unix(), session.GetSubjectToken()[consts.ClaimExpirationTime])
				})

				t.Run("ShouldRejectAnExpiredToken", func(t *testing.T) {
					_, err := exchange(t, &hoauth2.JWTSession{Subject: "peter", ExpiresAt: jwtSessionExpiry(time.Now().UTC().Add(-time.Minute))})

					assert.Error(t, err)
				})
			})
		}
	}
}

func jwtSessionExpiry(expires time.Time) map[oauth2.TokenType]time.Time {
	return map[oauth2.TokenType]time.Time{oauth2.AccessToken: expires, oauth2.RefreshToken: expires}
}

func mintJWTSessionAccessToken(ctx context.Context, strategy hoauth2.CoreStrategy, store rfc8693ExchangeStore, client oauth2.Client, session *hoauth2.JWTSession) string {
	client = permittingOwner(client)

	request := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{"password"},
		Request:    oauth2.Request{ID: uuid.New().String(), RequestedAt: time.Now().UTC(), Session: session, Client: client},
	}

	grantFixtureAudience(request)

	token, signature, err := strategy.GenerateAccessToken(ctx, request)
	if err != nil {
		panic(err.Error())
	}

	if err = store.(hoauth2.AccessTokenStorage).CreateAccessTokenSession(ctx, signature, request.Sanitize([]string{})); err != nil {
		panic(err.Error())
	}

	return token
}

func mintJWTSessionRefreshToken(ctx context.Context, strategy hoauth2.CoreStrategy, store rfc8693ExchangeStore, client oauth2.Client, session *hoauth2.JWTSession) string {
	request := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{"password"},
		Request:    oauth2.Request{ID: uuid.New().String(), RequestedAt: time.Now().UTC(), Session: session, Client: client},
	}

	token, signature, err := strategy.GenerateRefreshToken(ctx, request)
	if err != nil {
		panic(err.Error())
	}

	if err = store.(hoauth2.TokenRevocationStorage).CreateRefreshTokenSession(ctx, signature, "", request.Sanitize([]string{})); err != nil {
		panic(err.Error())
	}

	return token
}
