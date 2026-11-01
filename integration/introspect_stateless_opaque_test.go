// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestIntrospectOpaqueTokenWithStatelessIntrospector(t *testing.T) {
	type store interface {
		oauth2.Storage
		hoauth2.CoreStorage
	}

	stores := map[string]func() store{
		idjagStoreMemory:  func() store { return storage.NewMemoryStore() },
		idjagStoreHydrate: func() store { return storage.NewHydratingMemoryStore() },
	}

	orders := map[string][]compose.Factory{
		"CoreFirst":      {compose.OAuth2TokenIntrospectionFactory, compose.OAuth2StatelessJWTIntrospectionFactory},
		"StatelessFirst": {compose.OAuth2StatelessJWTIntrospectionFactory, compose.OAuth2TokenIntrospectionFactory},
	}

	prefixes := map[string]string{"Unprefixed": "", "Prefixed": "authelia_%s_"}

	for storeName, newStore := range stores {
		for orderName, factories := range orders {
			for prefixName, prefix := range prefixes {
				t.Run(storeName+"/"+orderName+"/"+prefixName, func(t *testing.T) {
					ctx := t.Context()

					config := &oauth2.Config{GlobalSecret: []byte("some-super-cool-secret-that-nobody-knows-nobody-knows")}
					s := newStore()
					core := hoauth2.NewHMACCoreStrategy(config, prefix)

					provider := compose.Compose(config, s, &compose.CommonStrategy{
						CoreStrategy: core,
						Strategy:     &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())},
					}, factories...)

					access, accessSignature, err := core.GenerateAccessToken(ctx, nil)
					require.NoError(t, err)

					refresh, refreshSignature, err := core.GenerateRefreshToken(ctx, nil)
					require.NoError(t, err)

					require.NoError(t, s.CreateAccessTokenSession(ctx, accessSignature, newStatelessOpaqueRequest()))
					require.NoError(t, s.CreateRefreshTokenSession(ctx, refreshSignature, accessSignature, newStatelessOpaqueRequest()))

					use, _, err := provider.IntrospectToken(ctx, access, oauth2.AccessToken, &oauth2.DefaultSession{})
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
					assert.Equal(t, oauth2.AccessToken, use)

					use, _, err = provider.IntrospectToken(ctx, refresh, oauth2.RefreshToken, &oauth2.DefaultSession{})
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
					assert.Equal(t, oauth2.RefreshToken, use)

					_, _, err = provider.IntrospectToken(ctx, "unknown.token", oauth2.AccessToken, &oauth2.DefaultSession{})
					require.Error(t, err)
				})
			}
		}
	}
}

func newStatelessOpaqueRequest() *oauth2.Request {
	request := oauth2.NewRequest()
	request.Client = &oauth2.DefaultClient{ID: "client"}
	request.Session = &oauth2.DefaultSession{
		ExpiresAt: map[oauth2.TokenType]time.Time{
			oauth2.AccessToken:  time.Now().Add(time.Hour),
			oauth2.RefreshToken: time.Now().Add(time.Hour),
		},
	}

	return request
}
