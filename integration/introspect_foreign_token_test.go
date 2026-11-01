// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
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

const (
	introspectFirstCore      = "CoreFirst"
	introspectFirstStateless = "StatelessFirst"
	introspectPrefixed       = "Prefixed"
	introspectUnprefixed     = "Unprefixed"
	introspectPrefix         = "authelia_%s_"
	introspectForeignToken   = "foreign-token"
	introspectJWTShapedToken = "aaa.bbb.ccc"
	introspectClientID       = "client"
)

type foreignTokenIntrospectorStore interface {
	oauth2.Storage
	hoauth2.CoreStorage
}

func TestIntrospectForeignTokenReachesTheNextIntrospector(t *testing.T) {
	testCases := []struct {
		name  string
		token string
	}{
		{name: "ShouldReachItWithoutSegments", token: introspectForeignToken},
		{name: "ShouldReachItWithAThreeSegmentToken", token: introspectJWTShapedToken},
		{name: "ShouldReachItWithAForeignPrefix", token: "ext_at_token"}, //nolint:gosec
	}

	for _, tc := range testCases {
		for prefixName, prefix := range map[string]string{introspectUnprefixed: "", introspectPrefixed: introspectPrefix} {
			for _, first := range []bool{true, false} {
				t.Run(tc.name+"/"+prefixName, func(t *testing.T) {
					config := &oauth2.Config{GlobalSecret: []byte("some-super-cool-secret-that-nobody-knows-nobody-knows")}

					provider := compose.Compose(config, storage.NewMemoryStore(), &compose.CommonStrategy{
						CoreStrategy: hoauth2.NewHMACCoreStrategy(config, prefix),
						Strategy:     &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())},
					}, compose.OAuth2TokenIntrospectionFactory)

					foreign := &foreignTokenIntrospector{token: tc.token}

					if first {
						config.TokenIntrospectionHandlers = append(oauth2.TokenIntrospectionHandlers{foreign}, config.TokenIntrospectionHandlers...)
					} else {
						config.TokenIntrospectionHandlers = append(config.TokenIntrospectionHandlers, foreign)
					}

					use, _, err := provider.IntrospectToken(t.Context(), tc.token, oauth2.AccessToken, &oauth2.DefaultSession{})
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
					assert.Equal(t, oauth2.AccessToken, use)
					assert.True(t, foreign.called)
				})
			}
		}
	}
}

func TestIntrospectForeignTokenIsRejectedWithoutAnIntrospector(t *testing.T) {
	config := &oauth2.Config{GlobalSecret: []byte("some-super-cool-secret-that-nobody-knows-nobody-knows")}

	provider := compose.Compose(config, storage.NewMemoryStore(), &compose.CommonStrategy{
		CoreStrategy: hoauth2.NewHMACCoreStrategy(config, ""),
		Strategy:     &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())},
	}, compose.OAuth2TokenIntrospectionFactory)

	for _, token := range []string{introspectForeignToken, introspectJWTShapedToken, "header.key.iv.ciphertext.tag", "aaa."} {
		_, _, err := provider.IntrospectToken(t.Context(), token, oauth2.AccessToken, &oauth2.DefaultSession{})
		assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized, token)
	}
}

func TestIntrospectRevokedJWTIsNotAcceptedByTheStatelessIntrospector(t *testing.T) {
	stores := map[string]func() foreignTokenIntrospectorStore{
		idjagStoreMemory:  func() foreignTokenIntrospectorStore { return storage.NewMemoryStore() },
		idjagStoreHydrate: func() foreignTokenIntrospectorStore { return storage.NewHydratingMemoryStore() },
	}

	orders := map[string][]compose.Factory{
		introspectFirstCore:      {compose.OAuth2TokenIntrospectionFactory, compose.OAuth2StatelessJWTIntrospectionFactory},
		introspectFirstStateless: {compose.OAuth2StatelessJWTIntrospectionFactory, compose.OAuth2TokenIntrospectionFactory},
	}

	for storeName, newStore := range stores {
		for orderName, factories := range orders {
			for prefixName, prefix := range map[string]string{introspectUnprefixed: "", introspectPrefixed: introspectPrefix} {
				t.Run(storeName+"/"+orderName+"/"+prefixName, func(t *testing.T) {
					ctx := t.Context()

					config := &oauth2.Config{
						GlobalSecret:                  []byte("some-super-cool-secret-that-nobody-knows-nobody-knows"),
						EnforceJWTProfileAccessTokens: true,
					}

					s := newStore()

					strategy := &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())}

					core := &hoauth2.JWTProfileCoreStrategy{
						HMACCoreStrategy: hoauth2.NewHMACCoreStrategy(config, prefix),
						Strategy:         strategy,
						Config:           config,
					}

					provider := compose.Compose(config, s, &compose.CommonStrategy{CoreStrategy: core, Strategy: strategy}, factories...)

					request := newForeignTokenJWTRequest()

					token, signature, err := core.GenerateAccessToken(ctx, request)
					require.NoError(t, err)

					require.NoError(t, s.CreateAccessTokenSession(ctx, signature, request))

					use, _, err := provider.IntrospectToken(ctx, token, oauth2.AccessToken, &hoauth2.JWTSession{})
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
					assert.Equal(t, oauth2.AccessToken, use)

					require.NoError(t, s.DeleteAccessTokenSession(ctx, signature))

					for _, hint := range []oauth2.TokenUse{oauth2.AccessToken, oauth2.RefreshToken, ""} {
						_, _, err = provider.IntrospectToken(ctx, token, hint, &hoauth2.JWTSession{})
						assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized, hint)
					}
				})
			}
		}
	}
}

type foreignTokenIntrospector struct {
	token  string
	called bool
}

func (i *foreignTokenIntrospector) IntrospectToken(_ context.Context, token string, _ oauth2.TokenUse, _ oauth2.AccessRequester, _ []string) (oauth2.TokenUse, error) {
	i.called = true

	if token != i.token {
		return "", oauth2.ErrUnknownRequest
	}

	return oauth2.AccessToken, nil
}

func newForeignTokenJWTRequest() *oauth2.Request {
	expires := time.Now().Add(time.Hour)

	request := oauth2.NewRequest()
	request.Client = &oauth2.DefaultClient{ID: introspectClientID}
	request.GrantAudience(introspectClientID)
	request.Session = &hoauth2.JWTSession{
		JWTClaims: &jwt.JWTClaims{Issuer: "https://auth.example.com", Subject: idjagSubject, Audience: []string{introspectClientID}, IssuedAt: time.Now(), ExpiresAt: expires},
		JWTHeader: &jwt.Headers{},
		ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.AccessToken: expires},
		Subject:   idjagSubject,
	}

	return request
}
