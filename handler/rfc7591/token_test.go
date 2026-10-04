// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestNewClientManagementToken(t *testing.T) {
	ctx := context.Background()
	config, store, tokens, _ := newTokenFixtures(t)

	managed := &oauth2.DefaultClient{ID: "managed-one"}

	tokenString, err := NewClientManagementToken(ctx, tokens, store, config, managed, oauth2.Arguments{"openid"}, oauth2.Arguments{"https://api.example.com"})
	require.NoError(t, err)

	requester, err := store.GetClientRegistrationTokenSession(ctx, tokens.ClientRegistrationTokenSignature(ctx, tokenString), &oauth2.DefaultSession{})
	require.NoError(t, err)
	assert.Equal(t, "managed-one", requester.GetClient().GetID())
	assert.True(t, requester.GetGrantedAudience().Has("https://auth.example.com/register/managed-one"))
	assert.True(t, requester.GetGrantedAudience().Has("https://api.example.com"))
	assert.Equal(t, oauth2.Arguments{"openid"}, requester.GetGrantedScopes())

	assert.Empty(t, requester.GetSession().GetSubject())

	exp := requester.GetSession().GetExpiresAt(oauth2.AccessToken)

	require.False(t, exp.IsZero())
	assert.True(t, exp.After(time.Now().UTC().AddDate(50, 0, 0)), "expected a far-future expiry, got '%s'", exp)
}

func TestNewClientManagementTokenNeverExpires(t *testing.T) {
	ctx := context.Background()
	config, store, tokens, _ := newTokenFixtures(t)

	config.AccessTokenLifespan = time.Nanosecond
	auth := NewDefaultEndpointAuthStrategy(config, store, tokens, tokens)

	tokenString, err := NewClientManagementToken(ctx, tokens, store, config, &oauth2.DefaultClient{ID: "forever"}, oauth2.Arguments{"openid"}, nil)
	require.NoError(t, err)

	time.Sleep(time.Millisecond)

	requester, err := auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodGet, "https://auth.example.com/register/forever", tokenString), "forever")
	require.NoError(t, err)

	assert.Equal(t, "forever", requester.GetClient().GetID())
}

func TestZeroExpiryRegistrationTokenIsRetired(t *testing.T) {
	ctx := context.Background()
	config, store, tokens, _ := newTokenFixtures(t)

	config.AccessTokenLifespan = time.Nanosecond

	auth := NewDefaultEndpointAuthStrategy(config, store, tokens, tokens)

	requester := oauth2.NewRequest()
	requester.Client = &oauth2.DefaultClient{ID: "forever"}
	requester.Session = &oauth2.DefaultSession{}
	requester.GrantAudience(ClientConfigurationURL("https://auth.example.com/register", "forever"))

	tokenString, signature, err := tokens.GenerateClientRegistrationToken(ctx, requester)
	require.NoError(t, err)
	require.NoError(t, store.CreateClientRegistrationTokenSession(ctx, signature, requester))

	time.Sleep(time.Millisecond)

	_, err = auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodGet, "https://auth.example.com/register/forever", tokenString), "forever")
	assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
}

func TestNewClientManagementTokenNeverExpiresUnderJWTProfile(t *testing.T) {
	ctx := context.Background()

	config := &oauth2.Config{
		GlobalSecret:                          []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
		RFC7591ClientRegistrationEndpointURL:  "https://auth.example.com/register",
		EnforceJWTProfileAccessTokens:         true,
		AccessTokenIssuer:                     "https://auth.example.com",
		AccessTokenLifespan:                   time.Nanosecond,
	}

	store := storage.NewMemoryStore()

	strategy := &hoauth2.JWTProfileCoreStrategy{
		HMACCoreStrategy: hoauth2.NewHMACCoreStrategy(config, "authelia_%s_"),
		Strategy: &jwt.DefaultStrategy{
			Config: config,
			Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey()),
		},
		Config: config,
	}

	auth := NewDefaultEndpointAuthStrategy(config, store, strategy, strategy)

	tokenString, err := NewClientManagementToken(ctx, strategy, store, config, &oauth2.DefaultClient{ID: "forever-jwt"}, oauth2.Arguments{"openid"}, nil)
	require.NoError(t, err)

	assert.True(t, strategy.IsOpaqueClientRegistrationToken(ctx, tokenString))

	time.Sleep(time.Millisecond)

	requester, err := auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodGet, "https://auth.example.com/register/forever-jwt", tokenString), "forever-jwt")
	require.NoError(t, err)

	assert.Equal(t, "forever-jwt", requester.GetClient().GetID())

	exp := requester.GetSession().GetExpiresAt(oauth2.AccessToken)
	assert.True(t, exp.After(time.Now().UTC().AddDate(50, 0, 0)), "expected a far-future expiry, got '%s'", exp)
}

func TestNewClientManagementTokenUnderJWTProfile(t *testing.T) {
	ctx := context.Background()

	config := &oauth2.Config{
		GlobalSecret:                          []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
		RFC7591ClientRegistrationEndpointURL:  "https://auth.example.com/register",
		EnforceJWTProfileAccessTokens:         true,
		AccessTokenIssuer:                     "https://auth.example.com",
	}

	store := storage.NewMemoryStore()

	strategy := &hoauth2.JWTProfileCoreStrategy{
		HMACCoreStrategy: hoauth2.NewHMACCoreStrategy(config, "authelia_%s_"),
		Strategy: &jwt.DefaultStrategy{
			Config: config,
			Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey()),
		},
		Config: config,
	}

	managed := &oauth2.DefaultClient{ID: "managed-jwt"}

	tokenString, err := NewClientManagementToken(ctx, strategy, store, config, managed, oauth2.Arguments{"openid"}, nil)
	require.NoError(t, err)

	assert.True(t, strategy.IsOpaqueClientRegistrationToken(ctx, tokenString))
	assert.True(t, strings.HasPrefix(tokenString, "authelia_cr_"))

	requester, err := store.GetClientRegistrationTokenSession(ctx, strategy.ClientRegistrationTokenSignature(ctx, tokenString), &oauth2.DefaultSession{})
	require.NoError(t, err)

	assert.Equal(t, "managed-jwt", requester.GetClient().GetID())
	assert.Equal(t, oauth2.Arguments{"openid"}, requester.GetGrantedScopes())
}

func TestRegistrationTokenIsNotIntrospectedAsAnAccessToken(t *testing.T) {
	ctx := context.Background()
	config, store, tokens, client := newTokenFixtures(t)

	validator := &hoauth2.CoreValidator{CoreStrategy: tokens, CoreStorage: store, Config: config}

	registration, err := NewClientManagementToken(ctx, tokens, store, config, client, oauth2.Arguments{"openid"}, nil)
	require.NoError(t, err)

	_, err = validator.IntrospectToken(ctx, registration, oauth2.AccessToken, oauth2.NewAccessRequest(&oauth2.DefaultSession{}), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrUnknownRequest)

	config.TokenIntrospectionHandlers = oauth2.TokenIntrospectionHandlers{validator}

	_, _, err = (&oauth2.Fosite{Store: store, Config: config}).IntrospectToken(ctx, registration, oauth2.AccessToken, &oauth2.DefaultSession{})
	assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)

	ordinary := oauth2.NewRequest()
	ordinary.Client = client
	ordinary.Session = &oauth2.DefaultSession{}

	tokenString, signature, err := tokens.GenerateAccessToken(ctx, ordinary)
	require.NoError(t, err)
	require.NoError(t, store.CreateAccessTokenSession(ctx, signature, ordinary))

	use, err := validator.IntrospectToken(ctx, tokenString, oauth2.AccessToken, oauth2.NewAccessRequest(&oauth2.DefaultSession{}), nil)
	require.NoError(t, err)
	assert.Equal(t, oauth2.AccessToken, use)
}

func TestManagementTokenIgnoresClientLifespanOverride(t *testing.T) {
	ctx := context.Background()

	config, store, strategy, _ := newTokenFixtures(t)

	client := &shortLifespanClient{DefaultClient: &oauth2.DefaultClient{ID: "client-a"}}

	token, err := NewClientManagementToken(ctx, strategy, store, config, client, oauth2.Arguments{"openid"}, nil)
	require.NoError(t, err)

	requester, err := store.GetClientRegistrationTokenSession(ctx, strategy.ClientRegistrationTokenSignature(ctx, token), &oauth2.DefaultSession{})
	require.NoError(t, err)

	assert.WithinDuration(t, time.Now().UTC().Add(NonExpiringTokenLifespan), requester.GetSession().GetExpiresAt(oauth2.AccessToken), time.Minute)
}

func newTokenFixtures(t *testing.T) (*oauth2.Config, *storage.MemoryStore, *hoauth2.HMACCoreStrategy, oauth2.Client) {
	t.Helper()

	config := &oauth2.Config{
		GlobalSecret:                          []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
		RFC7591ClientRegistrationEndpointURL:  "https://auth.example.com/register",
	}

	return config, storage.NewMemoryStore(), hoauth2.NewHMACCoreStrategy(config, "authelia_%s_"), &oauth2.DefaultClient{ID: "creator"}
}

type shortLifespanClient struct {
	*oauth2.DefaultClient
}

func (c *shortLifespanClient) GetEffectiveLifespan(gt oauth2.GrantType, tt oauth2.TokenType, fallback time.Duration) time.Duration {
	return time.Second
}
