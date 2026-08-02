// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/storage"
)

func TestDefaultEndpointAuthStrategy(t *testing.T) {
	ctx := context.Background()

	t.Run("ShouldRejectMissingHeader", func(t *testing.T) {
		auth, _, _, _ := newTestAuthStrategy(t)

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, request(http.MethodPost, testEndpoint, ""), "")
		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
	})

	t.Run("ShouldRejectDuplicateHeader", func(t *testing.T) {
		auth, _, store, tokens := newTestAuthStrategy(t)

		token := mintToken(t, ctx, tokens, store, testEndpoint, "", time.Time{})

		r := request(http.MethodPost, testEndpoint, token)
		r.Header.Add("Authorization", "Bearer "+token)

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, r, "")
		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
	})

	t.Run("ShouldRejectNonBearerScheme", func(t *testing.T) {
		auth, _, store, tokens := newTestAuthStrategy(t)

		token := mintToken(t, ctx, tokens, store, testEndpoint, "", time.Time{})

		r := request(http.MethodPost, testEndpoint, "")
		r.Header.Set("Authorization", "Basic "+token)

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, r, "")
		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
	})
}

func TestAuthAcceptsCreationTokenAtRegistrationEndpoint(t *testing.T) {
	ctx := context.Background()
	auth, config, store, tokens := newAuthFixtures(t)

	token, err := NewClientCreationToken(ctx, tokens, store, config, &oauth2.DefaultClient{ID: "creator"}, oauth2.Arguments{"openid"})
	require.NoError(t, err)

	requester, err := auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodPost, "https://auth.example.com/register", token), "")
	require.NoError(t, err)

	session, ok := requester.GetSession().(Session)
	require.True(t, ok)
	assert.Equal(t, KindCreate, session.GetClientRegistrationKind())
	assert.Equal(t, tokens.AccessTokenSignature(ctx, token), requester.GetID())
}

func TestAuthRejectsOrdinaryAccessToken(t *testing.T) {
	ctx := context.Background()
	auth, _, store, tokens := newAuthFixtures(t)

	requester := oauth2.NewRequest()
	requester.Client = &oauth2.DefaultClient{ID: "ordinary"}
	requester.Session = &oauth2.DefaultSession{}
	requester.GrantAudience("https://auth.example.com/register")

	token, signature, err := tokens.GenerateAccessToken(ctx, requester)
	require.NoError(t, err)
	require.NoError(t, store.CreateAccessTokenSession(ctx, signature, requester))

	_, err = auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodPost, "https://auth.example.com/register", token), "")
	assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
}

func TestAuthRejectsCreationTokenAtConfigurationEndpoint(t *testing.T) {
	ctx := context.Background()
	auth, config, store, tokens := newAuthFixtures(t)

	token, err := NewClientCreationToken(ctx, tokens, store, config, &oauth2.DefaultClient{ID: "creator"}, nil)
	require.NoError(t, err)

	_, err = auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodGet, "https://auth.example.com/register/some-client", token), "some-client")
	assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
}

func TestAuthRejectsManagementTokenAtRegistrationEndpoint(t *testing.T) {
	ctx := context.Background()
	auth, config, store, tokens := newAuthFixtures(t)

	token, err := NewClientManagementToken(ctx, tokens, store, config, &oauth2.DefaultClient{ID: "managed"}, nil)
	require.NoError(t, err)

	_, err = auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodPost, "https://auth.example.com/register", token), "")
	assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
}

func TestAuthRejectsManagementTokenForAnotherClient(t *testing.T) {
	ctx := context.Background()
	auth, config, store, tokens := newAuthFixtures(t)

	token, err := NewClientManagementToken(ctx, tokens, store, config, &oauth2.DefaultClient{ID: "client-a"}, nil)
	require.NoError(t, err)

	_, err = auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodGet, "https://auth.example.com/register/client-b", token), "client-b")
	assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
}

func TestAuthAcceptsManagementTokenForItsOwnClient(t *testing.T) {
	ctx := context.Background()
	auth, config, store, tokens := newAuthFixtures(t)

	token, err := NewClientManagementToken(ctx, tokens, store, config, &oauth2.DefaultClient{ID: "client-a"}, oauth2.Arguments{"openid"})
	require.NoError(t, err)

	requester, err := auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodGet, "https://auth.example.com/register/client-a", token), "client-a")
	require.NoError(t, err)

	assert.Equal(t, "client-a", requester.GetSession().GetSubject())
}

func TestAuthRejectsUnknownToken(t *testing.T) {
	ctx := context.Background()
	auth, _, _, _ := newAuthFixtures(t)

	_, err := auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodPost, "https://auth.example.com/register", "authelia_at_notreal.notreal"), "")
	assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
}

func TestAuthRejectsManageKindSessionAtRegistrationEndpoint(t *testing.T) {
	ctx := context.Background()
	auth, _, store, tokens := newAuthFixtures(t)

	session := NewDefaultSession()
	session.SetClientRegistrationKind(KindManage)
	session.SetSubject("client-a")

	requester := oauth2.NewRequest()
	requester.Client = &oauth2.DefaultClient{ID: "client-a"}
	requester.Session = session
	requester.GrantAudience("https://auth.example.com/register")

	token, signature, err := tokens.GenerateAccessToken(ctx, requester)
	require.NoError(t, err)
	require.NoError(t, store.CreateAccessTokenSession(ctx, signature, requester))

	_, err = auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodPost, "https://auth.example.com/register", token), "")
	assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
}

func TestAuthRejectsCreateKindSessionAtConfigurationEndpoint(t *testing.T) {
	ctx := context.Background()
	auth, _, store, tokens := newAuthFixtures(t)

	session := NewDefaultSession()
	session.SetClientRegistrationKind(KindCreate)
	session.SetSubject("client-a")

	requester := oauth2.NewRequest()
	requester.Client = &oauth2.DefaultClient{ID: "client-a"}
	requester.Session = session
	requester.GrantAudience(ClientConfigurationURL("https://auth.example.com/register", "client-a"))

	token, signature, err := tokens.GenerateAccessToken(ctx, requester)
	require.NoError(t, err)
	require.NoError(t, store.CreateAccessTokenSession(ctx, signature, requester))

	_, err = auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodGet, "https://auth.example.com/register/client-a", token), "client-a")
	assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
}

func TestAuthRejectsExpiredCreationToken(t *testing.T) {
	ctx := context.Background()
	auth, config, store, tokens := newAuthFixtures(t)
	config.RFC7591ClientRegistrationCreateTokenLifespan = time.Nanosecond

	token, err := NewClientCreationToken(ctx, tokens, store, config, &oauth2.DefaultClient{ID: "creator"}, nil)
	require.NoError(t, err)

	time.Sleep(time.Millisecond)

	_, err = auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodPost, "https://auth.example.com/register", token), "")
	assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
}

func newTestAuthStrategy(t *testing.T) (*DefaultEndpointAuthStrategy, *oauth2.Config, *storage.MemoryStore, *hoauth2.HMACCoreStrategy) {
	t.Helper()

	config := &oauth2.Config{
		GlobalSecret:                         []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationEndpointURL: testEndpoint,
	}

	tokens := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")
	store := storage.NewMemoryStore()

	return NewDefaultEndpointAuthStrategy(config, store, tokens), config, store, tokens
}

func mintToken(t *testing.T, ctx context.Context, tokens hoauth2.AccessTokenStrategy, store Storage, audience, subject string, exp time.Time) string {
	t.Helper()

	session := &oauth2.DefaultSession{Subject: subject}

	if !exp.IsZero() {
		session.SetExpiresAt(oauth2.AccessToken, exp)
	}

	req := oauth2.NewRequest()
	req.Session = session
	req.GrantAudience(audience)

	token, signature, err := tokens.GenerateAccessToken(ctx, req)
	require.NoError(t, err)

	require.NoError(t, store.CreateAccessTokenSession(ctx, signature, req))

	return token
}

func request(method, url, token string) *http.Request {
	r := httptest.NewRequest(method, url, nil)

	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}

	return r
}

func newAuthFixtures(t *testing.T) (*DefaultEndpointAuthStrategy, *oauth2.Config, *storage.MemoryStore, *hoauth2.HMACCoreStrategy) {
	t.Helper()

	config := &oauth2.Config{
		GlobalSecret:                         []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationEndpointURL: "https://auth.example.com/register",
	}

	store := storage.NewMemoryStore()
	tokens := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

	return NewDefaultEndpointAuthStrategy(config, store, tokens), config, store, tokens
}

func authRequest(t *testing.T, method, url, token string) *http.Request {
	t.Helper()

	r := httptest.NewRequest(method, url, nil)
	r.Header.Set("Authorization", "Bearer "+token)

	return r
}
