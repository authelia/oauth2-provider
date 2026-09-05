// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"encoding/json"
	"errors"
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
		assert.ErrorIs(t, err, oauth2.ErrInvalidToken)
	})

	t.Run("ShouldRejectDuplicateHeader", func(t *testing.T) {
		auth, _, store, tokens := newTestAuthStrategy(t)

		token := mintToken(t, ctx, tokens, store, testEndpoint, "", time.Time{})

		r := request(http.MethodPost, testEndpoint, token)
		r.Header.Add("Authorization", "Bearer "+token)

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, r, "")
		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
	})

	t.Run("ShouldRejectNonBearerScheme", func(t *testing.T) {
		auth, _, store, tokens := newTestAuthStrategy(t)

		token := mintToken(t, ctx, tokens, store, testEndpoint, "", time.Time{})

		r := request(http.MethodPost, testEndpoint, "")
		r.Header.Set("Authorization", "Basic "+token)

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, r, "")
		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrInvalidToken)
	})
}

func TestAuthRejectsAnAccessTokenAtTheConfigurationEndpoint(t *testing.T) {
	ctx := context.Background()
	auth, config, store, _ := newAuthFixtures(t)
	access := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

	token := mintAccessToken(t, ctx, store, access, []string{"authelia:oauth2:client_registration"}, []string{"https://auth.example.com/register/some-client"})

	_, err := auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodGet, "https://auth.example.com/register/some-client", token), "some-client")
	assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
}

func TestAuthRejectsManagementTokenForAnotherClient(t *testing.T) {
	ctx := context.Background()
	auth, config, store, tokens := newAuthFixtures(t)

	token, err := NewClientManagementToken(ctx, tokens, store, config, &oauth2.DefaultClient{ID: "client-a"}, nil, nil)
	require.NoError(t, err)

	_, err = auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodGet, "https://auth.example.com/register/client-b", token), "client-b")
	assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
}

func TestAuthAcceptsManagementTokenForItsOwnClient(t *testing.T) {
	ctx := context.Background()
	auth, config, store, tokens := newAuthFixtures(t)

	token, err := NewClientManagementToken(ctx, tokens, store, config, &oauth2.DefaultClient{ID: "client-a"}, oauth2.Arguments{"openid"}, nil)
	require.NoError(t, err)

	requester, err := auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodGet, "https://auth.example.com/register/client-a", token), "client-a")
	require.NoError(t, err)

	assert.Equal(t, "client-a", requester.GetClient().GetID())
}

func TestAuthRejectsMintedAudienceMismatchingClientID(t *testing.T) {
	ctx := context.Background()
	auth, _, store, tokens := newAuthFixtures(t)

	session := &oauth2.DefaultSession{}
	session.SetExpiresAt(oauth2.AccessToken, time.Now().Add(time.Hour))

	requester := oauth2.NewRequest()
	requester.Client = &oauth2.DefaultClient{ID: "client-a"}
	requester.Session = session
	requester.GrantAudience(ClientConfigurationURL("https://auth.example.com/register", "client-b"))

	token, signature, err := tokens.GenerateClientRegistrationToken(ctx, requester)
	require.NoError(t, err)
	require.NoError(t, store.CreateClientRegistrationTokenSession(ctx, signature, requester))

	_, err = auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodGet, ClientConfigurationURL("https://auth.example.com/register", "client-b"), token), "client-b")
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
	assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request could not be authorized. The provided Client Registration Token is not permitted to manage the client with id 'client-b'.")
}

func TestAuthRejectsUnknownToken(t *testing.T) {
	ctx := context.Background()
	auth, _, _, _ := newAuthFixtures(t)

	_, err := auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodPost, "https://auth.example.com/register", "authelia_at_notreal.notreal"), "")
	assert.ErrorIs(t, err, oauth2.ErrInvalidToken)
}

func TestAuthRejectsAnExpiredAccessToken(t *testing.T) {
	ctx := context.Background()

	auth, config, store, _ := newAuthFixtures(t)
	access := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

	request := oauth2.NewRequest()
	request.Client = &oauth2.DefaultClient{ID: "onboarding"}
	request.Session = &oauth2.DefaultSession{
		ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.AccessToken: time.Now().UTC().Add(-time.Hour)},
	}
	request.GrantScope("authelia:oauth2:client_registration")
	request.GrantAudience(testEndpoint)

	token, signature, err := access.GenerateAccessToken(ctx, request)
	require.NoError(t, err)
	require.NoError(t, store.CreateAccessTokenSession(ctx, signature, request))

	_, err = auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodPost, testEndpoint, token), "")
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidToken)
}

func TestAuthAcceptsAnAccessTokenWithTheAudienceAndScope(t *testing.T) {
	ctx := context.Background()

	handler, config, store, _ := newAuthFixtures(t)
	access := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

	token := mintAccessToken(t, ctx, store, access, []string{"authelia:oauth2:client_registration"}, []string{testEndpoint})

	requester, err := handler.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodPost, testEndpoint, token), "")

	require.NoError(t, err)
	assert.Equal(t, "onboarding", requester.GetClient().GetID())
}

func TestAuthRejectsAnAccessTokenMissingTheScope(t *testing.T) {
	ctx := context.Background()

	handler, config, store, _ := newAuthFixtures(t)
	access := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

	token := mintAccessToken(t, ctx, store, access, []string{"openid"}, []string{testEndpoint})

	_, err := handler.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodPost, testEndpoint, token), "")

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInsufficientScope)
}

func TestAuthRejectsAnAccessTokenMissingTheAudience(t *testing.T) {
	ctx := context.Background()

	handler, config, store, _ := newAuthFixtures(t)
	access := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

	token := mintAccessToken(t, ctx, store, access, []string{"authelia:oauth2:client_registration"}, []string{"https://elsewhere.example.com/register"})

	_, err := handler.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodPost, testEndpoint, token), "")

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidToken)
}

func TestAuthRejectsAManagementTokenAtTheRegistrationEndpoint(t *testing.T) {
	ctx := context.Background()

	handler, config, store, strategy := newAuthFixtures(t)

	token, err := NewClientManagementToken(ctx, strategy, store, config, &oauth2.DefaultClient{ID: "client-a"}, oauth2.Arguments{"openid"}, nil)
	require.NoError(t, err)

	_, err = handler.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodPost, testEndpoint, token), "")

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidToken)
}

func TestDefaultEndpointAuthStrategyRegistrationAudience(t *testing.T) {
	testCases := []struct {
		name       string
		configured string
		granted    string
		url        string
		expected   string
	}{
		{
			name:     "ShouldFallBackToTheRequestURL",
			granted:  testEndpoint,
			url:      testEndpoint,
			expected: "",
		},
		{
			name:     "ShouldRejectATokenAudiencedElsewhereWhenFallingBack",
			granted:  "https://elsewhere.example.com/register",
			url:      testEndpoint,
			expected: "The access token provided is expired, revoked, malformed, or invalid for other reasons. The credential used to authenticate the request does not have an audience which is permitted at this endpoint. The credential was expected to have an audience matching one of the values 'https://auth.example.com/register' but the audience had the values 'https://elsewhere.example.com/register'.",
		},
		{
			name:       "ShouldAcceptTheConfiguredAudience",
			configured: "https://auth.example.com/api/register",
			granted:    "https://auth.example.com/api/register",
			url:        testEndpoint,
			expected:   "",
		},
		{
			name:       "ShouldRejectTheRequestURLWhenAnAudienceIsConfigured",
			configured: "https://auth.example.com/api/register",
			granted:    testEndpoint,
			url:        testEndpoint,
			expected:   "The access token provided is expired, revoked, malformed, or invalid for other reasons. The credential used to authenticate the request does not have an audience which is permitted at this endpoint. The credential was expected to have an audience matching one of the values 'https://auth.example.com/api/register' but the audience had the values 'https://auth.example.com/register'.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			var audiences []string

			if tc.configured != "" {
				audiences = []string{tc.configured}
			}

			config := &oauth2.Config{
				GlobalSecret:                               []byte("super-duper-secret-that-is-at-least-32-bytes"),
				RFC7591ClientRegistrationGlobalSecret:      []byte("a-completely-different-secret-at-least-32b"),
				RFC7591ClientRegistrationEndpointURL:       testEndpoint,
				RFC7591ClientRegistrationEndpointAudiences: audiences,
				TokenEntropy:                               32,
			}

			store := storage.NewMemoryStore()
			strategy := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

			token := mintAccessToken(t, ctx, store, strategy, []string{"authelia:oauth2:client_registration"}, []string{tc.granted})

			auth := NewDefaultEndpointAuthStrategy(config, store, strategy, strategy)

			_, err := auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodPost, tc.url, token), "")

			if tc.expected == "" {
				assert.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.ErrorIs(t, err, oauth2.ErrInvalidToken)
			assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.expected)
		})
	}
}

func TestAuthHydratesTheAccessTokenSession(t *testing.T) {
	ctx := context.Background()

	config := &oauth2.Config{
		GlobalSecret:                          []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
		RFC7591ClientRegistrationEndpointURL:  testEndpoint,
		TokenEntropy:                          32,
	}

	store := &hydratingAccessTokenStore{MemoryStore: storage.NewMemoryStore()}
	strategy := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

	token := mintAccessToken(t, ctx, store.MemoryStore, strategy, []string{"authelia:oauth2:client_registration"}, []string{testEndpoint})

	auth := NewDefaultEndpointAuthStrategy(config, store, strategy, strategy)

	requester, err := auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodPost, testEndpoint, token), "")

	require.NoError(t, err)
	assert.Equal(t, "onboarding", requester.GetClient().GetID())
	assert.False(t, requester.GetSession().GetExpiresAt(oauth2.AccessToken).IsZero())
}

func TestAuthRejectsAWildcardScopeAtTheRegistrationEndpoint(t *testing.T) {
	ctx := context.Background()

	auth, config, store, _ := newAuthFixtures(t)
	require.Nil(t, config.ScopeStrategy, "the fixture must leave the scope strategy at its WildcardScopeStrategy default for this test to mean anything")

	access := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

	token := mintAccessToken(t, ctx, store, access, []string{"*"}, []string{testEndpoint})

	_, err := auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodPost, testEndpoint, token), "")

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInsufficientScope)
	assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request requires higher privileges than provided by the Access Token. The credential used to authenticate the request is not granted any of the scopes 'authelia:oauth2:client_registration', at least one of which is required.")
}

func TestAuthRejectsALooseServerAudienceStrategyAtTheRegistrationEndpoint(t *testing.T) {
	ctx := context.Background()

	auth, config, store, _ := newAuthFixtures(t)
	config.AudienceStrategy = func(haystack, needle []string) error { return nil }

	access := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

	token := mintAccessToken(t, ctx, store, access, []string{"authelia:oauth2:client_registration"}, []string{"https://elsewhere.example.com/register"})

	_, err := auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodPost, testEndpoint, token), "")

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidToken)
	assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The access token provided is expired, revoked, malformed, or invalid for other reasons. The credential used to authenticate the request does not have an audience which is permitted at this endpoint. The credential was expected to have an audience matching one of the values 'https://auth.example.com/register' but the audience had the values 'https://elsewhere.example.com/register'.")
}

func TestAuthIgnoresClientAudienceStrategyAtTheRegistrationEndpoint(t *testing.T) {
	ctx := context.Background()

	auth, config, store, _ := newAuthFixtures(t)
	access := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

	request := oauth2.NewRequest()
	request.Client = &permissiveAudienceClient{Client: &oauth2.DefaultClient{ID: "onboarding"}}
	request.Session = &oauth2.DefaultSession{
		ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.AccessToken: time.Now().UTC().Add(time.Hour)},
	}
	request.GrantScope("authelia:oauth2:client_registration")
	request.GrantAudience("https://elsewhere.example.com/register")

	token, signature, err := access.GenerateAccessToken(ctx, request)
	require.NoError(t, err)
	require.NoError(t, store.CreateAccessTokenSession(ctx, signature, request))

	_, err = auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodPost, testEndpoint, token), "")

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidToken)
	assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The access token provided is expired, revoked, malformed, or invalid for other reasons. The credential used to authenticate the request does not have an audience which is permitted at this endpoint. The credential was expected to have an audience matching one of the values 'https://auth.example.com/register' but the audience had the values 'https://elsewhere.example.com/register'.")
}

func TestAuthIgnoresClientScopeStrategyAtTheRegistrationEndpoint(t *testing.T) {
	ctx := context.Background()

	auth, config, store, _ := newAuthFixtures(t)
	access := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

	request := oauth2.NewRequest()
	request.Client = &permissiveScopeClient{Client: &oauth2.DefaultClient{ID: "onboarding"}}
	request.Session = &oauth2.DefaultSession{
		ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.AccessToken: time.Now().UTC().Add(time.Hour)},
	}
	request.GrantScope("openid")
	request.GrantAudience(testEndpoint)

	token, signature, err := access.GenerateAccessToken(ctx, request)
	require.NoError(t, err)
	require.NoError(t, store.CreateAccessTokenSession(ctx, signature, request))

	_, err = auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodPost, testEndpoint, token), "")

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInsufficientScope)
	assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request requires higher privileges than provided by the Access Token. The credential used to authenticate the request is not granted any of the scopes 'authelia:oauth2:client_registration', at least one of which is required.")
}

func TestAuthAcceptsAManagementTokenBehindAProxy(t *testing.T) {
	ctx := context.Background()
	auth, config, store, tokens := newAuthFixtures(t)

	token, err := NewClientManagementToken(ctx, tokens, store, config, &oauth2.DefaultClient{ID: "client-a"}, nil, nil)
	require.NoError(t, err)

	requester, err := auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodGet, "https://backend.internal:8080/oauth2/register/client-a", token), "client-a")
	require.NoError(t, err)
	assert.Equal(t, "client-a", requester.GetClient().GetID())
}

func TestAuthFallsBackToTheRequestURLWithoutAConfiguredEndpoint(t *testing.T) {
	ctx := context.Background()

	config := &oauth2.Config{
		GlobalSecret:                          []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
	}

	store := storage.NewMemoryStore()
	tokens := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")
	auth := NewDefaultEndpointAuthStrategy(config, store, tokens, tokens)

	session := &oauth2.DefaultSession{}
	session.SetExpiresAt(oauth2.AccessToken, time.Now().UTC().Add(time.Hour))

	req := oauth2.NewRequest()
	req.Client = &oauth2.DefaultClient{ID: "client-a"}
	req.Session = session
	req.GrantAudience("https://auth.example.com/register/client-a")

	token, signature, err := tokens.GenerateClientRegistrationToken(ctx, req)
	require.NoError(t, err)
	require.NoError(t, store.CreateClientRegistrationTokenSession(ctx, signature, req))

	_, err = auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodGet, "https://auth.example.com/register/client-a", token), "client-a")
	require.NoError(t, err)

	_, err = auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodGet, "https://elsewhere.example.com/register/client-a", token), "client-a")
	assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
}

func TestAuthRejectsASessionWithoutAClient(t *testing.T) {
	ctx := context.Background()
	auth, config, store, tokens := newAuthFixtures(t)

	session := &oauth2.DefaultSession{}
	session.SetExpiresAt(oauth2.AccessToken, time.Now().UTC().Add(time.Hour))

	req := oauth2.NewRequest()
	req.Client = nil
	req.Session = session
	req.GrantAudience(ClientConfigurationURL(config.GetRFC7591ClientRegistrationEndpointURL(ctx), "client-a"))

	token, signature, err := tokens.GenerateClientRegistrationToken(ctx, req)
	require.NoError(t, err)
	require.NoError(t, store.CreateClientRegistrationTokenSession(ctx, signature, req))

	require.NotPanics(t, func() {
		_, err = auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodGet, ClientConfigurationURL(testEndpoint, "client-a"), token), "client-a")
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
	assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request could not be authorized. The provided Client Registration Token is not permitted to manage the client with id 'client-a'.")
}

func TestAuthAcceptsExtraSpacesAfterTheScheme(t *testing.T) {
	ctx := context.Background()
	auth, config, store, tokens := newAuthFixtures(t)

	token, err := NewClientManagementToken(ctx, tokens, store, config, &oauth2.DefaultClient{ID: "client-a"}, nil, nil)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodGet, ClientConfigurationURL(testEndpoint, "client-a"), nil)
	r.Header.Set("Authorization", "Bearer   "+token)

	requester, err := auth.AuthenticateClientRegistrationRequest(ctx, r, "client-a")
	require.NoError(t, err)

	assert.Equal(t, "client-a", requester.GetClient().GetID())
}

func TestAuthenticateClientRegistrationErrorCodes(t *testing.T) {
	ctx := context.Background()

	t.Run("ShouldReportInsufficientScopeAt403", func(t *testing.T) {
		auth, config, store, _ := newAuthFixtures(t)
		access := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

		token := mintAccessToken(t, ctx, store, access, []string{"read"}, []string{testEndpoint})

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodPost, testEndpoint, token), "")

		require.Error(t, err)
		rfc := oauth2.ErrorToRFC6749Error(err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request requires higher privileges than provided by the Access Token. The credential used to authenticate the request is not granted any of the scopes 'authelia:oauth2:client_registration', at least one of which is required.")
		assert.Equal(t, http.StatusForbidden, rfc.CodeField)
	})

	t.Run("ShouldReportInvalidTokenForWrongAudience", func(t *testing.T) {
		auth, config, store, _ := newAuthFixtures(t)
		access := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

		token := mintAccessToken(t, ctx, store, access, []string{"authelia:oauth2:client_registration"}, []string{"urn:wrong"})

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodPost, testEndpoint, token), "")

		require.Error(t, err)
		rfc := oauth2.ErrorToRFC6749Error(err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The access token provided is expired, revoked, malformed, or invalid for other reasons. The credential used to authenticate the request does not have an audience which is permitted at this endpoint. The credential was expected to have an audience matching one of the values 'https://auth.example.com/register' but the audience had the values 'urn:wrong'.")
		assert.Equal(t, http.StatusUnauthorized, rfc.CodeField)
	})

	t.Run("ShouldReportInsufficientScopeWhenBothScopeAndAudienceFail", func(t *testing.T) {
		auth, config, store, _ := newAuthFixtures(t)
		access := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

		token := mintAccessToken(t, ctx, store, access, []string{"read"}, []string{"urn:wrong"})

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodPost, testEndpoint, token), "")

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request requires higher privileges than provided by the Access Token. The credential used to authenticate the request is not granted any of the scopes 'authelia:oauth2:client_registration', at least one of which is required.")
	})

	t.Run("ShouldReportInvalidTokenForUnknownToken", func(t *testing.T) {
		auth, _, _, _ := newAuthFixtures(t)

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodPost, testEndpoint, "authelia_at_notreal.notreal"), "")

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The access token provided is expired, revoked, malformed, or invalid for other reasons. The provided Access Token is not valid. Could not find the requested resource(s).")
	})

	t.Run("ShouldReportInvalidRequestAt400ForMultipleAuthorizationHeaders", func(t *testing.T) {
		auth, _, _, _ := newAuthFixtures(t)

		r := authRequest(t, http.MethodPost, testEndpoint, "one")
		r.Header.Add("Authorization", "Bearer two")

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, r, "")

		require.Error(t, err)
		rfc := oauth2.ErrorToRFC6749Error(err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Multiple methods used to include access token.")
		assert.Equal(t, http.StatusBadRequest, rfc.CodeField)
	})
}

func newTestAuthStrategy(t *testing.T) (*DefaultEndpointAuthStrategy, *oauth2.Config, *storage.MemoryStore, *hoauth2.HMACCoreStrategy) {
	t.Helper()

	config := &oauth2.Config{
		GlobalSecret:                          []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
		RFC7591ClientRegistrationEndpointURL:  testEndpoint,
	}

	tokens := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")
	store := storage.NewMemoryStore()

	return NewDefaultEndpointAuthStrategy(config, store, tokens, tokens), config, store, tokens
}

func mintToken(t *testing.T, ctx context.Context, tokens ClientRegistrationTokenStrategy, store Storage, audience, subject string, exp time.Time) string {
	t.Helper()

	session := &oauth2.DefaultSession{Subject: subject}

	if !exp.IsZero() {
		session.SetExpiresAt(oauth2.AccessToken, exp)
	}

	req := oauth2.NewRequest()
	req.Session = session
	req.GrantAudience(audience)

	token, signature, err := tokens.GenerateClientRegistrationToken(ctx, req)
	require.NoError(t, err)

	require.NoError(t, store.CreateClientRegistrationTokenSession(ctx, signature, req))

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
		GlobalSecret:                          []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
		RFC7591ClientRegistrationEndpointURL:  "https://auth.example.com/register",
	}

	store := storage.NewMemoryStore()
	tokens := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

	return NewDefaultEndpointAuthStrategy(config, store, tokens, tokens), config, store, tokens
}

func authRequest(t *testing.T, method, url, token string) *http.Request {
	t.Helper()

	r := httptest.NewRequest(method, url, nil)
	r.Header.Set("Authorization", "Bearer "+token)

	return r
}

func mintAccessToken(t *testing.T, ctx context.Context, store *storage.MemoryStore, strategy hoauth2.AccessTokenStrategy, scopes, audience []string) string {
	t.Helper()

	request := oauth2.NewRequest()
	request.Client = &oauth2.DefaultClient{ID: "onboarding"}
	request.Session = &oauth2.DefaultSession{
		ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.AccessToken: time.Now().UTC().Add(time.Hour)},
	}

	for _, scope := range scopes {
		request.GrantScope(scope)
	}

	for _, aud := range audience {
		request.GrantAudience(aud)
	}

	token, signature, err := strategy.GenerateAccessToken(ctx, request)
	require.NoError(t, err)
	require.NoError(t, store.CreateAccessTokenSession(ctx, signature, request))

	return token
}

type permissiveAudienceClient struct {
	oauth2.Client
}

func (c *permissiveAudienceClient) GetAudienceStrategy(_ context.Context) (strategy oauth2.AudienceStrategy) {
	return func(haystack, needle []string) error { return nil }
}

type permissiveScopeClient struct {
	oauth2.Client
}

func (c *permissiveScopeClient) GetScopeStrategy(_ context.Context) (strategy oauth2.ScopeStrategy) {
	return func(haystack []string, needle string) bool { return true }
}

type hydratingAccessTokenStore struct {
	*storage.MemoryStore
}

func (s *hydratingAccessTokenStore) GetAccessTokenSession(ctx context.Context, signature string, session oauth2.Session) (request oauth2.Requester, err error) {
	if session == nil {
		return nil, errors.New("cannot hydrate a nil session")
	}

	var stored oauth2.Requester

	if stored, err = s.MemoryStore.GetAccessTokenSession(ctx, signature, session); err != nil {
		return nil, err
	}

	var data []byte

	if data, err = json.Marshal(stored.GetSession()); err != nil {
		return nil, err
	}

	if err = json.Unmarshal(data, session); err != nil {
		return nil, err
	}

	request = &oauth2.Request{
		ID:              stored.GetID(),
		RequestedAt:     stored.GetRequestedAt(),
		Client:          stored.GetClient(),
		GrantedScope:    stored.GetGrantedScopes(),
		GrantedAudience: stored.GetGrantedAudience(),
		Session:         session,
	}

	return request, nil
}
