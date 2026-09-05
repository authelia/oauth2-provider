// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestClientRegistrationTokensAreNotAccessTokens(t *testing.T) {
	ctx := context.Background()

	config := &oauth2.Config{
		GlobalSecret:                          []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
		RFC7591ClientRegistrationEndpointURL:  testEndpoint,
		TokenEntropy:                          32,
	}

	store := storage.NewMemoryStore()
	strategy := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

	client := &oauth2.DefaultClient{ID: "onboarding"}

	token, err := NewClientManagementToken(ctx, strategy, store, config, client, oauth2.Arguments{"openid"}, nil)
	require.NoError(t, err)

	signature := strategy.ClientRegistrationTokenSignature(ctx, token)
	require.NotEmpty(t, signature)

	_, err = store.GetClientRegistrationTokenSession(ctx, signature, &oauth2.DefaultSession{})
	require.NoError(t, err)

	_, err = store.GetAccessTokenSession(ctx, signature, &oauth2.DefaultSession{})
	assert.ErrorIs(t, err, oauth2.ErrNotFound)

	assert.Empty(t, strategy.AccessTokenSignature(ctx, token))
}

func TestRegistrationScopeDoesNotAuthoriseOtherEndpoints(t *testing.T) {
	ctx := context.Background()

	t.Run("ShouldRejectAnIntrospectionScopedTokenAtTheRegistrationEndpoint", func(t *testing.T) {
		auth, config, store, _ := newAuthFixtures(t)
		access := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

		token := mintAccessToken(t, ctx, store, access, []string{consts.ScopeIntrospection}, []string{testEndpoint})

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodPost, testEndpoint, token), "")

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request requires higher privileges than provided by the Access Token. The credential used to authenticate the request is not granted any of the scopes 'authelia:oauth2:client_registration', at least one of which is required.")
	})

	t.Run("ShouldAcceptARegistrationScopedToken", func(t *testing.T) {
		auth, config, store, _ := newAuthFixtures(t)
		access := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

		token := mintAccessToken(t, ctx, store, access, []string{consts.ScopeClientRegistration}, []string{testEndpoint})

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodPost, testEndpoint, token), "")

		assert.NoError(t, err)
	})

	t.Run("ShouldRejectARegistrationScopedTokenAtAnIntrospectionScopedEndpoint", func(t *testing.T) {
		requester := oauth2.NewRequest()
		requester.Session = &oauth2.DefaultSession{}
		requester.GrantScope(consts.ScopeClientRegistration)
		requester.GrantAudience(testEndpoint)

		err := oauth2.ValidateBearerAuthorization(ctx, &oauth2.Config{},
			httptest.NewRequest(http.MethodPost, testEndpoint, nil), requester, "token",
			oauth2.BearerAuthorization{Audiences: []string{testEndpoint}, Scopes: []string{consts.ScopeIntrospection}})

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request requires higher privileges than provided by the Access Token. The credential used to authenticate the request is not granted any of the scopes 'authelia:oauth2:token_introspection', at least one of which is required.")
	})
}
