// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/handler/rfc7591"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
)

func TestRegistrationTokenIntrospectionThroughComposedProvider(t *testing.T) {
	provider, config, store := newRegistrationTokenIntrospectionFixture(t, true)
	strategy := compose.NewOAuth2HMACStrategy(config)

	token, err := rfc7591.NewClientManagementToken(context.Background(), strategy, store, config, &oauth2.DefaultClient{ID: "onboarding"}, oauth2.Arguments{"openid"}, nil)
	require.NoError(t, err)

	use, requester, err := provider.IntrospectToken(context.Background(), token, oauth2.AccessToken, &oauth2.DefaultSession{})
	require.NoError(t, err)
	assert.Equal(t, oauth2.ClientRegistrationToken, use)
	require.NotNil(t, requester)
	assert.Equal(t, "onboarding", requester.GetClient().GetID())
}

func TestRegistrationTokenIntrospectionDisabledByDefaultThroughComposedProvider(t *testing.T) {
	provider, config, store := newRegistrationTokenIntrospectionFixture(t, false)

	strategy := compose.NewOAuth2HMACStrategy(config)

	token, err := rfc7591.NewClientManagementToken(context.Background(), strategy, store, config, &oauth2.DefaultClient{ID: "onboarding"}, oauth2.Arguments{"openid"}, nil)
	require.NoError(t, err)

	use, _, err := provider.IntrospectToken(context.Background(), token, oauth2.AccessToken, &oauth2.DefaultSession{})
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
	assert.Empty(t, use)
}

func TestExpiredAccessTokenIsNotSilentlyDowngradedToUnknown(t *testing.T) {
	provider, config, store := newRegistrationTokenIntrospectionFixture(t, true)

	strategy := compose.NewOAuth2HMACStrategy(config)

	request := oauth2.NewRequest()
	request.Client = &oauth2.DefaultClient{ID: "some-client"}
	request.Session = &oauth2.DefaultSession{
		ExpiresAt: map[oauth2.TokenType]time.Time{
			oauth2.AccessToken: time.Now().Add(-time.Hour),
		},
	}

	tokenString, signature, err := strategy.GenerateAccessToken(context.Background(), request)
	require.NoError(t, err)
	require.NoError(t, store.CreateAccessTokenSession(context.Background(), signature, request))

	_, _, err = provider.IntrospectToken(context.Background(), tokenString, oauth2.AccessToken, &oauth2.DefaultSession{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, oauth2.ErrTokenExpired), "an expired access token must still report its real failure")
	assert.False(t, errors.Is(err, oauth2.ErrUnknownRequest), "an expired-but-present access token must not be silently reported as unrecognised")
}

func TestExpiredRefreshTokenIsNotSilentlyDowngradedToUnknown(t *testing.T) {
	provider, config, store := newRegistrationTokenIntrospectionFixture(t, true)

	strategy := compose.NewOAuth2HMACStrategy(config)

	request := oauth2.NewRequest()
	request.Client = &oauth2.DefaultClient{ID: "some-client"}
	request.Session = &oauth2.DefaultSession{
		ExpiresAt: map[oauth2.TokenType]time.Time{
			oauth2.RefreshToken: time.Now().Add(-time.Hour),
		},
	}

	tokenString, signature, err := strategy.GenerateRefreshToken(context.Background(), request)
	require.NoError(t, err)
	require.NoError(t, store.CreateRefreshTokenSession(context.Background(), signature, "", request))

	_, _, err = provider.IntrospectToken(context.Background(), tokenString, "", &oauth2.DefaultSession{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, oauth2.ErrTokenExpired), "an expired refresh token must still report its real failure")
	assert.False(t, errors.Is(err, oauth2.ErrUnknownRequest), "an expired-but-present refresh token must not be silently reported as unrecognised")
}

func newRegistrationTokenIntrospectionFixture(t *testing.T, includeIntrospection bool) (provider oauth2.Provider, config *oauth2.Config, store *storage.MemoryStore) {
	t.Helper()

	config = &oauth2.Config{
		GlobalSecret:                          []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
		RFC7591ClientRegistrationEndpointURL:  "https://auth.example.com/register",
		RFC7591ClientRegistrationStrategy:     rfc7591.NewDefaultClientRegistrationStrategy(),
		TokenEntropy:                          32,
	}

	store = storage.NewMemoryStore()
	provider = compose.ComposeAllEnabled(config, store, gen.MustRSAKey())

	if includeIntrospection {
		compose.Compose(config, store, compose.NewOAuth2HMACStrategy(config), compose.RFC7591ClientRegistrationTokenIntrospectionFactory)
	}

	return provider, config, store
}
