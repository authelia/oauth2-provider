// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/storage"
)

func TestClientRegistrationTokenIntrospectorReportsItsOwnTokenUse(t *testing.T) {
	introspector, _, _, _, token := newIntrospectionFixture(t)

	request := oauth2.NewAccessRequest(&oauth2.DefaultSession{})

	use, err := introspector.IntrospectToken(context.Background(), token, oauth2.AccessToken, request, nil)
	require.NoError(t, err)

	assert.Equal(t, oauth2.ClientRegistrationToken, use)
	assert.Equal(t, "onboarding", request.GetClient().GetID())
}

func TestClientRegistrationTokenIntrospectorIgnoresForeignTokens(t *testing.T) {
	introspector, config, store, _, _ := newIntrospectionFixture(t)

	strategy := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

	accessRequest := oauth2.NewRequest()
	accessRequest.Session = &oauth2.DefaultSession{}

	accessToken, signature, err := strategy.GenerateAccessToken(context.Background(), accessRequest)
	require.NoError(t, err)
	require.NoError(t, store.CreateAccessTokenSession(context.Background(), signature, accessRequest))

	_, err = introspector.IntrospectToken(context.Background(), accessToken, oauth2.AccessToken, oauth2.NewAccessRequest(&oauth2.DefaultSession{}), nil)
	assert.ErrorIs(t, err, oauth2.ErrUnknownRequest)
}

func TestComposedIntrospectionResolvesAClientRegistrationToken(t *testing.T) {
	ctx := context.Background()

	introspector, config, store, _, token := newIntrospectionFixture(t)

	strategy := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

	config.TokenIntrospectionHandlers = oauth2.TokenIntrospectionHandlers{
		&hoauth2.CoreValidator{CoreStrategy: strategy, CoreStorage: store, Config: config},
		introspector,
	}

	provider := &oauth2.Fosite{Store: store, Config: config}

	use, requester, err := provider.IntrospectToken(ctx, token, oauth2.AccessToken, &oauth2.DefaultSession{})
	require.NoError(t, err)

	assert.Equal(t, oauth2.ClientRegistrationToken, use)
	assert.Equal(t, "onboarding", requester.GetClient().GetID())
}

func TestComposedIntrospectionRejectsAnUnknownToken(t *testing.T) {
	ctx := context.Background()

	introspector, config, store, _, _ := newIntrospectionFixture(t)

	strategy := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

	config.TokenIntrospectionHandlers = oauth2.TokenIntrospectionHandlers{
		&hoauth2.CoreValidator{CoreStrategy: strategy, CoreStorage: store, Config: config},
		introspector,
	}

	provider := &oauth2.Fosite{Store: store, Config: config}

	_, _, err := provider.IntrospectToken(ctx, "authelia_cr_notreal.notreal", oauth2.AccessToken, &oauth2.DefaultSession{})
	assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
}

func newIntrospectionFixture(t *testing.T) (*ClientRegistrationTokenIntrospector, *oauth2.Config, *storage.MemoryStore, ClientRegistrationTokenStrategy, string) {
	t.Helper()

	config := &oauth2.Config{
		GlobalSecret:                          []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
		RFC7591ClientRegistrationEndpointURL:  testEndpoint,
		TokenEntropy:                          32,
	}

	store := storage.NewMemoryStore()
	strategy := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

	token, err := NewClientManagementToken(context.Background(), strategy, store, config, &oauth2.DefaultClient{ID: "onboarding"}, oauth2.Arguments{"openid"}, nil)
	require.NoError(t, err)

	return &ClientRegistrationTokenIntrospector{Store: store, Strategy: strategy, Config: config}, config, store, strategy, token
}
