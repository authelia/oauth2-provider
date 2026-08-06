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

	assert.Empty(t, strategy.AccessTokenSignature(ctx, token), "a registration token must not yield an access token signature")
}
