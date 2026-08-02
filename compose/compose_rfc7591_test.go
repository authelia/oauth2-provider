// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/rfc7591"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
)

func TestRFC7591Factories(t *testing.T) {
	ctx := context.Background()

	config := &oauth2.Config{
		GlobalSecret:                         []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationEndpointURL: "https://auth.example.com/register",
		RFC7591ClientRegistrationStrategy:    rfc7591.NewDefaultClientRegistrationStrategy(),
		TokenEntropy:                         32,
	}

	store := storage.NewMemoryStore()
	strategy := NewOAuth2HMACStrategy(config)

	registration := RFC7591ClientRegistrationFactory(config, store, strategy)
	require.Implements(t, (*oauth2.RFC7591ClientRegistrationEndpointHandler)(nil), registration)

	configuration := RFC7592ClientConfigurationFactory(config, store, strategy)
	require.Implements(t, (*oauth2.RFC7592ClientConfigurationEndpointHandler)(nil), configuration)

	provider := Compose(config, store, strategy, RFC7591ClientRegistrationFactory, RFC7592ClientConfigurationFactory)
	require.NotNil(t, provider)

	assert.Len(t, config.GetRFC7591ClientRegistrationEndpointHandlers(ctx), 1)
	assert.Len(t, config.GetRFC7592ClientConfigurationEndpointHandlers(ctx), 1)
}

func TestComposeAllEnabledIncludesRFC7591(t *testing.T) {
	ctx := context.Background()

	config := &oauth2.Config{
		GlobalSecret:                         []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationEndpointURL: "https://auth.example.com/register",
		RFC7591ClientRegistrationStrategy:    rfc7591.NewDefaultClientRegistrationStrategy(),
		TokenEntropy:                         32,
	}

	key := gen.MustRSAKey()

	provider := ComposeAllEnabled(config, storage.NewMemoryStore(), key)
	require.NotNil(t, provider)

	assert.Len(t, config.GetRFC7591ClientRegistrationEndpointHandlers(ctx), 1)
	assert.Len(t, config.GetRFC7592ClientConfigurationEndpointHandlers(ctx), 1)
}
