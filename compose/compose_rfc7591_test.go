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
		GlobalSecret:                          []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
		RFC7591ClientRegistrationEndpointURL:  "https://auth.example.com/register",
		RFC7591ClientRegistrationStrategy:     rfc7591.NewDefaultClientRegistrationStrategy(),
		TokenEntropy:                          32,
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
		GlobalSecret:                          []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
		RFC7591ClientRegistrationEndpointURL:  "https://auth.example.com/register",
		RFC7591ClientRegistrationStrategy:     rfc7591.NewDefaultClientRegistrationStrategy(),
		TokenEntropy:                          32,
	}

	key := gen.MustRSAKey()

	provider := ComposeAllEnabled(config, storage.NewMemoryStore(), key)
	require.NotNil(t, provider)

	assert.Len(t, config.GetRFC7591ClientRegistrationEndpointHandlers(ctx), 1)
	assert.Len(t, config.GetRFC7592ClientConfigurationEndpointHandlers(ctx), 1)
}

func TestRFC7591FactoriesRequireAClientRegistrationSecret(t *testing.T) {
	config := &oauth2.Config{GlobalSecret: []byte("super-duper-secret-that-is-at-least-32-bytes")}

	strategy := NewOAuth2HMACStrategy(config)
	store := storage.NewMemoryStore()

	expected := "the RFC 7591 client registration handlers require Config.RFC7591ClientRegistrationGlobalSecret to be set to at least 32 bytes, which is deliberately separate from the global secret because client management tokens never expire"

	testCases := []struct {
		name    string
		factory Factory
	}{
		{"RFC7591ClientRegistrationFactory", RFC7591ClientRegistrationFactory},
		{"RFC7592ClientConfigurationFactory", RFC7592ClientConfigurationFactory},
		{"RFC7591ClientRegistrationTokenIntrospectionFactory", RFC7591ClientRegistrationTokenIntrospectionFactory},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.PanicsWithError(t, expected, func() {
				tc.factory(config, store, strategy)
			})
		})
	}
}

func TestRFC7591FactoriesRejectATooShortClientRegistrationSecret(t *testing.T) {
	config := &oauth2.Config{
		GlobalSecret:                          []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("short-secret"),
	}

	strategy := NewOAuth2HMACStrategy(config)

	assert.PanicsWithError(t, "the RFC 7591 client registration handlers require Config.RFC7591ClientRegistrationGlobalSecret to be set to at least 32 bytes, which is deliberately separate from the global secret because client management tokens never expire", func() {
		RFC7591ClientRegistrationFactory(config, storage.NewMemoryStore(), strategy)
	})
}

func TestRFC7591FactoriesRejectASharedClientRegistrationSecret(t *testing.T) {
	shared := []byte("super-duper-secret-that-is-at-least-32-bytes")

	config := &oauth2.Config{
		GlobalSecret:                          shared,
		RFC7591ClientRegistrationGlobalSecret: shared,
	}

	strategy := NewOAuth2HMACStrategy(config)
	store := storage.NewMemoryStore()

	expected := "the RFC 7591 client registration handlers require Config.RFC7591ClientRegistrationGlobalSecret to differ from Config.GlobalSecret: reusing the global secret defeats the separation this field exists for, because the global secret is expected to rotate routinely while client management tokens never expire, so the first global secret rotation would silently and permanently lock every registered client out of its own registration"

	testCases := []struct {
		name    string
		factory Factory
	}{
		{"RFC7591ClientRegistrationFactory", RFC7591ClientRegistrationFactory},
		{"RFC7592ClientConfigurationFactory", RFC7592ClientConfigurationFactory},
		{"RFC7591ClientRegistrationTokenIntrospectionFactory", RFC7591ClientRegistrationTokenIntrospectionFactory},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.PanicsWithError(t, expected, func() {
				tc.factory(config, store, strategy)
			})
		})
	}
}

func TestComposeAllEnabledOmitsRegistrationTokenIntrospection(t *testing.T) {
	config := &oauth2.Config{
		GlobalSecret:                          []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
	}

	_ = ComposeAllEnabled(config, storage.NewMemoryStore(), nil)

	for _, introspector := range config.GetTokenIntrospectionHandlers(context.Background()) {
		_, ok := introspector.(*rfc7591.ClientRegistrationTokenIntrospector)
		assert.False(t, ok)
	}
}
