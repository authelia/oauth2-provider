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
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/rfc7591"
	"authelia.com/provider/oauth2/storage"
)

func TestClientRegistrationTokenStrategyFailsAtComposeForUnsupportedCoreStrategy(t *testing.T) {
	config := rfc7591TestConfig()
	store := storage.NewMemoryStore()

	strategy := &CommonStrategy{
		CoreStrategy: coreStrategyWithoutClientRegistration{CoreStrategy: NewOAuth2HMACStrategy(config)},
	}

	recovered := recoverPanic(func() {
		Compose(config, store, strategy, RFC7591ClientRegistrationFactory)
	})

	require.NotNil(t, recovered, "Compose must panic at compose time when CoreStrategy does not implement rfc7591.ClientRegistrationTokenStrategy")

	err, ok := recovered.(error)
	require.Truef(t, ok, "expected the panic value to be an error, got %T: %v", recovered, recovered)

	msg := err.Error()
	assert.Contains(t, msg, "CoreStrategy")
	assert.Contains(t, msg, "ClientRegistrationTokenSignature")
	assert.Contains(t, msg, "GenerateClientRegistrationToken")
	assert.Contains(t, msg, "ValidateClientRegistrationToken")
}

func TestClientRegistrationTokenStrategyFailsAtComposeForNilCoreStrategy(t *testing.T) {
	config := rfc7591TestConfig()
	store := storage.NewMemoryStore()

	strategy := &CommonStrategy{}

	recovered := recoverPanic(func() {
		Compose(config, store, strategy, RFC7592ClientConfigurationFactory)
	})

	require.NotNil(t, recovered, "Compose must panic at compose time when CoreStrategy is nil")

	err, ok := recovered.(error)
	require.Truef(t, ok, "expected the panic value to be an error, got %T: %v", recovered, recovered)

	msg := err.Error()
	assert.Contains(t, msg, "CoreStrategy")
	assert.Contains(t, msg, "ClientRegistrationTokenSignature")
	assert.Contains(t, msg, "GenerateClientRegistrationToken")
	assert.Contains(t, msg, "ValidateClientRegistrationToken")
}

func TestClientRegistrationTokenStrategySucceedsForValueCommonStrategy(t *testing.T) {
	config := rfc7591TestConfig()
	store := storage.NewMemoryStore()

	strategy := CommonStrategy{CoreStrategy: NewOAuth2HMACStrategy(config)}

	var provider oauth2.Provider

	recovered := recoverPanic(func() {
		provider = Compose(config, store, strategy, RFC7591ClientRegistrationFactory, RFC7592ClientConfigurationFactory)
	})

	require.Nil(t, recovered, "Compose must not panic for a value CommonStrategy whose CoreStrategy is well-formed")
	require.NotNil(t, provider)

	assert.Len(t, config.GetRFC7591ClientRegistrationEndpointHandlers(context.Background()), 1)
	assert.Len(t, config.GetRFC7592ClientConfigurationEndpointHandlers(context.Background()), 1)
}

type coreStrategyWithoutClientRegistration struct {
	hoauth2.CoreStrategy
}

func rfc7591TestConfig() *oauth2.Config {
	return &oauth2.Config{
		GlobalSecret:                          []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
		RFC7591ClientRegistrationEndpointURL:  "https://auth.example.com/register",
		RFC7591ClientRegistrationStrategy:     rfc7591.NewDefaultClientRegistrationStrategy(),
		TokenEntropy:                          32,
	}
}

func recoverPanic(fn func()) (recovered any) {
	defer func() { recovered = recover() }()

	fn()

	return recovered
}
