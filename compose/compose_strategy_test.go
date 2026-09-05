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

func TestComposePanicsWhenTheCoreStrategyCannotIssueClientRegistrationTokens(t *testing.T) {
	testCases := []struct {
		name     string
		strategy func(config *oauth2.Config) any
		factory  Factory
		expected string
	}{
		{
			name: "ShouldPanicForACoreStrategyMissingTheTokenMethods",
			strategy: func(config *oauth2.Config) any {
				return &CommonStrategy{CoreStrategy: coreStrategyWithoutClientRegistration{CoreStrategy: NewOAuth2HMACStrategy(config)}}
			},
			factory:  RFC7591ClientRegistrationFactory,
			expected: "compose: CommonStrategy.CoreStrategy (compose.coreStrategyWithoutClientRegistration) does not implement rfc7591.ClientRegistrationTokenStrategy: missing ClientRegistrationTokenSignature, GenerateClientRegistrationToken, ValidateClientRegistrationToken; use *hoauth2.HMACCoreStrategy, *hoauth2.JWTProfileCoreStrategy, or implement these methods on your CoreStrategy",
		},
		{
			name:     "ShouldPanicForANilCoreStrategy",
			strategy: func(config *oauth2.Config) any { return &CommonStrategy{} },
			factory:  RFC7592ClientConfigurationFactory,
			expected: "compose: CommonStrategy.CoreStrategy (<nil>) does not implement rfc7591.ClientRegistrationTokenStrategy: missing ClientRegistrationTokenSignature, GenerateClientRegistrationToken, ValidateClientRegistrationToken; use *hoauth2.HMACCoreStrategy, *hoauth2.JWTProfileCoreStrategy, or implement these methods on your CoreStrategy",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := newRFC7591Config()

			recovered := recoverPanic(func() {
				Compose(config, storage.NewMemoryStore(), tc.strategy(config), tc.factory)
			})

			require.NotNil(t, recovered)

			err, ok := recovered.(error)
			require.Truef(t, ok, "panic value was %T", recovered)

			assert.EqualError(t, err, tc.expected)
		})
	}
}

func TestComposeAcceptsAValueCommonStrategy(t *testing.T) {
	config := newRFC7591Config()

	var provider oauth2.Provider

	recovered := recoverPanic(func() {
		provider = Compose(config, storage.NewMemoryStore(), CommonStrategy{CoreStrategy: NewOAuth2HMACStrategy(config)}, RFC7591ClientRegistrationFactory, RFC7592ClientConfigurationFactory)
	})

	require.Nil(t, recovered)
	require.NotNil(t, provider)

	assert.Len(t, config.GetRFC7591ClientRegistrationEndpointHandlers(context.Background()), 1)
	assert.Len(t, config.GetRFC7592ClientConfigurationEndpointHandlers(context.Background()), 1)
}

func newRFC7591Config() *oauth2.Config {
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

type coreStrategyWithoutClientRegistration struct {
	hoauth2.CoreStrategy
}
