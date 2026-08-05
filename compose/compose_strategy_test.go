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

// coreStrategyWithoutClientRegistration wraps a real hoauth2.CoreStrategy behind the bare interface, reproducing what
// a consumer's own hoauth2.CoreStrategy implementation looks like from CommonStrategy's perspective: even though the
// wrapped *hoauth2.HMACCoreStrategy genuinely has ClientRegistrationTokenSignature, GenerateClientRegistrationToken
// and ValidateClientRegistrationToken, embedding it here as the hoauth2.CoreStrategy interface means none of those
// three methods are promoted onto coreStrategyWithoutClientRegistration itself - only the methods hoauth2.CoreStrategy
// declares are. This is the exact shape of a misconfigured CoreStrategy the tests below must catch at compose time.
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

// recoverPanic runs fn and returns what it recovered, or nil if fn did not panic.
func recoverPanic(fn func()) (recovered any) {
	defer func() { recovered = recover() }()

	fn()

	return recovered
}

// TestClientRegistrationTokenStrategyFailsAtComposeForUnsupportedCoreStrategy is the regression test for the review
// finding that RFC7591ClientRegistrationFactory and RFC7592ClientConfigurationFactory used to accept any
// *CommonStrategy unconditionally - because forwarding methods on *CommonStrategy made the factory's outer type
// assertion trivially succeed - deferring the real check on CoreStrategy to the first request that reached one of
// those forwarding methods. A consumer supplying a CoreStrategy that does not implement
// rfc7591.ClientRegistrationTokenStrategy must instead fail here, in Compose, with a message naming the CoreStrategy
// field and the methods it lacks.
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

// TestClientRegistrationTokenStrategyFailsAtComposeForNilCoreStrategy covers the same finding for the degenerate case
// of a CommonStrategy left with a nil CoreStrategy entirely - it must fail identically to an unsupported one, not
// panic with an unhelpful nil-dereference somewhere downstream.
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

// TestClientRegistrationTokenStrategySucceedsForValueCommonStrategy is the regression test for the review finding
// that the (now removed) forwarding methods on *CommonStrategy had pointer receivers, so a CommonStrategy passed by
// value silently stopped satisfying rfc7591.ClientRegistrationTokenStrategy and panicked at Compose. Resolution
// happens by reaching into CoreStrategy directly (see mustClientRegistrationTokenStrategy), which works identically
// whether CommonStrategy is held by value or by pointer, so both must succeed here.
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
