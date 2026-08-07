// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/rfc7591"
)

// RFC7591ClientRegistrationFactory creates the OAuth 2.0 Dynamic Client Registration (RFC 7591) endpoint handler.
func RFC7591ClientRegistrationFactory(config oauth2.Configurator, storage any, strategy any) any {
	mustClientRegistrationSecret(context.Background(), config)

	return &rfc7591.ClientRegistrationHandler{
		Store:    storage.(rfc7591.Storage),
		Strategy: mustClientRegistrationTokenStrategy(strategy),
		Config:   config,
	}
}

// RFC7592ClientConfigurationFactory creates the OAuth 2.0 Dynamic Client Registration Management (RFC 7592) endpoint
// handler.
func RFC7592ClientConfigurationFactory(config oauth2.Configurator, storage any, strategy any) any {
	mustClientRegistrationSecret(context.Background(), config)

	return &rfc7591.ClientConfigurationHandler{
		Store:    storage.(rfc7591.Storage),
		Strategy: mustClientRegistrationTokenStrategy(strategy),
		Config:   config,
	}
}

// RFC7591ClientRegistrationTokenIntrospectionFactory creates the token introspection handler for RFC 7591 / RFC 7592
// client registration tokens. It is opt-in by composition: it is not part of ComposeAllEnabled, so a deployment
// that wants registration tokens visible at the introspection endpoint must compose it explicitly.
func RFC7591ClientRegistrationTokenIntrospectionFactory(config oauth2.Configurator, storage any, strategy any) any {
	mustClientRegistrationSecret(context.Background(), config)

	return &rfc7591.ClientRegistrationTokenIntrospector{
		Store:    storage.(rfc7591.Storage),
		Strategy: mustClientRegistrationTokenStrategy(strategy),
		Config:   config,
	}
}

// mustClientRegistrationSecret panics when no client registration token secret of sufficient length is configured,
// or when that secret is identical to the global secret. It fails while the provider is being composed rather than at
// the first request, because a missing, too-short, or shared secret makes every client registration token unmintable,
// unverifiable, or silently dependent on the global secret's rotation schedule.
//
// Every call site passes context.Background(), since the Factory signature this is composed under carries no caller
// context. A GetRFC7591ClientRegistrationGlobalSecret or GetGlobalSecret implementation backed by a network round
// trip therefore runs here with no deadline and no cancellation.
func mustClientRegistrationSecret(ctx context.Context, config oauth2.Configurator) {
	secret, err := config.GetRFC7591ClientRegistrationGlobalSecret(ctx)

	// Unreachable against this repository's own Config, which always returns a nil error. It is kept because
	// RFC7591ClientRegistrationConfigProvider is a public interface a third-party configuration may implement with a
	// getter that can fail.
	if err != nil {
		panic(fmt.Errorf("the RFC 7591 client registration handlers require a client registration token secret but reading it returned an error: %w", err))
	}

	if len(secret) < minimumClientRegistrationSecretLength {
		panic(fmt.Errorf("the RFC 7591 client registration handlers require Config.RFC7591ClientRegistrationGlobalSecret to be set to at least %d bytes, which is deliberately separate from the global secret because client management tokens never expire", minimumClientRegistrationSecretLength))
	}

	global, err := config.GetGlobalSecret(ctx)

	// Unreachable in-tree for the same reason as above: Config.GetGlobalSecret always returns a nil error.
	if err != nil {
		panic(fmt.Errorf("the RFC 7591 client registration handlers require the global secret, to confirm it differs from the client registration token secret, but reading it returned an error: %w", err))
	}

	// The registration secret must differ from the CURRENT global secret specifically. GlobalSecret is expected to
	// rotate routinely, with its old values moving to RotatedGlobalSecrets, while
	// Config.RFC7591ClientRegistrationGlobalSecret is a separate field this package never touches during a rotation.
	// An integrator copying the global secret's current value into the registration field gets a provider that
	// composes and passes every test until the next global secret rotation, at which point every already-issued,
	// never-expiring client management token is permanently unverifiable with no re-issue path under RFC 7592.
	//
	// RotatedGlobalSecrets is not checked: those values are already retired from signing and exist only as a
	// validation fallback, so a registration secret matching one carries no forward-rotation hazard.
	if bytes.Equal(secret, global) {
		panic(errors.New("the RFC 7591 client registration handlers require Config.RFC7591ClientRegistrationGlobalSecret to differ from Config.GlobalSecret: reusing the global secret defeats the separation this field exists for, because the global secret is expected to rotate routinely while client management tokens never expire, so the first global secret rotation would silently and permanently lock every registered client out of its own registration"))
	}
}
