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
// or when that secret is identical to the global secret. It fails here, while the provider is being composed,
// rather than at the first request: a missing, too-short, or shared secret makes every client registration token
// unmintable, unverifiable, or silently dependent on the global secret's rotation schedule, and a deployment must
// learn that at start-up.
//
// Every call site below passes context.Background(): the Factory signature this is composed under does not carry a
// caller context, so a GetRFC7591ClientRegistrationGlobalSecret or GetGlobalSecret implementation backed by a
// network round trip - a KMS or vault lookup, say - runs here with no deadline and no cancellation.
func mustClientRegistrationSecret(ctx context.Context, config oauth2.Configurator) {
	secret, err := config.GetRFC7591ClientRegistrationGlobalSecret(ctx)

	// GetRFC7591ClientRegistrationGlobalSecret returns a nil error for every in-tree implementation - see
	// Config.GetRFC7591ClientRegistrationGlobalSecret in config_default.go - so this branch is unreachable against
	// this repository's own Config. It is kept because RFC7591ClientRegistrationConfigProvider is a public interface
	// a third-party configuration (one backed by a vault or KMS lookup, say) may legitimately implement with a
	// getter that can fail, and that failure deserves the same start-up-time treatment as a missing secret.
	if err != nil {
		panic(fmt.Errorf("the RFC 7591 client registration handlers require a client registration token secret but reading it returned an error: %w", err))
	}

	if len(secret) < minimumClientRegistrationSecretLength {
		panic(fmt.Errorf("the RFC 7591 client registration handlers require Config.RFC7591ClientRegistrationGlobalSecret to be set to at least %d bytes, which is deliberately separate from the global secret because client management tokens never expire", minimumClientRegistrationSecretLength))
	}

	global, err := config.GetGlobalSecret(ctx)

	// Same unreachable-in-tree, kept-for-third-parties reasoning as above: Config.GetGlobalSecret also always
	// returns a nil error.
	if err != nil {
		panic(fmt.Errorf("the RFC 7591 client registration handlers require the global secret, to confirm it differs from the client registration token secret, but reading it returned an error: %w", err))
	}

	// The client registration secret must differ from the CURRENT global secret specifically, not merely be present:
	// GlobalSecret is expected to rotate routinely (its old values move to RotatedGlobalSecrets, kept only to
	// validate tokens already signed with them), while Config.RFC7591ClientRegistrationGlobalSecret is a wholly
	// separate field that this package never touches during a rotation. An integrator who copies the global secret's
	// current value into the registration field - directly, or by pointing both at the same secrets-manager entry -
	// gets a provider that composes and passes every test, right up until the next routine global secret rotation,
	// at which point every already-issued, never-expiring client management token is permanently unverifiable with
	// no re-issue path under RFC 7592, because the client can no longer authenticate to ask for a new one.
	//
	// RotatedGlobalSecrets is deliberately not checked here: those values are already retired from signing new
	// global-secret material and exist only as a validation fallback during a rotation window, so a registration
	// secret that happens to match one carries none of that forward-rotation hazard - nothing rotates it out from
	// under the registration secret the way GlobalSecret does.
	if bytes.Equal(secret, global) {
		panic(errors.New("the RFC 7591 client registration handlers require Config.RFC7591ClientRegistrationGlobalSecret to differ from Config.GlobalSecret: reusing the global secret defeats the separation this field exists for, because the global secret is expected to rotate routinely while client management tokens never expire, so the first global secret rotation would silently and permanently lock every registered client out of its own registration"))
	}
}
