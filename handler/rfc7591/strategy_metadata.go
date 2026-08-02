// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

// ClientRegistrationMetadataStrategyConfig is the configuration DefaultClientRegistrationMetadataStrategy consults
// to decide whether a feature's client metadata may be registered and returned.
//
// It restates the two 'enabled' getters rather than embedding oauth2.DPoPConfigProvider and oauth2.MTLSConfigProvider,
// which together carry ten methods where two are needed. Go interfaces are structural, so any configuration already
// satisfying those providers satisfies this one without change.
type ClientRegistrationMetadataStrategyConfig interface {
	// GetDPoPEnabled returns true if DPoP handling is enabled.
	GetDPoPEnabled(ctx context.Context) (enabled bool)

	// GetMTLSEnabled returns true if RFC 8705 handling is enabled.
	GetMTLSEnabled(ctx context.Context) (enabled bool)
}

// DefaultClientRegistrationMetadataStrategy is the default oauth2.ClientRegistrationMetadataStrategy. It removes the
// client metadata belonging to a feature the server has disabled, so such a value is never validated against, never
// persisted, and never returned to the client describing a capability it does not have.
//
// It only ever clears values on the *oauth2.ClientRegistrationMetadata passed to it; nothing here writes to the
// store. That makes a read non-destructive: a client persisted while a feature was enabled keeps its stored values
// and advertises them again once the feature is read back after being re-enabled. It does not make a write
// non-destructive: the registration and configuration-update call sites persist a client built from the filtered
// metadata, so a client that registers or updates itself while a feature is disabled has that feature's values
// cleared in storage too, not only in the response, and re-enabling the feature will not restore them.
type DefaultClientRegistrationMetadataStrategy struct {
	config ClientRegistrationMetadataStrategyConfig
}

// NewDefaultClientRegistrationMetadataStrategy returns a new *DefaultClientRegistrationMetadataStrategy.
func NewDefaultClientRegistrationMetadataStrategy(config ClientRegistrationMetadataStrategyConfig) (strategy *DefaultClientRegistrationMetadataStrategy) {
	return &DefaultClientRegistrationMetadataStrategy{config: config}
}

// FilterClientRegistrationMetadata implements oauth2.ClientRegistrationMetadataStrategy. client is unused: whether a
// feature is available is a property of the server, not of the client the metadata belongs to.
func (s *DefaultClientRegistrationMetadataStrategy) FilterClientRegistrationMetadata(ctx context.Context, client oauth2.Client, metadata *oauth2.ClientRegistrationMetadata) (err error) {
	if metadata == nil {
		return nil
	}

	if !s.config.GetMTLSEnabled(ctx) {
		metadata.TLSClientAuthSubjectDN = ""
		metadata.TLSClientAuthSANDNS = ""
		metadata.TLSClientAuthSANURI = ""
		metadata.TLSClientAuthSANIP = ""
		metadata.TLSClientAuthSANEmail = ""
		metadata.TLSClientCertificateBoundAccessTokens = false

		// The authentication method is cleared alongside the subject values it selects between, keeping the result
		// internally coherent: LocalValidator rejects a subject value registered without 'tls_client_auth', so
		// clearing only half would fail validation over metadata that was about to be discarded anyway. Clearing
		// narrows rather than widens at all three endpoints: an emptied TokenEndpointAuthMethod falls back to the
		// 'client_secret_basic' default per OpenID Connect Dynamic Client Registration 1.0 Section 2, so the client
		// is issued a secret, and an emptied IntrospectionEndpointAuthMethod or RevocationEndpointAuthMethod
		// inherits that token endpoint method (see DefaultRegisteredClient.GetIntrospectionEndpointAuthMethod).
		metadata.TokenEndpointAuthMethod = clearMutualTLSAuthMethod(metadata.TokenEndpointAuthMethod)
		metadata.IntrospectionEndpointAuthMethod = clearMutualTLSAuthMethod(metadata.IntrospectionEndpointAuthMethod)
		metadata.RevocationEndpointAuthMethod = clearMutualTLSAuthMethod(metadata.RevocationEndpointAuthMethod)
	}

	if !s.config.GetDPoPEnabled(ctx) {
		metadata.DPoPBoundAccessTokens = false
	}

	return nil
}

// clearMutualTLSAuthMethod returns an empty string when method names one of the two RFC 8705 mutual-TLS client
// authentication methods, and method unchanged otherwise.
func clearMutualTLSAuthMethod(method string) string {
	switch method {
	case consts.ClientAuthMethodTLSClientAuth, consts.ClientAuthMethodSelfSignedTLSClientAuth:
		return ""
	default:
		return method
	}
}

// metadataStrategy returns the configured oauth2.ClientRegistrationMetadataStrategy, falling back to
// DefaultClientRegistrationMetadataStrategy when none is configured. The fallback is what makes the gating correct
// out of the box: an integrator who has never heard of this seam still gets metadata for disabled features removed,
// which is the safe default. Configuring a strategy explicitly replaces it, including with one that filters nothing.
func metadataStrategy(ctx context.Context, config Configurator) (strategy oauth2.ClientRegistrationMetadataStrategy) {
	if strategy = config.GetRFC7591ClientRegistrationMetadataStrategy(ctx); strategy != nil {
		return strategy
	}

	return NewDefaultClientRegistrationMetadataStrategy(config)
}

var _ oauth2.ClientRegistrationMetadataStrategy = (*DefaultClientRegistrationMetadataStrategy)(nil)
