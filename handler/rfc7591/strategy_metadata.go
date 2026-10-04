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
type ClientRegistrationMetadataStrategyConfig interface {
	// GetDPoPEnabled returns true if DPoP handling is enabled.
	GetDPoPEnabled(ctx context.Context) (enabled bool)

	// GetMTLSEnabled returns true if RFC 8705 handling is enabled.
	GetMTLSEnabled(ctx context.Context) (enabled bool)
}

// DefaultClientRegistrationMetadataStrategy is the default oauth2.ClientRegistrationMetadataStrategy. It removes the
// client metadata belonging to a feature the server has disabled.
//
// It only clears values on the *oauth2.ClientRegistrationMetadata passed to it and never writes to the store, so a
// read is non-destructive. The registration and configuration-update call sites persist a client built from the
// filtered metadata, so a client registered or updated while a feature is disabled loses that feature's values in
// storage too.
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

		// The authentication method is cleared alongside the subject values it selects between, as LocalValidator
		// rejects a subject value registered without 'tls_client_auth'. An emptied TokenEndpointAuthMethod falls back
		// to 'client_secret_basic', and the introspection and revocation methods inherit the token endpoint method.
		metadata.TokenEndpointAuthMethod = clearMutualTLSAuthMethod(metadata.TokenEndpointAuthMethod)
		metadata.IntrospectionEndpointAuthMethod = clearMutualTLSAuthMethod(metadata.IntrospectionEndpointAuthMethod)
		metadata.RevocationEndpointAuthMethod = clearMutualTLSAuthMethod(metadata.RevocationEndpointAuthMethod)
	}

	if !s.config.GetDPoPEnabled(ctx) {
		metadata.DPoPBoundAccessTokens = false
	}

	return nil
}

func clearMutualTLSAuthMethod(method string) string {
	switch method {
	case consts.ClientAuthMethodTLSClientAuth, consts.ClientAuthMethodSelfSignedTLSClientAuth:
		return ""
	default:
		return method
	}
}

// metadataStrategy returns the configured oauth2.ClientRegistrationMetadataStrategy, falling back to
// DefaultClientRegistrationMetadataStrategy when none is configured.
func metadataStrategy(ctx context.Context, config Configurator) (strategy oauth2.ClientRegistrationMetadataStrategy) {
	if strategy = config.GetRFC7591ClientRegistrationMetadataStrategy(ctx); strategy != nil {
		return strategy
	}

	return NewDefaultClientRegistrationMetadataStrategy(config)
}

var (
	_ oauth2.ClientRegistrationMetadataStrategy = (*DefaultClientRegistrationMetadataStrategy)(nil)
)
