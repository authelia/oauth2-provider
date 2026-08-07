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
)

func TestDefaultClientRegistrationMetadataStrategyStripsMTLSWhenDisabled(t *testing.T) {
	strategy := NewDefaultClientRegistrationMetadataStrategy(&oauth2.Config{DPoPEnabled: true})

	metadata := newFilterMetadata()

	require.NoError(t, strategy.FilterClientRegistrationMetadata(context.Background(), nil, metadata))

	assert.Empty(t, metadata.TLSClientAuthSubjectDN)
	assert.Empty(t, metadata.TLSClientAuthSANDNS)
	assert.Empty(t, metadata.TLSClientAuthSANURI)
	assert.Empty(t, metadata.TLSClientAuthSANIP)
	assert.Empty(t, metadata.TLSClientAuthSANEmail)
	assert.False(t, metadata.TLSClientCertificateBoundAccessTokens)

	assert.Empty(t, metadata.TokenEndpointAuthMethod)
	assert.Empty(t, metadata.IntrospectionEndpointAuthMethod)
	assert.Empty(t, metadata.RevocationEndpointAuthMethod)

	assert.True(t, metadata.DPoPBoundAccessTokens)
	assert.Equal(t, "Example", metadata.ClientName)
	assert.Equal(t, []string{"https://example.com/cb"}, metadata.RedirectURIs)
}

func TestDefaultClientRegistrationMetadataStrategyPreservesMTLSWhenEnabled(t *testing.T) {
	strategy := NewDefaultClientRegistrationMetadataStrategy(&oauth2.Config{MTLSEnabled: true, DPoPEnabled: true})

	metadata := newFilterMetadata()

	require.NoError(t, strategy.FilterClientRegistrationMetadata(context.Background(), nil, metadata))

	assert.Equal(t, "CN=client,O=Example", metadata.TLSClientAuthSubjectDN)
	assert.Equal(t, "client.example.com", metadata.TLSClientAuthSANDNS)
	assert.Equal(t, "https://client.example.com", metadata.TLSClientAuthSANURI)
	assert.Equal(t, "203.0.113.10", metadata.TLSClientAuthSANIP)
	assert.Equal(t, "client@example.com", metadata.TLSClientAuthSANEmail)
	assert.True(t, metadata.TLSClientCertificateBoundAccessTokens)

	assert.Equal(t, "tls_client_auth", metadata.TokenEndpointAuthMethod)
	assert.Equal(t, "self_signed_tls_client_auth", metadata.IntrospectionEndpointAuthMethod)
	assert.Equal(t, "tls_client_auth", metadata.RevocationEndpointAuthMethod)
}

func TestDefaultClientRegistrationMetadataStrategyStripsDPoPWhenDisabled(t *testing.T) {
	strategy := NewDefaultClientRegistrationMetadataStrategy(&oauth2.Config{MTLSEnabled: true})

	metadata := newFilterMetadata()

	require.NoError(t, strategy.FilterClientRegistrationMetadata(context.Background(), nil, metadata))

	assert.False(t, metadata.DPoPBoundAccessTokens)
	assert.Equal(t, "CN=client,O=Example", metadata.TLSClientAuthSubjectDN)
}

func TestDefaultClientRegistrationMetadataStrategyLeavesNonMutualTLSAuthMethods(t *testing.T) {
	strategy := NewDefaultClientRegistrationMetadataStrategy(&oauth2.Config{})

	metadata := &oauth2.ClientRegistrationMetadata{
		TokenEndpointAuthMethod:         "client_secret_basic",
		IntrospectionEndpointAuthMethod: "private_key_jwt",
		RevocationEndpointAuthMethod:    "none",
	}

	require.NoError(t, strategy.FilterClientRegistrationMetadata(context.Background(), nil, metadata))

	assert.Equal(t, "client_secret_basic", metadata.TokenEndpointAuthMethod)
	assert.Equal(t, "private_key_jwt", metadata.IntrospectionEndpointAuthMethod)
	assert.Equal(t, "none", metadata.RevocationEndpointAuthMethod)
}

func TestDefaultClientRegistrationMetadataStrategyAcceptsNilMetadata(t *testing.T) {
	strategy := NewDefaultClientRegistrationMetadataStrategy(&oauth2.Config{})

	assert.NoError(t, strategy.FilterClientRegistrationMetadata(context.Background(), nil, nil))
}

func TestMetadataStrategyFallsBackToDefault(t *testing.T) {
	config := &oauth2.Config{}

	strategy := metadataStrategy(context.Background(), config)
	require.NotNil(t, strategy)
	assert.IsType(t, &DefaultClientRegistrationMetadataStrategy{}, strategy)

	configured := &testMetadataStrategy{}
	config.RFC7591ClientRegistrationMetadataStrategy = configured

	assert.Same(t, configured, metadataStrategy(context.Background(), config))
}

func newFilterMetadata() *oauth2.ClientRegistrationMetadata {
	return &oauth2.ClientRegistrationMetadata{
		RedirectURIs:                          []string{"https://example.com/cb"},
		ClientName:                            "Example",
		TokenEndpointAuthMethod:               "tls_client_auth",
		IntrospectionEndpointAuthMethod:       "self_signed_tls_client_auth",
		RevocationEndpointAuthMethod:          "tls_client_auth",
		TLSClientAuthSubjectDN:                "CN=client,O=Example",
		TLSClientAuthSANDNS:                   "client.example.com",
		TLSClientAuthSANURI:                   "https://client.example.com",
		TLSClientAuthSANIP:                    "203.0.113.10",
		TLSClientAuthSANEmail:                 "client@example.com",
		TLSClientCertificateBoundAccessTokens: true,
		DPoPBoundAccessTokens:                 true,
	}
}

type testMetadataStrategy struct {
	err error
}

func (s *testMetadataStrategy) FilterClientRegistrationMetadata(ctx context.Context, client oauth2.Client, metadata *oauth2.ClientRegistrationMetadata) (err error) {
	return s.err
}
