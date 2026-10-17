// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfigClientIDMetadataDocumentDisabledByDefault(t *testing.T) {
	config := &Config{}

	var provider ClientIDMetadataDocumentConfigProvider = config

	assert.Nil(t, provider.GetClientIDMetadataDocumentResolver(t.Context()))
	assert.Nil(t, provider.GetClientIDMetadataDocumentHTTPClient(t.Context()))
	assert.Nil(t, provider.GetClientIDMetadataDocumentJWKSFetcherStrategy(t.Context()))
	assert.Empty(t, provider.GetClientIDMetadataDocumentAllowedDomainSuffixes(t.Context()))
}

func TestConfigClientIDMetadataDocumentReturnsConfiguredValues(t *testing.T) {
	client := NewSpecialUseAddressGuardedHTTPClient()
	fetcher := NewDefaultJWKSFetcherStrategy(JWKSFetcherWithHTTPClient(client))

	config := &Config{
		ClientIDMetadataDocumentHTTPClient:            client,
		ClientIDMetadataDocumentJWKSFetcherStrategy:   fetcher,
		ClientIDMetadataDocumentAllowedDomainSuffixes: []string{"example.com"},
	}

	assert.Equal(t, []string{"example.com"}, config.GetClientIDMetadataDocumentAllowedDomainSuffixes(t.Context()))

	assert.Same(t, client, config.GetClientIDMetadataDocumentHTTPClient(t.Context()))
	assert.Equal(t, fetcher, config.GetClientIDMetadataDocumentJWKSFetcherStrategy(t.Context()))
}
