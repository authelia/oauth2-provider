// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type cibaSectorTestClient struct {
	*DefaultClient
	*DefaultCIBAClient
	*DefaultJARClient

	sector string
}

func (c *cibaSectorTestClient) GetSectorIdentifierURI() string { return c.sector }

func TestCIBASectorIdentifierHost(t *testing.T) {
	testCases := []struct {
		name     string
		sector   string
		mode     string
		jwksURI  string
		endpoint string
		expected string
		err      bool
	}{
		{name: "ShouldPreferSectorIdentifierURI", sector: "https://sector.example.com/doc.json", mode: "poll", jwksURI: "https://jwks.example.com/jwks", expected: "sector.example.com"},
		{name: "ShouldUseJWKSURIForPoll", mode: "poll", jwksURI: "https://JWKS.example.com:8443/jwks", endpoint: "https://notify.example.com/cb", expected: "jwks.example.com"},
		{name: "ShouldUseJWKSURIForPing", mode: "ping", jwksURI: "https://jwks.example.com/jwks", endpoint: "https://notify.example.com/cb", expected: "jwks.example.com"},
		{name: "ShouldUseNotificationEndpointForPush", mode: "push", jwksURI: "https://jwks.example.com/jwks", endpoint: "https://notify.example.com/cb", expected: "notify.example.com"},
		{name: "ShouldErrorWhenNothingRegistered", mode: "poll", err: true},
		{name: "ShouldErrorWhenNoHost", mode: "push", endpoint: "https:///cb", err: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := &cibaSectorTestClient{
				DefaultClient:     &DefaultClient{},
				DefaultCIBAClient: &DefaultCIBAClient{BackChannelTokenDeliveryMode: tc.mode, BackChannelClientNotificationEndpoint: tc.endpoint},
				DefaultJARClient:  &DefaultJARClient{JSONWebKeysURI: tc.jwksURI},
				sector:            tc.sector,
			}

			host, err := CIBASectorIdentifierHost(client)

			if tc.err {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, host)
		})
	}

	t.Run("ShouldErrorForNonCIBAClient", func(t *testing.T) {
		_, err := CIBASectorIdentifierHost(&DefaultClient{})
		require.Error(t, err)
	})

	t.Run("ShouldPreferSectorIdentifierURIOfRegisteredClient", func(t *testing.T) {
		client := &DefaultRegisteredClient{}
		client.SectorIdentifierURI = "https://sector.example.com/doc.json"
		client.JSONWebKeysURI = "https://jwks.example.com/jwks"
		client.BackChannelTokenDeliveryMode = "poll"

		host, err := CIBASectorIdentifierHost(client)
		require.NoError(t, err)
		assert.Equal(t, "sector.example.com", host)
	})
}
