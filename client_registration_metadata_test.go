// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientRegistrationMetadataRoundTrip(t *testing.T) {
	raw := []byte(`{
		"redirect_uris": ["https://example.com/cb"],
		"grant_types": ["authorization_code", "refresh_token"],
		"response_types": ["code"],
		"client_name": "Example",
		"scope": "openid profile",
		"token_endpoint_auth_method": "client_secret_basic",
		"application_type": "web",
		"subject_type": "public",
		"id_token_signed_response_alg": "RS256",
		"vendor_specific": {"a": 1}
	}`)

	metadata := &ClientRegistrationMetadata{}

	require.NoError(t, json.Unmarshal(raw, metadata))

	assert.Equal(t, []string{"https://example.com/cb"}, metadata.RedirectURIs)
	assert.Equal(t, []string{"authorization_code", "refresh_token"}, metadata.GrantTypes)
	assert.Equal(t, "Example", metadata.ClientName)
	assert.Equal(t, "openid profile", metadata.Scope)
	assert.Equal(t, "web", metadata.ApplicationType)
	assert.Equal(t, "RS256", metadata.IDTokenSignedResponseAlg)

	// Unregistered parameters survive.
	require.Contains(t, metadata.Extra, "vendor_specific")

	// Registered parameters must not be duplicated into Extra.
	assert.NotContains(t, metadata.Extra, "redirect_uris")
	assert.NotContains(t, metadata.Extra, "client_name")

	out, err := json.Marshal(metadata)
	require.NoError(t, err)

	round := map[string]any{}
	require.NoError(t, json.Unmarshal(out, &round))

	assert.Equal(t, "Example", round["client_name"])
	assert.Contains(t, round, "vendor_specific")

	// Empty values are omitted.
	assert.NotContains(t, round, "logo_uri")
}

func TestClientRegistrationMetadataGetScopes(t *testing.T) {
	metadata := &ClientRegistrationMetadata{Scope: "openid  profile "}

	assert.Equal(t, Arguments{"openid", "profile"}, metadata.GetScopes())

	assert.Empty(t, (&ClientRegistrationMetadata{}).GetScopes())
}
