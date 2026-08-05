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

func TestClientRegistrationMetadataDefaultMaxAgePresence(t *testing.T) {
	testCases := []struct {
		name     string
		raw      string
		expected *int64
	}{
		{
			name:     "ShouldDecodeAnOmittedValueAsAbsent",
			raw:      `{"client_name":"Example"}`,
			expected: nil,
		},
		{
			name:     "ShouldDecodeAnExplicitZeroAsPresent",
			raw:      `{"default_max_age":0}`,
			expected: pointerTo(int64(0)),
		},
		{
			name:     "ShouldDecodeAnOrdinaryValue",
			raw:      `{"default_max_age":3600}`,
			expected: pointerTo(int64(3600)),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metadata := &ClientRegistrationMetadata{}

			require.NoError(t, json.Unmarshal([]byte(tc.raw), metadata))
			assert.Equal(t, tc.expected, metadata.DefaultMaxAge)
			assert.NotContains(t, metadata.Extra, "default_max_age")

			out, err := json.Marshal(metadata)
			require.NoError(t, err)

			round := map[string]any{}
			require.NoError(t, json.Unmarshal(out, &round))

			if tc.expected == nil {
				assert.NotContains(t, round, "default_max_age")
			} else {
				require.Contains(t, round, "default_max_age")
				assert.Equal(t, float64(*tc.expected), round["default_max_age"])
			}
		})
	}
}

func TestClientRegistrationMetadataPreservesLargeNumbers(t *testing.T) {
	const raw = `{"client_name":"Example","vendor_serial":9007199254740993}`

	metadata := &ClientRegistrationMetadata{}

	require.NoError(t, json.Unmarshal([]byte(raw), metadata))

	require.Contains(t, metadata.Extra, "vendor_serial")
	assert.Equal(t, json.Number("9007199254740993"), metadata.Extra["vendor_serial"])

	out, err := json.Marshal(metadata)
	require.NoError(t, err)

	assert.Contains(t, string(out), `"vendor_serial":9007199254740993`)
}

func pointerTo[T any](value T) *T {
	return &value
}
