// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package cimd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
)

func TestRedirectURISameOriginValidator(t *testing.T) {
	testCases := []struct {
		name      string
		clientID  any
		redirects []string
		valid     bool
	}{
		{"ShouldAcceptSameOrigin", "https://client.example.com/metadata.json", []string{"https://client.example.com/cb", "https://client.example.com/other/cb?x=1"}, true},
		{"ShouldAcceptSameOriginWithPort", "https://client.example.com:8443/metadata.json", []string{"https://client.example.com:8443/cb"}, true},
		{"ShouldAcceptHostCaseDifference", "https://client.example.com/metadata.json", []string{"https://CLIENT.example.com/cb"}, true},
		{"ShouldAcceptNoRedirectURIs", "https://client.example.com/metadata.json", nil, true},
		{"ShouldRejectOtherHost", "https://client.example.com/metadata.json", []string{"https://client.example.com/cb", "https://attacker.example.com/cb"}, false},
		{"ShouldRejectSubdomain", "https://client.example.com/metadata.json", []string{"https://app.client.example.com/cb"}, false},
		{"ShouldRejectOtherPort", "https://client.example.com/metadata.json", []string{"https://client.example.com:8443/cb"}, false},
		{"ShouldRejectExplicitDefaultPort", "https://client.example.com/metadata.json", []string{"https://client.example.com:443/cb"}, false},
		{"ShouldRejectOtherScheme", "https://client.example.com/metadata.json", []string{"com.example.client:/cb"}, false},
		{"ShouldRejectLoopback", "https://client.example.com/metadata.json", []string{"http://127.0.0.1/cb"}, false},
		{"ShouldRejectUnparsableRedirectURI", "https://client.example.com/metadata.json", []string{"https://client.example.com/%zz"}, false},
		{"ShouldRejectUserinfoNamingTheClientHost", "https://client.example.com/metadata.json", []string{"https://client.example.com@attacker.example.com/cb"}, false},
		{"ShouldRejectTrailingDotHost", "https://client.example.com/metadata.json", []string{"https://client.example.com./cb"}, false},
		{"ShouldRejectOpaqueRedirectURI", "https://client.example.com/metadata.json", []string{"https:client.example.com/cb"}, false},
		{"ShouldRejectEmptyPort", "https://client.example.com/metadata.json", []string{"https://client.example.com:/cb"}, false},
		{"ShouldRejectClientIDWithoutSchemeOrHost", "/metadata.json", []string{"/cb"}, false},
		{"ShouldRejectClientIDWithoutScheme", "//client.example.com/metadata.json", []string{"//client.example.com/cb"}, false},
		{"ShouldRejectClientIDWithoutHost", "https:/metadata.json", []string{"https:/cb"}, false},
		{"ShouldRejectOpaqueClientID", "https:client.example.com/metadata.json", []string{"https:client.example.com/cb"}, false},
		{"ShouldRejectMissingClientID", nil, []string{"https://client.example.com/cb"}, false},
		{"ShouldRejectNonStringClientID", 1, []string{"https://client.example.com/cb"}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metadata := &oauth2.ClientRegistrationMetadata{RedirectURIs: tc.redirects}

			if tc.clientID != nil {
				metadata.Extra = map[string]any{"client_id": tc.clientID}
			}

			err := RedirectURISameOriginValidator{}.ValidateClientRegistrationMetadata(t.Context(), nil, metadata)

			if tc.valid {
				require.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, oauth2.ErrInvalidRedirectURI)
			}
		})
	}
}

func TestRedirectURISameOriginValidatorWithParsedDocument(t *testing.T) {
	metadata, err := parseDocument(testClientID, document(`"redirect_uris":["https://attacker.example.com/cb"]`))

	require.NoError(t, err)

	assert.ErrorIs(t, RedirectURISameOriginValidator{}.ValidateClientRegistrationMetadata(t.Context(), nil, metadata), oauth2.ErrInvalidRedirectURI)
}
