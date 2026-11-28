// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

// FAPI 2.0 Security Profile Sections 5.3.2.1 and 5.3.2.2.
func TestValidateFAPI2SecurityProfileClient(t *testing.T) {
	testCases := []struct {
		name     string
		client   oauth2.Client
		expected []string
	}{
		{
			name:   "ShouldPassAConfidentialCodeClient",
			client: &oauth2.DefaultClient{ID: "c", ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow}},
		},
		{
			name:     "ShouldRejectAPublicClient",
			client:   &oauth2.DefaultClient{ID: "c", Public: true, ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow}},
			expected: []string{"Section 5.3.2.1: the client 'c' must be confidential, but it is public"},
		},
		{
			name:     "ShouldRejectAnotherResponseType",
			client:   &oauth2.DefaultClient{ID: "c", ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow, "code id_token"}},
			expected: []string{"Section 5.3.2.2: the client 'c' must register only the 'code' response type, but it registers 'code id_token'"},
		},
		{
			name:     "ShouldRejectARequiredPlainChallengeMethod",
			client:   &pkceRequiringClient{DefaultClient: &oauth2.DefaultClient{ID: "c", ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow}}, method: consts.PKCEChallengeMethodPlain},
			expected: []string{"Section 5.3.2.2: the client 'c' requires the PKCE code challenge method 'plain', but only 'S256' is permitted"},
		},
		{
			name:     "ShouldRejectARequiredEmptyChallengeMethod",
			client:   &pkceRequiringClient{DefaultClient: &oauth2.DefaultClient{ID: "c", ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow}}},
			expected: []string{"Section 5.3.2.2: the client 'c' requires the PKCE code challenge method '', but only 'S256' is permitted"},
		},
		{
			name:   "ShouldPassARequiredS256ChallengeMethod",
			client: &pkceRequiringClient{DefaultClient: &oauth2.DefaultClient{ID: "c", ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow}}, method: consts.PKCEChallengeMethodSHA256},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateFAPI2SecurityProfileClient(tc.client)

			if len(tc.expected) == 0 {
				assert.NoError(t, err)

				return
			}

			require.Error(t, err)

			for _, expected := range tc.expected {
				assert.Contains(t, err.Error(), expected)
			}
		})
	}
}

type pkceRequiringClient struct {
	*oauth2.DefaultClient

	method string
}

func (c *pkceRequiringClient) GetEnforcePKCE() bool { return true }

func (c *pkceRequiringClient) GetEnforcePKCEChallengeMethod() bool { return true }

func (c *pkceRequiringClient) GetPKCEChallengeMethod() string { return c.method }
