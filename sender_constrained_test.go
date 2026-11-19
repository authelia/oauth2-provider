// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsSenderConstrainedAccessTokenEnforced(t *testing.T) {
	testCases := []struct {
		name     string
		config   EnforceSenderConstrainedAccessTokensProvider
		client   Client
		expected bool
	}{
		{"ShouldNotEnforceByDefault", &Config{}, &DefaultRegisteredClient{DefaultClient: &DefaultClient{}}, false},
		{"ShouldNotEnforceWithoutConfig", nil, &DefaultClient{}, false},
		{"ShouldEnforceWhenProviderEnforces", &Config{EnforceSenderConstrainedAccessTokens: true}, &DefaultClient{}, true},
		{"ShouldEnforceWhenClientEnforces", &Config{}, &DefaultRegisteredClient{DefaultClient: &DefaultClient{}, EnforceSenderConstrainedAccessTokens: true}, true},
		{"ShouldEnforceWhenClientEnforcesWithoutConfig", nil, &DefaultRegisteredClient{DefaultClient: &DefaultClient{}, EnforceSenderConstrainedAccessTokens: true}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, IsSenderConstrainedAccessTokenEnforced(t.Context(), tc.config, tc.client))
		})
	}
}

// RFC 10027 Section 6.1.12.
func TestIsCrossDeviceSenderConstrainedAccessTokenEnforced(t *testing.T) {
	plain := &DefaultRegisteredClient{DefaultClient: &DefaultClient{}}
	device := &DefaultRegisteredClient{DefaultClient: &DefaultClient{}, RFC8628EnforceSenderConstrainedAccessTokens: true}
	ciba := &DefaultRegisteredClient{DefaultClient: &DefaultClient{}, CIBAEnforceSenderConstrainedAccessTokens: true}

	testCases := []struct {
		name     string
		config   CrossDeviceSenderConstrainedAccessTokensProvider
		client   Client
		gt       GrantType
		expected bool
	}{
		{"ShouldNotEnforceTheDeviceGrantByDefault", &Config{}, plain, GrantTypeDeviceCode, false},
		{"ShouldNotEnforceCIBAByDefault", &Config{}, plain, GrantTypeCIBA, false},
		{"ShouldNotEnforceWithoutConfig", nil, &DefaultClient{}, GrantTypeDeviceCode, false},
		{"ShouldEnforceTheDeviceGrantWhenProviderEnforces", &Config{RFC8628EnforceSenderConstrainedAccessTokens: true}, plain, GrantTypeDeviceCode, true},
		{"ShouldNotEnforceCIBAWhenProviderEnforcesTheDeviceGrant", &Config{RFC8628EnforceSenderConstrainedAccessTokens: true}, plain, GrantTypeCIBA, false},
		{"ShouldEnforceCIBAWhenProviderEnforces", &Config{CIBAEnforceSenderConstrainedAccessTokens: true}, plain, GrantTypeCIBA, true},
		{"ShouldNotEnforceTheDeviceGrantWhenProviderEnforcesCIBA", &Config{CIBAEnforceSenderConstrainedAccessTokens: true}, plain, GrantTypeDeviceCode, false},
		{"ShouldEnforceTheDeviceGrantWhenClientEnforces", &Config{}, device, GrantTypeDeviceCode, true},
		{"ShouldNotEnforceCIBAWhenClientEnforcesTheDeviceGrant", &Config{}, device, GrantTypeCIBA, false},
		{"ShouldEnforceCIBAWhenClientEnforces", &Config{}, ciba, GrantTypeCIBA, true},
		{"ShouldEnforceCIBAWhenClientEnforcesWithoutConfig", nil, ciba, GrantTypeCIBA, true},
		{"ShouldNotEnforceAnotherGrant", &Config{RFC8628EnforceSenderConstrainedAccessTokens: true, CIBAEnforceSenderConstrainedAccessTokens: true}, ciba, GrantTypeAuthorizationCode, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, IsCrossDeviceSenderConstrainedAccessTokenEnforced(t.Context(), tc.config, tc.client, tc.gt))
		})
	}
}
