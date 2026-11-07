// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfig_GetIssuer(t *testing.T) {
	assert.Equal(t, "https://op", (&Config{Issuer: "https://op"}).GetIssuer(t.Context()))
	assert.Empty(t, (&Config{}).GetIssuer(t.Context()))
}

func TestConfig_GetAuthorizationServerIdentificationEnabled(t *testing.T) {
	testCases := []struct {
		name     string
		config   *Config
		expected bool
	}{
		{
			name:     "ShouldBeEnabledByDefault",
			config:   &Config{},
			expected: true,
		},
		{
			name:     "ShouldBeDisabledWhenDisableAuthorizationServerIdentificationIsSet",
			config:   &Config{Issuer: "https://op", DisableAuthorizationServerIdentification: true},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.config.GetAuthorizationServerIdentificationEnabled(t.Context()))
		})
	}
}
