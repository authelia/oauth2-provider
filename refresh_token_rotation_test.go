// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsRefreshTokenRotationDisabled(t *testing.T) {
	testCases := []struct {
		name     string
		config   DisableRefreshTokenRotationProvider
		client   Client
		expected bool
	}{
		{"ShouldRotateByDefault", &Config{}, &DefaultRegisteredClient{DefaultClient: &DefaultClient{}}, false},
		{"ShouldRotateWithoutConfig", nil, &DefaultClient{}, false},
		{"ShouldNotRotateWhenProviderDisables", &Config{DisableRefreshTokenRotation: true}, &DefaultClient{}, true},
		{"ShouldNotRotateWhenClientDisables", &Config{}, &DefaultRegisteredClient{DefaultClient: &DefaultClient{}, DisableRefreshTokenRotation: true}, true},
		{"ShouldNotRotateWhenClientDisablesWithoutConfig", nil, &DefaultRegisteredClient{DefaultClient: &DefaultClient{}, DisableRefreshTokenRotation: true}, true},
		{"ShouldNotRotateWhenProviderDisablesForClientPolicy", &Config{DisableRefreshTokenRotation: true}, &DefaultRegisteredClient{DefaultClient: &DefaultClient{}}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, IsRefreshTokenRotationDisabled(t.Context(), tc.config, tc.client))

			if config, ok := tc.config.(*Config); ok {
				f := &Fosite{Config: config}

				assert.Equal(t, tc.expected, f.DisableRefreshTokenRotation(t.Context(), tc.client))
			}
		})
	}
}
