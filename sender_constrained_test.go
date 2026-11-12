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
