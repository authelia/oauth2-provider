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

func TestIsRefreshTokenRotationDisabledForRequest(t *testing.T) {
	confidential := &DefaultRegisteredClient{DefaultClient: &DefaultClient{ID: "confidential"}, DisableRefreshTokenRotation: true}
	public := &DefaultRegisteredClient{DefaultClient: &DefaultClient{ID: "public", Public: true}, DisableRefreshTokenRotation: true}

	testCases := []struct {
		name     string
		config   *Config
		client   Client
		session  *DefaultSession
		expected bool
	}{
		{"ShouldNotRotateForAConfidentialClient", &Config{}, confidential, &DefaultSession{}, true},
		{"ShouldRotateForAPublicClientWithAnUnboundToken", &Config{}, public, &DefaultSession{}, false},
		{"ShouldRotateForAPublicClientWhenTheProviderDisables", &Config{DisableRefreshTokenRotation: true}, &DefaultClient{ID: "public", Public: true}, &DefaultSession{}, false},
		{"ShouldNotRotateForAPublicClientWithADPoPBoundToken", &Config{DPoPEnabled: true}, public, &DefaultSession{JWKThumbprint: "jkt"}, true},
		{"ShouldRotateForAPublicClientWhenDPoPIsDisabled", &Config{}, public, &DefaultSession{JWKThumbprint: "jkt"}, false},
		{"ShouldNotRotateForAPublicClientWithACertificateBoundToken", &Config{MTLSEnabled: true}, public, &DefaultSession{ClientCertificateThumbprint: "x5t"}, true},
		{"ShouldRotateForAPublicClientWhenMTLSIsDisabled", &Config{}, public, &DefaultSession{ClientCertificateThumbprint: "x5t"}, false},
		{"ShouldRotateWhenNotDisabled", &Config{DPoPEnabled: true}, &DefaultClient{ID: "public", Public: true}, &DefaultSession{JWKThumbprint: "jkt"}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			request := &Request{Client: tc.client, Session: tc.session}

			assert.Equal(t, tc.expected, IsRefreshTokenRotationDisabledForRequest(t.Context(), tc.config, request))
		})
	}
}
