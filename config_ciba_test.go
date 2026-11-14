// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCIBAConfigDefaults(t *testing.T) {
	ctx := t.Context()
	config := &Config{}

	assert.Equal(t, []string{"poll", "ping", "push"}, config.GetCIBATokenDeliveryModes(ctx))
	assert.Equal(t, 5*time.Minute, config.GetCIBAAuthRequestLifespan(ctx))
	assert.Equal(t, 30*time.Second, config.GetCIBARequestedExpiryMinimum(ctx))
	assert.Equal(t, 30*time.Minute, config.GetCIBARequestedExpiryMaximum(ctx))
	assert.Equal(t, 5*time.Second, config.GetCIBAPollingInterval(ctx))
	assert.Equal(t, time.Duration(0), config.GetCIBALongPollingTimeout(ctx))
	assert.Equal(t, 0, config.GetCIBASlowDownLimit(ctx))
	assert.False(t, config.GetCIBAUserCodeSupported(ctx))
	assert.True(t, config.GetCIBARequireOpenIDScope(ctx))
	assert.Equal(t, 24*time.Hour, config.GetCIBAIDTokenHintMaximumAge(ctx))
	assert.False(t, config.GetCIBARequireBindingMessage(ctx))
	assert.Equal(t, 64, config.GetCIBAMaximumBindingMessageLength(ctx))

	algs := config.GetCIBARequestSigningAlgValues(ctx)

	assert.NotEmpty(t, algs)
	assert.Contains(t, algs, "RS256")
	assert.Contains(t, algs, "ES256")
	assert.NotContains(t, algs, "none")
	assert.NotContains(t, algs, "HS256")
	assert.NotContains(t, algs, "HS384")
	assert.NotContains(t, algs, "HS512")
}

func TestCIBAConfigTokenDeliveryModesOmitUndefinedModes(t *testing.T) {
	testCases := []struct {
		name     string
		modes    []string
		expected []string
	}{
		{"ShouldKeepDefinedModes", []string{"push", "poll"}, []string{"push", "poll"}},
		{"ShouldOmitUndefinedModes", []string{"poll", "sms", "PING", ""}, []string{"poll"}},
		{"ShouldOmitDuplicates", []string{"ping", "ping", "poll"}, []string{"ping", "poll"}},
		{"ShouldSupportNoModeWhenNoneIsDefined", []string{"fax"}, nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, (&Config{CIBATokenDeliveryModes: tc.modes}).GetCIBATokenDeliveryModes(t.Context()))
		})
	}
}

func TestCIBAConfigConfigured(t *testing.T) {
	ctx := t.Context()

	config := &Config{
		CIBATokenDeliveryModes:            []string{"poll"},
		CIBAAuthRequestLifespan:           time.Minute,
		CIBARequestedExpiryMinimum:        time.Minute,
		CIBARequestedExpiryMaximum:        time.Hour,
		CIBAPollingInterval:               7 * time.Second,
		CIBALongPollingTimeout:            20 * time.Second,
		CIBASlowDownLimit:                 3,
		CIBAUserCodeSupported:             true,
		CIBARequestSigningAlgValues:       []string{"PS256"},
		CIBADisableOpenIDScopeRequirement: true,
		CIBAIDTokenHintMaximumAge:         time.Hour,
		CIBARequireBindingMessage:         true,
		CIBAMaximumBindingMessageLength:   16,
	}

	assert.Equal(t, []string{"poll"}, config.GetCIBATokenDeliveryModes(ctx))
	assert.Equal(t, time.Minute, config.GetCIBAAuthRequestLifespan(ctx))
	assert.Equal(t, time.Minute, config.GetCIBARequestedExpiryMinimum(ctx))
	assert.Equal(t, time.Hour, config.GetCIBARequestedExpiryMaximum(ctx))
	assert.Equal(t, 7*time.Second, config.GetCIBAPollingInterval(ctx))
	assert.Equal(t, 20*time.Second, config.GetCIBALongPollingTimeout(ctx))
	assert.Equal(t, 3, config.GetCIBASlowDownLimit(ctx))
	assert.True(t, config.GetCIBAUserCodeSupported(ctx))
	assert.Equal(t, []string{"PS256"}, config.GetCIBARequestSigningAlgValues(ctx))
	assert.False(t, config.GetCIBARequireOpenIDScope(ctx))
	assert.Equal(t, time.Hour, config.GetCIBAIDTokenHintMaximumAge(ctx))
	assert.True(t, config.GetCIBARequireBindingMessage(ctx))
	assert.Equal(t, 16, config.GetCIBAMaximumBindingMessageLength(ctx))
}

func TestCIBAConfigLongPollingTimeoutIsClamped(t *testing.T) {
	config := &Config{CIBALongPollingTimeout: 45 * time.Second}

	assert.Equal(t, 30*time.Second, config.GetCIBALongPollingTimeout(t.Context()))
}

func TestBackChannelAuthenticationEndpointURLs(t *testing.T) {
	urls := EndpointURLs{
		BackChannelAuthentication: "https://as/ciba",
		MutualTLSAliases:          RFC8705MutualTLSEndpointAliases{BackChannelAuthentication: "https://mtls/ciba"},
	}

	assert.Equal(t, []string{"https://as/ciba", "https://mtls/ciba"}, urls.URLs(EndpointBackChannelAuthentication))
}
