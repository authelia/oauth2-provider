// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"authelia.com/provider/oauth2/internal/consts"
)

func TestConfigRFC7591ClientRegistrationPolicyClaim(t *testing.T) {
	const (
		issuer   = "https://auth.example.com/"
		explicit = "https://example.com/claim"
	)

	testCases := []struct {
		name     string
		issuer   string
		explicit string
		expected string
	}{
		{"ShouldDeriveFromIssuer", issuer, "", "https://auth.example.com:authelia:authelia:oauth2:dynamic-client-registration:policy"},
		{"ShouldDefaultWhenIssuerEmpty", "", "", "policy/oauth2/dynamic-client-registration"},
		{"ShouldPreferExplicitValue", issuer, explicit, explicit},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{AccessTokenIssuer: tc.issuer, RFC7591ClientRegistrationPolicyClaim: tc.explicit}

			assert.Equal(t, tc.expected, config.GetRFC7591ClientRegistrationPolicyClaim(context.Background()))
		})
	}

	issuers := []RFC7591TrustedIssuer{{Issuer: "https://issuer.example.com", JSONWebKeysURI: "https://issuer.example.com/jwks"}}

	assert.Nil(t, (&Config{}).GetRFC7591ClientRegistrationTrustedIssuers(context.Background()))
	assert.Equal(t, issuers, (&Config{RFC7591ClientRegistrationTrustedIssuers: issuers}).GetRFC7591ClientRegistrationTrustedIssuers(context.Background()))

	assert.Nil(t, (&Config{}).GetRFC7591ClientRegistrationPatternIssuers(context.Background()))
	assert.Equal(t, []string{"https://issuer.example.com"}, (&Config{RFC7591ClientRegistrationPatternIssuers: []string{"https://issuer.example.com"}}).GetRFC7591ClientRegistrationPatternIssuers(context.Background()))
}

func TestConfigRFC7591SoftwareStatementJWTValidation(t *testing.T) {
	ctx := context.Background()

	defaults := &Config{}

	assert.False(t, defaults.GetRFC7591SoftwareStatementJWTValidationHeaderAllowEmptyType(ctx))
	assert.Equal(t, []string{consts.JSONWebTokenTypeSoftwareStatement}, defaults.GetRFC7591SoftwareStatementJWTValidationHeaderAllowTypes(ctx))
	assert.False(t, defaults.GetRFC7591SoftwareStatementRequireSoftwareID(ctx))

	types := []string{consts.JSONWebTokenTypeSoftwareStatement}

	configured := &Config{
		RFC7591SoftwareStatementJWTValidationHeaderAllowEmptyType: true,
		RFC7591SoftwareStatementJWTValidationHeaderAllowTypes:     types,
		RFC7591SoftwareStatementRequireSoftwareID:                 true,
	}

	assert.True(t, configured.GetRFC7591SoftwareStatementJWTValidationHeaderAllowEmptyType(ctx))
	assert.Equal(t, types, configured.GetRFC7591SoftwareStatementJWTValidationHeaderAllowTypes(ctx))
	assert.True(t, configured.GetRFC7591SoftwareStatementRequireSoftwareID(ctx))
}

func TestConfigRFC7591ClientRegistrationProvider(t *testing.T) {
	ctx := context.Background()

	config := &Config{
		RFC7591ClientRegistrationEndpointURL: "https://auth.example.com/register",
		RFC7591ClientSecretLifespan:          time.Hour,
	}

	assert.Equal(t, "https://auth.example.com/register", config.GetRFC7591ClientRegistrationEndpointURL(ctx))
	assert.Equal(t, time.Hour, config.GetRFC7591ClientSecretLifespan(ctx))
	assert.Nil(t, config.GetRFC7591ClientRegistrationStrategy(ctx))
	assert.Nil(t, config.GetRFC7591ClientRegistrationEndpointAuthStrategy(ctx))
	assert.Empty(t, config.GetRFC7591ClientRegistrationValidators(ctx))

	var _ RFC7591ClientRegistrationConfigProvider = config
}
