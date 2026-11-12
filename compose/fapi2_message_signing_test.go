// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestValidateFAPI2MessageSigning(t *testing.T) {
	testCases := []struct {
		name     string
		parts    FAPI2MessageSigningParts
		modify   func(config *oauth2.Config)
		expected []string
	}{
		{name: "ShouldPassEveryPart", parts: FAPI2MessageSigningAll},
		{name: "ShouldPassSignedRequestsWithoutResponseStrategies", parts: FAPI2MessageSigningRequests, modify: func(config *oauth2.Config) {
			config.JWTSecuredAuthorizeResponseModeStrategy = nil
			config.IntrospectionJWTResponseStrategy = nil
		}},
		{name: "ShouldRejectOptionallySignedRequestObjects", parts: FAPI2MessageSigningRequests, modify: func(config *oauth2.Config) { config.RequireSignedRequestObject = false }, expected: []string{"FAPI 2.0 Message Signing Section 5.3.1: signed request objects must be required"}},
		{name: "ShouldRejectSkippingPushedAuthorizationRequests", parts: FAPI2MessageSigningRequests, modify: func(config *oauth2.Config) {
			config.RequireSignedRequestObjectSkipPushedAuthorizationRequests = true
		}, expected: []string{"Section 5.3.1: signed request objects must be required at the pushed authorization request endpoint"}},
		{name: "ShouldRejectUnboundedRequestObjects", parts: FAPI2MessageSigningRequests, modify: func(config *oauth2.Config) {
			config.RequireRequestObjectAudienceAndLifetime = false
		}, expected: []string{"Section 5.3.1: request objects must carry 'aud', 'nbf' and 'exp'"}},
		{name: "ShouldRejectADisabledLifetimeBound", parts: FAPI2MessageSigningRequests, modify: func(config *oauth2.Config) { config.RequestObjectMaximumLifetime = -1 }, expected: []string{"Section 5.3.1: the request object lifetime must be bounded to at most 1h0m0s, but is bounded to 0s"}},
		{name: "ShouldRejectALongLifetimeBound", parts: FAPI2MessageSigningRequests, modify: func(config *oauth2.Config) { config.RequestObjectMaximumLifetime = 2 * time.Hour }, expected: []string{"Section 5.3.1: the request object lifetime must be bounded to at most 1h0m0s, but is bounded to 2h0m0s"}},
		{name: "ShouldRejectUnsignedRequestObjectAlgorithms", parts: FAPI2MessageSigningRequests, modify: func(config *oauth2.Config) {
			config.RequestObjectSigningAlgValues = []string{consts.JSONWebTokenAlgNone}
		}, expected: []string{"Section 5.3.1: the request object algorithms 'none' include one not permitted"}},
		{name: "ShouldRejectAMissingJARMStrategy", parts: FAPI2MessageSigningResponses, modify: func(config *oauth2.Config) { config.JWTSecuredAuthorizeResponseModeStrategy = nil }, expected: []string{"Section 5.4.1: signed authorization responses must be supported"}},
		{name: "ShouldRejectHMACSignedAuthorizationResponses", parts: FAPI2MessageSigningResponses, modify: func(config *oauth2.Config) { config.AuthorizationSignedResponseAlgValues = nil }, expected: []string{"Section 5.4.1: the authorization response algorithms 'ES256', 'HS256', 'HS384', 'HS512' must be permitted ones"}},
		{name: "ShouldRejectAuthorizationAlgorithmsTheStrategyCannotSign", parts: FAPI2MessageSigningResponses, modify: func(config *oauth2.Config) {
			config.AuthorizationSignedResponseAlgValues = []string{string(jose.PS256)}
		}, expected: []string{"Section 5.4.1: signed authorization responses must be supported, but the JWT Secured Authorization Response Mode strategy supports none of the algorithms permitted"}},
		{name: "ShouldRejectAMissingIntrospectionStrategy", parts: FAPI2MessageSigningIntrospection, modify: func(config *oauth2.Config) { config.IntrospectionJWTResponseStrategy = nil }, expected: []string{"Section 5.5.1: introspection responses must be signed, but no introspection JWT response strategy is configured"}},
		{name: "ShouldRejectHMACSignedIntrospectionResponses", parts: FAPI2MessageSigningIntrospection, modify: func(config *oauth2.Config) { config.IntrospectionSignedResponseAlgValues = nil }, expected: []string{"Section 5.5.1: the introspection response algorithms 'ES256', 'HS256', 'HS384', 'HS512' must be permitted ones"}},
		{name: "ShouldRejectIntrospectionAlgorithmsTheStrategyCannotSign", parts: FAPI2MessageSigningIntrospection, modify: func(config *oauth2.Config) {
			config.IntrospectionSignedResponseAlgValues = []string{string(jose.PS256)}
		}, expected: []string{"Section 5.5.1: introspection responses must be signed, but the introspection JWT response strategy supports none of the algorithms permitted"}},
		{name: "ShouldRejectUnrestrictedIntrospectionCallers", parts: FAPI2MessageSigningIntrospection, modify: func(config *oauth2.Config) { config.EnforceIntrospectionPermission = false }, expected: []string{"Section 6.2: only resource servers may call the introspection endpoint"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := newFAPI2MessageSigningConfig()

			ApplyFAPI2MessageSigning(config, tc.parts)

			if tc.modify != nil {
				tc.modify(config)
			}

			composeFAPI2(t, config, OAuth2TokenIntrospectionFactory)

			err := ValidateFAPI2MessageSigning(context.Background(), config, tc.parts)

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

func TestValidateFAPI2MessageSigningWithoutTheProfile(t *testing.T) {
	config := newFAPI2MessageSigningConfig()

	composeFAPI2(t, config)

	err := ValidateFAPI2MessageSigning(context.Background(), config, FAPI2MessageSigningAll)
	require.Error(t, err)

	for _, expected := range []string{
		"Section 5.3.1: signed request objects must be required",
		"RequireRequestObjectAudienceAndLifetime is not set",
		"Section 5.4.1: the authorization response algorithms",
		"Section 5.5.1: introspection responses must be signed, but no introspection handler is registered",
		"EnforceIntrospectionPermission is not set",
	} {
		assert.Contains(t, err.Error(), expected)
	}
}

func TestValidateFAPI2MessageSigningRequiresAnIssuer(t *testing.T) {
	testCases := []struct {
		name     string
		parts    FAPI2MessageSigningParts
		expected string
	}{
		{name: "ShouldRequireAnIssuerForSignedRequests", parts: FAPI2MessageSigningRequests, expected: "FAPI 2.0 Message Signing Section 5.3.1: request objects must carry the issuer as 'aud', but Issuer is not set"},
		{name: "ShouldRequireAnIssuerForSignedResponses", parts: FAPI2MessageSigningResponses, expected: "FAPI 2.0 Message Signing Section 5.4.1: signed authorization responses must carry 'iss', but Issuer is not set"},
		{name: "ShouldRequireAnIssuerForSignedIntrospection", parts: FAPI2MessageSigningIntrospection, expected: "FAPI 2.0 Message Signing Section 5.5.1: signed introspection responses must carry 'iss', but Issuer is not set"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := newFAPI2MessageSigningConfig()

			ApplyFAPI2MessageSigning(config, tc.parts)

			config.Issuer = ""

			err := ValidateFAPI2MessageSigning(context.Background(), config, tc.parts)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.expected)
		})
	}
}

func TestApplyFAPI2MessageSigning(t *testing.T) {
	t.Run("ShouldApplyEveryPart", func(t *testing.T) {
		config := &oauth2.Config{
			RequestObjectMaximumLifetime:                              2 * time.Hour,
			RequestObjectSigningAlgValues:                             []string{string(jose.RS256), string(jose.ES256)},
			AuthorizationSignedResponseAlgValues:                      []string{string(jose.HS256)},
			RequireSignedRequestObjectSkipPushedAuthorizationRequests: true,
		}

		ApplyFAPI2MessageSigning(config, FAPI2MessageSigningAll)

		assert.True(t, config.RequireSignedRequestObject)
		assert.False(t, config.RequireSignedRequestObjectSkipPushedAuthorizationRequests)
		assert.True(t, config.RequirePushedAuthorizationRequests)
		assert.True(t, config.RequireRequestObjectAudienceAndLifetime)
		assert.Equal(t, time.Duration(0), config.RequestObjectMaximumLifetime)
		assert.Equal(t, []string{string(jose.ES256)}, config.RequestObjectSigningAlgValues)
		assert.Equal(t, oauth2.FAPI2SecurityProfileSigningAlgValues, config.AuthorizationSignedResponseAlgValues)
		assert.Equal(t, oauth2.FAPI2SecurityProfileSigningAlgValues, config.IntrospectionSignedResponseAlgValues)
		assert.True(t, config.EnforceIntrospectionPermission)
	})

	t.Run("ShouldApplyOnlyTheSelectedParts", func(t *testing.T) {
		config := &oauth2.Config{}

		ApplyFAPI2MessageSigning(config, FAPI2MessageSigningResponses)

		assert.False(t, config.RequireSignedRequestObject)
		assert.False(t, config.EnforceIntrospectionPermission)
		assert.Nil(t, config.IntrospectionSignedResponseAlgValues)
		assert.Equal(t, oauth2.FAPI2SecurityProfileSigningAlgValues, config.AuthorizationSignedResponseAlgValues)
	})
}

func newFAPI2MessageSigningConfig() *oauth2.Config {
	config := newFAPI2Config()

	strategy := &jwt.DefaultStrategy{
		Config: config,
		Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: gen.MustES256Key(), KeyID: "fapi2-message-signing", Algorithm: string(jose.ES256), Use: consts.JSONWebTokenUseSignature},
		}}),
	}

	config.JWTSecuredAuthorizeResponseModeStrategy = strategy
	config.IntrospectionJWTResponseStrategy = strategy

	return config
}
