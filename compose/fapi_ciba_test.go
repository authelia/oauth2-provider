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

const fapiCIBATestErrPush = "FAPI-CIBA Profile Section 4.1.1: the push token delivery mode must not be supported"

func TestApplyFAPICIBAProfile(t *testing.T) {
	testCases := []struct {
		name     string
		modes    []string
		algs     []string
		lifetime time.Duration
		expModes []string
		expAlgs  []string
		expLife  time.Duration
	}{
		{
			name:     "ShouldSetPollAndPingWhenUnset",
			expModes: []string{consts.CIBAModePoll, consts.CIBAModePing},
			expAlgs:  oauth2.FAPICIBASigningAlgValues,
			expLife:  time.Hour,
		},
		{
			name:     "ShouldRemovePush",
			modes:    []string{consts.CIBAModePush, consts.CIBAModePoll, consts.CIBAModePing},
			algs:     []string{string(jose.RS256), string(jose.ES256), string(jose.PS256)},
			expModes: []string{consts.CIBAModePoll, consts.CIBAModePing},
			expAlgs:  []string{string(jose.ES256), string(jose.PS256)},
			expLife:  time.Hour,
		},
		{
			name:     "ShouldAddPoll",
			modes:    []string{consts.CIBAModePing, consts.CIBAModePush},
			expModes: []string{consts.CIBAModePing, consts.CIBAModePoll},
			expAlgs:  oauth2.FAPICIBASigningAlgValues,
			expLife:  time.Hour,
		},
		{
			name:     "ShouldReplaceAPushOnlyList",
			modes:    []string{consts.CIBAModePush},
			algs:     []string{string(jose.RS256)},
			expModes: []string{consts.CIBAModePoll, consts.CIBAModePing},
			expAlgs:  oauth2.FAPICIBASigningAlgValues,
			expLife:  time.Hour,
		},
		{
			name:     "ShouldKeepAShorterLifetime",
			modes:    []string{consts.CIBAModePoll},
			lifetime: 10 * time.Minute,
			expModes: []string{consts.CIBAModePoll},
			expAlgs:  oauth2.FAPICIBASigningAlgValues,
			expLife:  10 * time.Minute,
		},
		{
			name:     "ShouldReplaceALongerLifetime",
			lifetime: 2 * time.Hour,
			expModes: []string{consts.CIBAModePoll, consts.CIBAModePing},
			expAlgs:  oauth2.FAPICIBASigningAlgValues,
			expLife:  time.Hour,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &oauth2.Config{
				CIBATokenDeliveryModes:           tc.modes,
				CIBARequestSigningAlgValues:      tc.algs,
				CIBASignedRequestMaximumLifetime: tc.lifetime,
			}

			ApplyFAPICIBAProfile(config)

			assert.Equal(t, tc.expModes, config.CIBATokenDeliveryModes)
			assert.Equal(t, tc.expAlgs, config.CIBARequestSigningAlgValues)
			assert.Equal(t, tc.expLife, config.CIBASignedRequestMaximumLifetime)
			assert.True(t, config.CIBARequireBindingMessage)
			assert.True(t, config.CIBARequireSingleAudienceAssertion)
			assert.False(t, config.CIBARequireRequestContext)
		})
	}
}

func TestApplyFAPICIBAProfileSigningAlgs(t *testing.T) {
	const rs256, ps256, es256, eddsa = string(jose.RS256), string(jose.PS256), string(jose.ES256), string(jose.EdDSA)

	t.Run("ShouldNarrowEveryConfiguredList", func(t *testing.T) {
		configured := []string{rs256, eddsa, es256, ps256}

		config := &oauth2.Config{
			CIBARequestSigningAlgValues:               configured,
			ClientAssertionSigningAlgValues:           configured,
			RequestObjectSigningAlgValues:             configured,
			DPoPAllowedJWSAlgorithms:                  configured,
			RFC7523AssertionSigningAlgValues:          configured,
			AuthorizationSignedResponseAlgValues:      configured,
			IntrospectionSignedResponseAlgValues:      configured,
			RevocationEndpointAuthSigningAlgValues:    configured,
			IntrospectionEndpointAuthSigningAlgValues: configured,
		}

		ApplyFAPICIBAProfile(config)

		expected := []string{es256, ps256}

		assert.Equal(t, expected, config.CIBARequestSigningAlgValues)
		assert.Equal(t, expected, config.ClientAssertionSigningAlgValues)
		assert.Equal(t, expected, config.RequestObjectSigningAlgValues)
		assert.Equal(t, expected, config.DPoPAllowedJWSAlgorithms)
		assert.Equal(t, expected, config.RFC7523AssertionSigningAlgValues)
		assert.Equal(t, expected, config.AuthorizationSignedResponseAlgValues)
		assert.Equal(t, expected, config.IntrospectionSignedResponseAlgValues)
		assert.Equal(t, expected, config.RevocationEndpointAuthSigningAlgValues)
		assert.Equal(t, expected, config.IntrospectionEndpointAuthSigningAlgValues)
	})

	t.Run("ShouldNarrowTheFAPI2Lists", func(t *testing.T) {
		config := &oauth2.Config{}

		ApplyFAPI2SecurityProfile(config)
		ApplyFAPICIBAProfile(config)

		ctx := context.Background()

		for name, algs := range map[string][]string{
			"CIBARequestSigningAlgValues":               config.GetCIBARequestSigningAlgValues(ctx),
			"ClientAssertionSigningAlgValues":           config.GetClientAssertionSigningAlgValues(ctx),
			"RequestObjectSigningAlgValues":             config.GetRequestObjectSigningAlgValues(ctx),
			"DPoPAllowedJWSAlgorithms":                  config.GetDPoPAllowedJWSAlgorithms(ctx),
			"RFC7523AssertionSigningAlgValues":          config.GetRFC7523AssertionSigningAlgValues(ctx),
			"AuthorizationSignedResponseAlgValues":      config.GetAuthorizationSignedResponseAlgValues(ctx),
			"IntrospectionSignedResponseAlgValues":      config.GetIntrospectionSignedResponseAlgValues(ctx),
			"RevocationEndpointAuthSigningAlgValues":    oauth2.SupportedEndpointAuthSigningAlgValues(ctx, config, oauth2.ClientAuthEndpointRevocation),
			"IntrospectionEndpointAuthSigningAlgValues": oauth2.SupportedEndpointAuthSigningAlgValues(ctx, config, oauth2.ClientAuthEndpointIntrospection),
		} {
			assert.Equal(t, oauth2.FAPICIBASigningAlgValues, algs, name)
		}
	})

	t.Run("ShouldKeepUnsetEndpointLists", func(t *testing.T) {
		config := &oauth2.Config{}

		ApplyFAPICIBAProfile(config)

		assert.Nil(t, config.RevocationEndpointAuthSigningAlgValues)
		assert.Nil(t, config.IntrospectionEndpointAuthSigningAlgValues)
	})
}

func TestApplyFAPICIBAProfileRemovesRSA15(t *testing.T) {
	const rsa15, oaep = string(jose.RSA1_5), string(jose.RSA_OAEP_256)

	testCases := []struct {
		name       string
		configured []string
		expected   []string
	}{
		{"ShouldRemoveRSA15FromTheDefaults", nil, nil},
		{"ShouldRemoveRSA15FromAConfiguredList", []string{rsa15, oaep}, []string{oaep}},
		{"ShouldKeepAListWithoutRSA15", []string{oaep}, []string{oaep}},
		{"ShouldReplaceAnRSA15OnlyListWithTheDefaults", []string{rsa15}, nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			config := &oauth2.Config{
				ClientAssertionEncryptionAlgValues: tc.configured,
				RequestObjectEncryptionAlgValues:   tc.configured,
				ResponseEncryptionAlgValues:        map[oauth2.ResponseEncryptionTarget][]string{},
			}

			for _, target := range fapiCIBAResponseEncryptionTargets {
				config.ResponseEncryptionAlgValues[target] = tc.configured
			}

			ApplyFAPICIBAProfile(config)

			effective := map[string][]string{
				"client_assertion": config.GetClientAssertionEncryptionAlgValues(ctx),
				"request_object":   config.GetRequestObjectEncryptionAlgValues(ctx),
			}

			for _, target := range fapiCIBAResponseEncryptionTargets {
				effective[string(target)] = config.GetResponseEncryptionAlgValues(ctx, target)
			}

			for name, algs := range effective {
				assert.NotEmpty(t, algs, name)
				assert.NotContains(t, algs, rsa15, name)

				if tc.expected != nil {
					assert.Equal(t, tc.expected, algs, name)
				}
			}
		})
	}
}

func TestValidateFAPICIBAProfile(t *testing.T) {
	testCases := []struct {
		name      string
		modify    func(config *oauth2.Config)
		factories []Factory
		expected  []string
	}{
		{
			name: "ShouldPass",
		},
		{
			name:   "ShouldPassWithPollOnly",
			modify: func(config *oauth2.Config) { config.CIBATokenDeliveryModes = []string{consts.CIBAModePoll} },
		},
		{
			name:   "ShouldIncludeTheFAPI2SecurityProfile",
			modify: func(config *oauth2.Config) { config.EnforcePKCE = false },
			expected: []string{
				"FAPI-CIBA Profile Section 4.1.1: the FAPI 2.0 Security Profile requirements must be met",
				"FAPI 2.0 Security Profile Section 5.3.2.2: PKCE is required, but EnforcePKCE is not set",
			},
		},
		{
			name: "ShouldRejectPush",
			modify: func(config *oauth2.Config) {
				config.CIBATokenDeliveryModes = []string{consts.CIBAModePoll, consts.CIBAModePush}
			},
			expected: []string{fapiCIBATestErrPush},
		},
		{
			name:     "ShouldRejectPushByDefault",
			modify:   func(config *oauth2.Config) { config.CIBATokenDeliveryModes = nil },
			expected: []string{fapiCIBATestErrPush},
		},
		{
			name:     "ShouldRequirePoll",
			modify:   func(config *oauth2.Config) { config.CIBATokenDeliveryModes = []string{consts.CIBAModePing} },
			expected: []string{"FAPI-CIBA Profile Section 4.1.1: the poll token delivery mode must be supported"},
		},
		{
			name:     "ShouldRequireTheBindingMessage",
			modify:   func(config *oauth2.Config) { config.CIBARequireBindingMessage = false },
			expected: []string{"FAPI-CIBA Profile Section 4.1.1: a unique authorization context or a 'binding_message' must be required, but CIBARequireBindingMessage is not set"},
		},
		{
			name: "ShouldRejectRS256SignedRequests",
			modify: func(config *oauth2.Config) {
				config.CIBARequestSigningAlgValues = []string{string(jose.PS256), string(jose.RS256)}
			},
			expected: []string{"FAPI-CIBA Profile Section 5.10: the signed authentication request algorithms 'PS256', 'RS256' include one not permitted"},
		},
		{
			name:     "ShouldRejectEdDSAClientAssertions",
			modify:   func(config *oauth2.Config) { config.ClientAssertionSigningAlgValues = []string{string(jose.EdDSA)} },
			expected: []string{"FAPI-CIBA Profile Section 5.10: the client assertion algorithms 'EdDSA' include one not permitted"},
		},
		{
			name: "ShouldRejectEdDSARevocationClientAssertions",
			modify: func(config *oauth2.Config) {
				config.RevocationEndpointAuthSigningAlgValues = []string{string(jose.ES256), string(jose.EdDSA)}
			},
			expected: []string{"FAPI-CIBA Profile Section 5.10: the revocation endpoint client assertion algorithms 'ES256', 'EdDSA' include one not permitted"},
		},
		{
			name:     "ShouldRejectEdDSARequestObjects",
			modify:   func(config *oauth2.Config) { config.RequestObjectSigningAlgValues = []string{string(jose.EdDSA)} },
			expected: []string{"FAPI-CIBA Profile Section 5.10: the request object algorithms 'EdDSA' include one not permitted"},
		},
		{
			name:     "ShouldRejectEdDSADPoPProofs",
			modify:   func(config *oauth2.Config) { config.DPoPAllowedJWSAlgorithms = []string{string(jose.EdDSA)} },
			expected: []string{"FAPI-CIBA Profile Section 5.10: the DPoP proof algorithms 'EdDSA' include one not permitted"},
		},
		{
			name:      "ShouldRejectEdDSAJWTBearerGrantAssertions",
			modify:    func(config *oauth2.Config) { config.RFC7523AssertionSigningAlgValues = []string{string(jose.EdDSA)} },
			factories: append(CIBAFactories(), RFC7523AssertionGrantFactory),
			expected:  []string{"FAPI-CIBA Profile Section 5.10: the JWT bearer grant assertion algorithms 'EdDSA' include one not permitted"},
		},
		{
			name: "ShouldRejectEdDSAIntrospectionClientAssertions",
			modify: func(config *oauth2.Config) {
				config.IntrospectionEndpointAuthMethods = []string{consts.ClientAuthMethodPrivateKeyJWT}
				config.IntrospectionEndpointAuthSigningAlgValues = []string{string(jose.EdDSA)}
			},
			factories: append(CIBAFactories(), OAuth2TokenIntrospectionFactory),
			expected:  []string{"FAPI-CIBA Profile Section 5.10: the introspection endpoint client assertion algorithms 'EdDSA' include one not permitted"},
		},
		{
			name: "ShouldRejectHS256AuthorizationResponses",
			modify: func(config *oauth2.Config) {
				config.JWTSecuredAuthorizeResponseModeStrategy = newFAPICIBATestES256Strategy(config)
				config.AuthorizationSignedResponseAlgValues = []string{string(jose.ES256), string(jose.HS256)}
			},
			expected: []string{"FAPI-CIBA Profile Section 5.10: the authorization response algorithms 'ES256', 'HS256' include one not permitted"},
		},
		{
			name: "ShouldRejectHS256IntrospectionResponses",
			modify: func(config *oauth2.Config) {
				config.IntrospectionJWTResponseStrategy = newFAPICIBATestES256Strategy(config)
				config.IntrospectionSignedResponseAlgValues = []string{string(jose.ES256), string(jose.HS256)}
			},
			expected: []string{"FAPI-CIBA Profile Section 5.10: the introspection response algorithms 'ES256', 'HS256' include one not permitted"},
		},
		{
			name: "ShouldPassWithSignedResponses",
			modify: func(config *oauth2.Config) {
				config.JWTSecuredAuthorizeResponseModeStrategy = newFAPICIBATestES256Strategy(config)
				config.IntrospectionJWTResponseStrategy = newFAPICIBATestES256Strategy(config)
			},
		},
		{
			name:     "ShouldRequireIssuerAudience",
			modify:   func(config *oauth2.Config) { config.DisableClientAssertionIssuerAudience = true },
			expected: []string{"FAPI-CIBA Profile Section 4.1.1: the issuer must be the sole client assertion audience, but DisableClientAssertionIssuerAudience is set"},
		},
		{
			name: "ShouldRejectPublicClients",
			modify: func(config *oauth2.Config) {
				config.TokenEndpointAuthMethods = []string{consts.ClientAuthMethodPrivateKeyJWT, consts.ClientAuthMethodNone}
			},
			expected: []string{"FAPI-CIBA Profile Section 4.1.1: only confidential clients may be supported, but the backchannel_authentication endpoint accepts the client authentication method 'none'"},
		},
		{
			name: "ShouldRejectRSA15ClientAssertionDecryption",
			modify: func(config *oauth2.Config) {
				config.ClientAssertionEncryptionAlgValues = []string{string(jose.RSA_OAEP_256), string(jose.RSA1_5)}
			},
			expected: []string{"FAPI-CIBA Profile Section 5.11: the RSA1_5 algorithm must not be used, but the client assertion encryption algorithms are 'RSA-OAEP-256', 'RSA1_5'"},
		},
		{
			name:     "ShouldRejectRSA15RequestObjectDecryption",
			modify:   func(config *oauth2.Config) { config.RequestObjectEncryptionAlgValues = []string{string(jose.RSA1_5)} },
			expected: []string{"FAPI-CIBA Profile Section 5.11: the RSA1_5 algorithm must not be used, but the request object encryption algorithms are 'RSA1_5'"},
		},
		{
			name: "ShouldRejectRSA15ResponseEncryption",
			modify: func(config *oauth2.Config) {
				config.ResponseEncryptionAlgValues = map[oauth2.ResponseEncryptionTarget][]string{oauth2.ResponseEncryptionTargetIDToken: {string(jose.RSA1_5)}}
			},
			expected: []string{"FAPI-CIBA Profile Section 5.11: the RSA1_5 algorithm must not be used, but the id_token response encryption algorithms are 'RSA1_5'"},
		},
		{
			name:     "ShouldRejectRSA15ResponseEncryptionByDefault",
			modify:   func(config *oauth2.Config) { config.ResponseEncryptionAlgValues = nil },
			expected: []string{"FAPI-CIBA Profile Section 5.11: the RSA1_5 algorithm must not be used, but the userinfo response encryption algorithms are"},
		},
		{
			name:      "ShouldRequireTheACRConveyanceHandler",
			factories: []Factory{CIBADecisionFactory, CIBATokenFactory, CIBAEndpointFactory},
			expected:  []string{"FAPI-CIBA Profile Section 4.1.1: the 'acr' claim must be returned in the ID Token when requested, but the OpenID Connect CIBA handler is not registered"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := newFAPI2Config()

			ApplyFAPI2SecurityProfile(config)
			ApplyFAPICIBAProfile(config)

			if tc.modify != nil {
				tc.modify(config)
			}

			factories := tc.factories
			if factories == nil {
				factories = CIBAFactories()
			}

			composeFAPI2(t, config, factories...)

			err := ValidateFAPICIBAProfile(context.Background(), config)

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

func TestValidateFAPICIBAProfileWithoutTheProfile(t *testing.T) {
	config := newFAPI2Config()

	ApplyFAPI2SecurityProfile(config)

	composeFAPI2(t, config, CIBAFactories()...)

	err := ValidateFAPICIBAProfile(context.Background(), config)
	require.Error(t, err)

	for _, expected := range []string{
		"the push token delivery mode must not be supported",
		"CIBARequireBindingMessage is not set",
	} {
		assert.Contains(t, err.Error(), expected)
	}

	assert.NotContains(t, err.Error(), "FAPI 2.0 Security Profile")
}

func newFAPICIBATestES256Strategy(config *oauth2.Config) jwt.Strategy {
	return &jwt.DefaultStrategy{
		Config: config,
		Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: gen.MustES256Key(), KeyID: "fapi-ciba", Algorithm: string(jose.ES256), Use: consts.JSONWebTokenUseSignature},
		}}),
	}
}
