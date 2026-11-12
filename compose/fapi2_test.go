// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestValidateFAPI2SecurityProfile(t *testing.T) {
	testCases := []struct {
		name      string
		modify    func(config *oauth2.Config)
		factories []Factory
		expected  []string
	}{
		{
			name: "ShouldPassWithDPoP",
		},
		{
			name:   "ShouldPassWithMTLS",
			modify: func(config *oauth2.Config) { config.DPoPEnabled = false; config.MTLSEnabled = true },
		},
		{
			name:      "ShouldRejectThePasswordGrant",
			factories: []Factory{OAuth2ResourceOwnerPasswordCredentialsFactory},
			expected:  []string{"Section 5.3.2.1: the resource owner password credentials grant handler must not be registered"},
		},
		{
			name:      "ShouldRejectTheImplicitFlow",
			factories: []Factory{OAuth2AuthorizeImplicitFactory},
			expected:  []string{"Section 5.3.2.2: the response type must be 'code', but the '*oauth2.AuthorizeImplicitGrantTypeHandler' authorize endpoint handler is registered"},
		},
		{
			name: "ShouldRejectAClientSecretMethod",
			modify: func(config *oauth2.Config) {
				config.TokenEndpointAuthMethods = []string{consts.ClientAuthMethodClientSecretBasic}
			},
			expected: []string{"Section 5.3.2.1: the token endpoint accepts the client authentication methods 'client_secret_basic'"},
		},
		{
			name:     "ShouldRejectUnrestrictedClientAuthentication",
			modify:   func(config *oauth2.Config) { config.RevocationEndpointAuthMethods = nil },
			expected: []string{"Section 5.3.2.1: the revocation endpoint accepts the client authentication methods"},
		},
		{
			name:     "ShouldRejectBearerAccessTokens",
			modify:   func(config *oauth2.Config) { config.EnforceSenderConstrainedAccessTokens = false },
			expected: []string{"Section 5.3.2.1: only sender-constrained access tokens may be issued"},
		},
		{
			name:     "ShouldRejectNeitherDPoPNorMTLS",
			modify:   func(config *oauth2.Config) { config.DPoPEnabled = false },
			expected: []string{"Section 5.3.2.1: access tokens must be sender-constrained by DPoP or mTLS, but neither is enabled"},
		},
		{
			name:     "ShouldRejectAnArrayClientAssertionAudience",
			modify:   func(config *oauth2.Config) { config.DisableClientAssertionIssuerAudience = true },
			expected: []string{"Section 5.3.2.1: the issuer must be the sole client assertion audience"},
		},
		{
			name:     "ShouldRejectRefreshTokenRotation",
			modify:   func(config *oauth2.Config) { config.DisableRefreshTokenRotation = false },
			expected: []string{"Section 5.3.2.1: refresh tokens must not be rotated"},
		},
		{
			name:     "ShouldRejectALongAuthorizationCodeLifetime",
			modify:   func(config *oauth2.Config) { config.AuthorizeCodeLifespan = 2 * time.Minute },
			expected: []string{"Section 5.3.2.1: the authorization code lifetime must be at most 1m0s, but is 2m0s"},
		},
		{
			name:     "ShouldRejectAShortJWTClockSkew",
			modify:   func(config *oauth2.Config) { config.JWTClockSkew = time.Second },
			expected: []string{"Section 5.3.2.1: the JWT clock skew must be between 10s and 1m0s, but is 1s"},
		},
		{
			name:     "ShouldRejectALongDPoPClockSkew",
			modify:   func(config *oauth2.Config) { config.DPoPClockSkew = 2 * time.Minute },
			expected: []string{"Section 5.3.2.1: the DPoP clock skew must be between 10s and 1m0s, but is 2m0s"},
		},
		{
			name:     "ShouldRejectUnpushedAuthorizationRequests",
			modify:   func(config *oauth2.Config) { config.RequirePushedAuthorizationRequests = false },
			expected: []string{"Section 5.3.2.2: authorization requests must be pushed"},
		},
		{
			name:     "ShouldRejectPushedAuthorizationRequestsWithoutARedirectURI",
			modify:   func(config *oauth2.Config) { config.RequireRedirectURIPushedAuthorizationRequests = false },
			expected: []string{"Section 5.3.2.2: pushed authorization requests must carry 'redirect_uri'"},
		},
		{
			name:     "ShouldRejectALongPushedAuthorizationRequestLifetime",
			modify:   func(config *oauth2.Config) { config.PushedAuthorizeContextLifespan = 10 * time.Minute },
			expected: []string{"Section 5.3.2.2: the pushed authorization request 'expires_in' must be less than 10m0s, but is 10m0s"},
		},
		{
			name:     "ShouldRejectOptionalPKCE",
			modify:   func(config *oauth2.Config) { config.EnforcePKCE = false },
			expected: []string{"Section 5.3.2.2: PKCE is required, but EnforcePKCE is not set"},
		},
		{
			name:     "ShouldRejectThePlainPKCEMethod",
			modify:   func(config *oauth2.Config) { config.EnablePKCEPlainChallengeMethod = true },
			expected: []string{"Section 5.3.2.2: PKCE must use S256"},
		},
		{
			name:     "ShouldRejectAMissingIssuer",
			modify:   func(config *oauth2.Config) { config.Issuer = "" },
			expected: []string{"Section 5.3.2.2: the 'iss' authorization response parameter must be returned, but Issuer is not set"},
		},
		{
			name:     "ShouldRejectDisabledIssuerIdentification",
			modify:   func(config *oauth2.Config) { config.DisableAuthorizationServerIdentification = true },
			expected: []string{"Section 5.3.2.2: the 'iss' authorization response parameter must be returned, but DisableAuthorizationServerIdentification is set"},
		},
		{
			name:     "ShouldRejectRS256ClientAssertions",
			modify:   func(config *oauth2.Config) { config.ClientAssertionSigningAlgValues = []string{string(jose.RS256)} },
			expected: []string{"Section 5.4.1: the client assertion algorithms 'RS256' include one not permitted", "Section 5.4.1: the revocation endpoint client assertion algorithms 'RS256' include one not permitted"},
		},
		{
			name: "ShouldRejectUnsignedRequestObjects",
			modify: func(config *oauth2.Config) {
				config.RequestObjectSigningAlgValues = []string{"none", string(jose.PS256)}
			},
			expected: []string{"Section 5.4.1: the request object algorithms 'none', 'PS256' include one not permitted"},
		},
		{
			name:      "ShouldPassWithTheJWTBearerGrant",
			factories: []Factory{RFC7523AssertionGrantFactory},
		},
		{
			name:      "ShouldRejectRS256JWTBearerGrantAssertions",
			modify:    func(config *oauth2.Config) { config.RFC7523AssertionSigningAlgValues = []string{string(jose.RS256)} },
			factories: []Factory{RFC7523AssertionGrantFactory},
			expected:  []string{"Section 5.4.1: the JWT bearer grant assertion algorithms 'RS256' include one not permitted"},
		},
		{
			name:     "ShouldNotCheckJWTBearerGrantAssertionsWithoutTheGrant",
			modify:   func(config *oauth2.Config) { config.RFC7523AssertionSigningAlgValues = []string{string(jose.RS256)} },
			expected: nil,
		},
		{
			name: "ShouldPassWithIntrospection",
			modify: func(config *oauth2.Config) {
				config.IntrospectionEndpointAuthMethods = []string{consts.ClientAuthMethodPrivateKeyJWT, consts.AuthSchemeBearer}
			},
			factories: []Factory{OAuth2TokenIntrospectionFactory},
		},
		{
			name:      "ShouldRejectUnrestrictedIntrospection",
			factories: []Factory{OAuth2TokenIntrospectionFactory},
			expected:  []string{"Section 5.3.2.1: the introspection endpoint accepts the client authentication methods 'client_secret_basic'"},
		},
		{
			name: "ShouldPassWithBearerIntrospection",
			modify: func(config *oauth2.Config) {
				config.IntrospectionEndpointAuthMethods = []string{consts.AuthSchemeBearer}
			},
			factories: []Factory{OAuth2TokenIntrospectionFactory},
		},
		{
			name: "ShouldRejectAClientSecretMethodAtIntrospection",
			modify: func(config *oauth2.Config) {
				config.IntrospectionEndpointAuthMethods = []string{consts.ClientAuthMethodClientSecretBasic, consts.AuthSchemeBearer}
			},
			factories: []Factory{OAuth2TokenIntrospectionFactory},
			expected:  []string{"Section 5.3.2.1: the introspection endpoint accepts the client authentication methods 'client_secret_basic', but only"},
		},
		{
			name: "ShouldRejectRS256IntrospectionClientAssertions",
			modify: func(config *oauth2.Config) {
				config.IntrospectionEndpointAuthSigningAlgValues = []string{string(jose.RS256)}
			},
			factories: []Factory{OAuth2TokenIntrospectionFactory},
			expected:  []string{"Section 5.4.1: the introspection endpoint client assertion algorithms 'RS256' include one not permitted"},
		},
		{
			name:     "ShouldRejectRS256DPoPProofs",
			modify:   func(config *oauth2.Config) { config.DPoPAllowedJWSAlgorithms = []string{string(jose.RS256)} },
			expected: []string{"Section 5.4.1: the DPoP proof algorithms 'RS256' include one not permitted"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := newFAPI2Config()

			ApplyFAPI2SecurityProfile(config)

			if tc.modify != nil {
				tc.modify(config)
			}

			composeFAPI2(t, config, tc.factories...)

			err := ValidateFAPI2SecurityProfile(context.Background(), config)

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

func TestValidateFAPI2SecurityProfileWithoutTheProfile(t *testing.T) {
	config := newFAPI2Config()
	config.RFC7591ClientRegistrationGlobalSecret = []byte("a-completely-different-secret-at-least-32b")

	ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey())

	err := ValidateFAPI2SecurityProfile(context.Background(), config)
	require.Error(t, err)

	for _, expected := range []string{
		"the response type must be 'code'",
		"only sender-constrained access tokens may be issued",
		"refresh tokens must not be rotated",
		"the authorization code lifetime must be at most 1m0s, but is 2m0s",
		"authorization requests must be pushed",
		"PKCE is required, but EnforcePKCE is not set",
		"the token endpoint accepts the client authentication methods",
		"the client assertion algorithms",
	} {
		assert.Contains(t, err.Error(), expected)
	}
}

func TestValidateFAPI2SecurityProfileMissingHandlers(t *testing.T) {
	config := newFAPI2Config()
	config.MTLSEnabled = true

	ApplyFAPI2SecurityProfile(config)

	Compose(config, storage.NewMemoryStore(), NewOAuth2HMACStrategy(config), OAuth2AuthorizeExplicitFactory)

	err := ValidateFAPI2SecurityProfile(context.Background(), config)
	require.Error(t, err)

	for _, expected := range []string{
		"Section 5.3.2.1: DPoP is enabled, but the DPoP token endpoint handler is not registered",
		"Section 5.3.2.1: DPoP is enabled, but the DPoP authorization code binding handler is not registered",
		"Section 5.3.2.1: mTLS is enabled, but the mTLS certificate-bound access token handler is not registered",
		"Section 5.3.2.2: pushed authorization requests must be supported, but the pushed authorization request handler is not registered",
		"Section 5.3.2.2: PKCE is required, but the PKCE handler is not registered",
	} {
		assert.Contains(t, err.Error(), expected)
	}
}

func TestApplyFAPI2SecurityProfile(t *testing.T) {
	config := &oauth2.Config{
		AuthorizeCodeLifespan:                    5 * time.Minute,
		PushedAuthorizeContextLifespan:           time.Hour,
		JWTClockSkew:                             -1,
		DPoPClockSkew:                            30 * time.Second,
		DisableAuthorizationServerIdentification: true,
		DisableClientAssertionIssuerAudience:     true,
		EnablePKCEPlainChallengeMethod:           true,
		TokenEndpointAuthMethods:                 []string{consts.ClientAuthMethodClientSecretBasic, consts.ClientAuthMethodPrivateKeyJWT},
		RevocationEndpointAuthMethods:            []string{consts.ClientAuthMethodClientSecretBasic},
		ClientAssertionSigningAlgValues:          []string{string(jose.RS256), string(jose.ES256)},
		RevocationEndpointAuthSigningAlgValues:   []string{string(jose.RS256)},
		IntrospectionEndpointAuthMethods:         []string{consts.ClientAuthMethodClientSecretBasic, consts.ClientAuthMethodPrivateKeyJWT, consts.AuthSchemeBearer},
		RFC7523AssertionSigningAlgValues:         []string{string(jose.RS256), string(jose.PS256)},
	}

	ApplyFAPI2SecurityProfile(config)

	assert.Equal(t, time.Minute, config.AuthorizeCodeLifespan)
	assert.Equal(t, time.Duration(0), config.PushedAuthorizeContextLifespan)
	assert.Equal(t, time.Duration(0), config.JWTClockSkew)
	assert.Equal(t, 30*time.Second, config.DPoPClockSkew)
	assert.True(t, config.RequirePushedAuthorizationRequests)
	assert.True(t, config.RequireRedirectURIPushedAuthorizationRequests)
	assert.True(t, config.EnforcePKCE)
	assert.False(t, config.EnablePKCEPlainChallengeMethod)
	assert.False(t, config.DisableAuthorizationServerIdentification)
	assert.False(t, config.DisableClientAssertionIssuerAudience)
	assert.True(t, config.DisableRefreshTokenRotation)
	assert.True(t, config.EnforceSenderConstrainedAccessTokens)
	assert.Equal(t, []string{consts.ClientAuthMethodPrivateKeyJWT}, config.TokenEndpointAuthMethods)
	assert.Equal(t, FAPI2SecurityProfileClientAuthMethods, config.RevocationEndpointAuthMethods)
	assert.Equal(t, []string{string(jose.ES256)}, config.ClientAssertionSigningAlgValues)
	assert.Equal(t, FAPI2SecurityProfileSigningAlgValues, config.RequestObjectSigningAlgValues)
	assert.Equal(t, FAPI2SecurityProfileSigningAlgValues, config.DPoPAllowedJWSAlgorithms)
	assert.Equal(t, FAPI2SecurityProfileSigningAlgValues, config.RevocationEndpointAuthSigningAlgValues)
	assert.Equal(t, []string{consts.ClientAuthMethodPrivateKeyJWT, consts.AuthSchemeBearer}, config.IntrospectionEndpointAuthMethods)
	assert.Equal(t, []string{string(jose.PS256)}, config.RFC7523AssertionSigningAlgValues)
	assert.Nil(t, config.IntrospectionEndpointAuthSigningAlgValues)

	for _, tc := range []struct {
		name     string
		methods  []string
		expected []string
	}{
		{"ShouldKeepAnUnsetIntrospectionList", nil, nil},
		{"ShouldKeepABearerOnlyIntrospectionList", []string{consts.AuthSchemeBearer}, []string{consts.AuthSchemeBearer}},
		{"ShouldKeepATokenOnlyIntrospectionList", []string{consts.AuthSchemeBearer, consts.AuthSchemeDPoP}, []string{consts.AuthSchemeBearer, consts.AuthSchemeDPoP}},
		{"ShouldReplaceIntrospectionClientMethodsNonePermitted", []string{consts.ClientAuthMethodClientSecretBasic, consts.AuthSchemeBearer}, append(slices.Clone(FAPI2SecurityProfileClientAuthMethods), consts.AuthSchemeBearer)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := &oauth2.Config{IntrospectionEndpointAuthMethods: tc.methods}

			ApplyFAPI2SecurityProfile(config)

			assert.Equal(t, tc.expected, config.IntrospectionEndpointAuthMethods)
		})
	}
}

func newFAPI2Config() *oauth2.Config {
	return &oauth2.Config{
		Issuer:       "https://as.example.com",
		DPoPEnabled:  true,
		GlobalSecret: []byte("some-cool-secret-that-is-32bytes"),
	}
}

func composeFAPI2(t *testing.T, config *oauth2.Config, extra ...Factory) oauth2.Provider {
	t.Helper()

	key := gen.MustRSAKey()

	keyGetter := func(context.Context) (any, error) {
		return key, nil
	}

	strategy := &jwt.DefaultStrategy{
		Config: config,
		Issuer: jwt.NewDefaultIssuerRS256Unverified(key),
	}

	factories := append([]Factory{
		OAuth2AuthorizeExplicitFactory,
		OAuth2RefreshTokenGrantFactory,
		OAuth2PKCEFactory,
		PushedAuthorizeHandlerFactory,
		OpenIDConnectExplicitFactory,
		OpenIDConnectRefreshFactory,
		DPoPAuthorizeFactory,
		DPoPTokenFactory,
		RFC8705Factory,
	}, extra...)

	return Compose(
		config,
		storage.NewMemoryStore(),
		&CommonStrategy{
			CoreStrategy:               NewOAuth2HMACStrategy(config),
			OpenIDConnectTokenStrategy: NewOpenIDConnectStrategy(keyGetter, strategy, config),
			Strategy:                   strategy,
		},
		factories...,
	)
}
