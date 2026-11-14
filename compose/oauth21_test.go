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

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestValidateOAuth21Profile(t *testing.T) {
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
			name:      "ShouldPassWithTheNoneResponseType",
			factories: []Factory{OAuth2AuthorizeNoneFactory},
		},
		{
			name:   "ShouldPassWithoutRefreshTokenRotation",
			modify: func(config *oauth2.Config) { config.DisableRefreshTokenRotation = true },
		},
		{
			name:   "ShouldPassWithRefreshTokensWhichDoNotExpireBeforeTheMaximum",
			modify: func(config *oauth2.Config) { config.RefreshTokenLifespan = -1 },
		},
		{
			name: "ShouldPassWithoutClientSecrets",
			modify: func(config *oauth2.Config) {
				config.TokenEndpointAuthMethods = []string{consts.ClientAuthMethodPrivateKeyJWT, consts.ClientAuthMethodNone}
			},
		},
		{
			name:      "ShouldRejectThePasswordGrant",
			factories: []Factory{OAuth2ResourceOwnerPasswordCredentialsFactory},
			expected:  []string{"OAuth 2.1 Section 10: the resource owner password credentials grant handler must not be registered"},
		},
		{
			name:      "ShouldRejectTheImplicitGrant",
			factories: []Factory{OAuth2AuthorizeImplicitFactory},
			expected:  []string{"OAuth 2.1 Section 10.1: access tokens must not be issued in the authorization response, but the '*oauth2.AuthorizeImplicitGrantTypeHandler' authorize endpoint handler is registered"},
		},
		{
			name:      "ShouldRejectTheOpenIDConnectImplicitFlow",
			factories: []Factory{OAuth2AuthorizeImplicitFactory, OpenIDConnectImplicitFactory},
			expected:  []string{"OAuth 2.1 Section 10.1: access tokens must not be issued in the authorization response, but the '*openid.OpenIDConnectImplicitHandler' authorize endpoint handler is registered"},
		},
		{
			name:     "ShouldRejectOptionalPKCE",
			modify:   func(config *oauth2.Config) { config.EnforcePKCE = false },
			expected: []string{"OAuth 2.1 Section 4.1.1: PKCE must be enforced, but EnforcePKCE is not set"},
		},
		{
			name:     "ShouldRejectPublicClientsWithoutPKCE",
			modify:   func(config *oauth2.Config) { config.AllowPublicClientsWithoutPKCE = true },
			expected: []string{"OAuth 2.1 Section 4.1.2.1: requests from public clients without 'code_challenge' must be rejected, but AllowPublicClientsWithoutPKCE is set"},
		},
		{
			name:     "ShouldRejectThePlainPKCEMethod",
			modify:   func(config *oauth2.Config) { config.EnablePKCEPlainChallengeMethod = true },
			expected: []string{"OAuth 2.1 Section 7.5.2: the 'plain' code challenge method is forbidden, but EnablePKCEPlainChallengeMethod is set"},
		},
		{
			name:     "ShouldRejectInsecureRedirectURIsForPublicClients",
			modify:   func(config *oauth2.Config) { config.AllowInsecureRedirectURIForPublicClients = true },
			expected: []string{"OAuth 2.1 Section 1.5: redirect URIs other than loopback interface ones must use 'https', but AllowInsecureRedirectURIForPublicClients is set"},
		},
		{
			name:     "ShouldRejectAMissingIssuer",
			modify:   func(config *oauth2.Config) { config.Issuer = "" },
			expected: []string{"OAuth 2.1 Section 4.1.2: the 'iss' authorization response parameter must be returned, but Issuer is not set"},
		},
		{
			name:     "ShouldRejectDisabledIssuerIdentification",
			modify:   func(config *oauth2.Config) { config.DisableAuthorizationServerIdentification = true },
			expected: []string{"OAuth 2.1 Section 4.1.2: the 'iss' authorization response parameter must be returned, but DisableAuthorizationServerIdentification is set"},
		},
		{
			name:     "ShouldRejectALongAuthorizationCodeLifetime",
			modify:   func(config *oauth2.Config) { config.AuthorizeCodeLifespan = 11 * time.Minute },
			expected: []string{"OAuth 2.1 Section 4.1.2: the authorization code lifetime must be at most 10m0s, but is 11m0s"},
		},
		{
			name:     "ShouldRejectUnlimitedRefreshTokens",
			modify:   func(config *oauth2.Config) { config.RefreshTokenMaximumLifespan = 0 },
			expected: []string{"OAuth 2.1 Section 9.3.2: rotated refresh tokens must not outlive the first refresh token of the grant, but RefreshTokenMaximumLifespan is not set"},
		},
		{
			name:     "ShouldRejectANegativeRefreshTokenMaximumLifespan",
			modify:   func(config *oauth2.Config) { config.RefreshTokenMaximumLifespan = -1 },
			expected: []string{"OAuth 2.1 Section 9.3.2: rotated refresh tokens must not outlive the first refresh token of the grant, but RefreshTokenMaximumLifespan is not set"},
		},
		{
			name:     "ShouldRejectLowTokenEntropy",
			modify:   func(config *oauth2.Config) { config.TokenEntropy = 16 },
			expected: []string{"OAuth 2.1 Section 7.7: the client secrets the client registration handler generates must have a guessing probability of at most 2^-128, which needs a TokenEntropy of at least 22, but it is 16"},
		},
		{
			name: "ShouldRejectClientSecretsWithoutClientSecretPost",
			modify: func(config *oauth2.Config) {
				config.TokenEndpointAuthMethods = []string{consts.ClientAuthMethodClientSecretBasic, consts.ClientAuthMethodPrivateKeyJWT}
			},
			expected: []string{"OAuth 2.1 Section 2.4.1: the token endpoint accepts the client authentication methods 'client_secret_basic', 'private_key_jwt', but not 'client_secret_post'"},
		},
		{
			name: "ShouldRejectClientSecretJWTWithoutClientSecretPost",
			modify: func(config *oauth2.Config) {
				config.TokenEndpointAuthMethods = []string{consts.ClientAuthMethodClientSecretJWT}
			},
			expected: []string{"OAuth 2.1 Section 2.4.1: the token endpoint accepts the client authentication methods 'client_secret_jwt', but not 'client_secret_post'"},
		},
		{
			name:     "ShouldRejectAnArrayClientAssertionAudience",
			modify:   func(config *oauth2.Config) { config.DisableClientAssertionIssuerAudience = true },
			expected: []string{"OAuth 2.1 Section 2.4: the issuer must be the sole client assertion audience, but DisableClientAssertionIssuerAudience is set"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := newOAuth21Config()

			ApplyOAuth21Profile(config)

			if tc.modify != nil {
				tc.modify(config)
			}

			composeOAuth21(t, config, tc.factories...)

			err := ValidateOAuth21Profile(context.Background(), config)

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

func TestValidateOAuth21ProfileWithoutTheProfile(t *testing.T) {
	config := newOAuth21Config()
	config.AuthorizeCodeLifespan = time.Hour
	config.EnablePKCEPlainChallengeMethod = true

	ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey())

	err := ValidateOAuth21Profile(context.Background(), config)
	require.Error(t, err)

	for _, expected := range []string{
		"OAuth 2.1 Section 10.1: access tokens must not be issued in the authorization response, but the '*oauth2.AuthorizeImplicitGrantTypeHandler'",
		"OAuth 2.1 Section 10.1: access tokens must not be issued in the authorization response, but the '*openid.OpenIDConnectImplicitHandler'",
		"OAuth 2.1 Section 10.1: access tokens must not be issued in the authorization response, but the '*openid.OpenIDConnectHybridHandler'",
		"OAuth 2.1 Section 4.1.1: PKCE must be enforced, but EnforcePKCE is not set",
		"OAuth 2.1 Section 7.5.2: the 'plain' code challenge method is forbidden",
		"OAuth 2.1 Section 4.1.2: the authorization code lifetime must be at most 10m0s, but is 1h0m0s",
		"OAuth 2.1 Section 9.3.2: rotated refresh tokens must not outlive the first refresh token of the grant",
	} {
		assert.Contains(t, err.Error(), expected)
	}
}

func TestValidateOAuth21ProfileMissingHandlers(t *testing.T) {
	config := newOAuth21Config()

	ApplyOAuth21Profile(config)

	config.AuthorizeEndpointHandlers = oauth2.AuthorizeEndpointHandlers{&hoauth2.AuthorizeExplicitGrantHandler{}}

	err := ValidateOAuth21Profile(context.Background(), config)
	require.Error(t, err)

	for _, expected := range []string{
		"OAuth 2.1 Section 4.1.1: PKCE must be supported, but the PKCE handler is not registered",
		"OAuth 2.1 Section 4.1.2: the 'iss' authorization response parameter must be returned, but the RFC 9207 response mode parameter handler is not registered",
	} {
		assert.Contains(t, err.Error(), expected)
	}
}

func TestValidateOAuth21ProfileWithoutTheAuthorizationCodeGrant(t *testing.T) {
	config := newOAuth21Config()

	ApplyOAuth21Profile(config)

	config.TokenEntropy = 16
	config.RefreshTokenMaximumLifespan = 0

	Compose(config, storage.NewMemoryStore(), NewOAuth2HMACStrategy(config), OAuth2ClientCredentialsGrantFactory)

	assert.NoError(t, ValidateOAuth21Profile(context.Background(), config))
}

func TestApplyOAuth21Profile(t *testing.T) {
	config := &oauth2.Config{
		AuthorizeCodeLifespan:                    time.Hour,
		TokenEntropy:                             16,
		EnforcePKCE:                              false,
		AllowPublicClientsWithoutPKCE:            true,
		EnablePKCEPlainChallengeMethod:           true,
		AllowInsecureRedirectURIForPublicClients: true,
		DisableAuthorizationServerIdentification: true,
		DisableClientAssertionIssuerAudience:     true,
		TokenEndpointAuthMethods:                 []string{consts.ClientAuthMethodClientSecretBasic, consts.ClientAuthMethodPrivateKeyJWT},
	}

	ApplyOAuth21Profile(config)

	assert.Equal(t, 10*time.Minute, config.AuthorizeCodeLifespan)
	assert.Equal(t, 0, config.TokenEntropy)
	assert.Equal(t, 30*24*time.Hour, config.RefreshTokenMaximumLifespan)
	assert.Equal(t, time.Duration(0), config.RefreshTokenLifespan)
	assert.True(t, config.EnforcePKCE)
	assert.False(t, config.AllowPublicClientsWithoutPKCE)
	assert.False(t, config.EnablePKCEPlainChallengeMethod)
	assert.False(t, config.AllowInsecureRedirectURIForPublicClients)
	assert.False(t, config.DisableAuthorizationServerIdentification)
	assert.False(t, config.DisableClientAssertionIssuerAudience)
	assert.False(t, config.DisableRefreshTokenRotation)
	assert.Equal(t, []string{consts.ClientAuthMethodClientSecretBasic, consts.ClientAuthMethodPrivateKeyJWT, consts.ClientAuthMethodClientSecretPost}, config.TokenEndpointAuthMethods)

	t.Run("ShouldKeepValuesWithinTheProfile", func(t *testing.T) {
		config := &oauth2.Config{
			AuthorizeCodeLifespan:       5 * time.Minute,
			TokenEntropy:                64,
			RefreshTokenLifespan:        8 * time.Hour,
			RefreshTokenMaximumLifespan: 24 * time.Hour,
			DisableRefreshTokenRotation: true,
			TokenEndpointAuthMethods:    []string{consts.ClientAuthMethodPrivateKeyJWT},
		}

		ApplyOAuth21Profile(config)

		assert.Equal(t, 5*time.Minute, config.AuthorizeCodeLifespan)
		assert.Equal(t, 64, config.TokenEntropy)
		assert.Equal(t, 8*time.Hour, config.RefreshTokenLifespan)
		assert.Equal(t, 24*time.Hour, config.RefreshTokenMaximumLifespan)
		assert.True(t, config.DisableRefreshTokenRotation)
		assert.Equal(t, []string{consts.ClientAuthMethodPrivateKeyJWT}, config.TokenEndpointAuthMethods)
	})

	t.Run("ShouldKeepUnsetValues", func(t *testing.T) {
		config := &oauth2.Config{}

		ApplyOAuth21Profile(config)

		assert.Equal(t, time.Duration(0), config.AuthorizeCodeLifespan)
		assert.Equal(t, 0, config.TokenEntropy)
		assert.Nil(t, config.TokenEndpointAuthMethods)
	})

	for _, tc := range []struct {
		name     string
		lifespan time.Duration
		maximum  time.Duration
		expected time.Duration
	}{
		{"ShouldLimitRefreshTokensToTheDefaultLifespan", 0, 0, 30 * 24 * time.Hour},
		{"ShouldLimitRefreshTokensToTheConfiguredLifespan", 8 * time.Hour, 0, 8 * time.Hour},
		{"ShouldLimitRefreshTokensWhichNeverExpire", -1, 0, 30 * 24 * time.Hour},
		{"ShouldReplaceANegativeMaximum", 8 * time.Hour, -1, 8 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := &oauth2.Config{RefreshTokenLifespan: tc.lifespan, RefreshTokenMaximumLifespan: tc.maximum}

			ApplyOAuth21Profile(config)

			assert.Equal(t, tc.expected, config.RefreshTokenMaximumLifespan)
			assert.Equal(t, tc.lifespan, config.RefreshTokenLifespan)
		})
	}
}

func newOAuth21Config() *oauth2.Config {
	return &oauth2.Config{
		Issuer:                                "https://as.example.com",
		GlobalSecret:                          []byte("some-cool-secret-that-is-32bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
	}
}

func composeOAuth21(t *testing.T, config *oauth2.Config, extra ...Factory) oauth2.Provider {
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
		OAuth2ClientCredentialsGrantFactory,
		OAuth2RefreshTokenGrantFactory,
		RFC8628DeviceAuthorizeFactory,
		RFC8628UserAuthorizeFactory,
		RFC8628DeviceAuthorizeTokenFactory,
		RFC7523AssertionGrantFactory,
		RFC8693TokenExchangeGrantFactory,
		RFC8693AccessTokenTypeFactory,
		RFC8693RefreshTokenTypeFactory,
		RFC8693IDTokenTypeFactory,
		RFC8693ActorTokenValidationFactory,
		OpenIDConnectExplicitFactory,
		OpenIDConnectRefreshFactory,
		OpenIDConnectDeviceAuthorizeFactory,
		OAuth2TokenIntrospectionFactory,
		OAuth2TokenRevocationFactory,
		OAuth2PKCEFactory,
		PushedAuthorizeHandlerFactory,
		RFC7591ClientRegistrationFactory,
		RFC7592ClientConfigurationFactory,
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
