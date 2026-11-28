// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/handler/ciba"
	"authelia.com/provider/oauth2/handler/idjag"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/handler/rfc7591"
	"authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/handler/rfc8705"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

var update = flag.Bool("update", false, "update the golden files")

func TestOAuth2MetadataComposeAllEnabled(t *testing.T) {
	config := newDiscoveryAllEnabledConfig()
	provider := compose.ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey())

	metadata, err := provider.NewOAuth2AuthorizationServerMetadata(context.Background())
	require.NoError(t, err)

	assertGolden(t, filepath.Join("testdata", "discovery", "oauth2_all_enabled.json"), metadata)
}

func TestOAuth2MetadataMinimal(t *testing.T) {
	config := &oauth2.Config{
		Issuer: "https://auth.example.com",
		EndpointURLs: oauth2.EndpointURLs{
			Authorization:              "https://auth.example.com/authorize",
			Token:                      "https://auth.example.com/token",
			JWKS:                       "https://auth.example.com/jwks.json",
			Revocation:                 "https://auth.example.com/revoke",
			Introspection:              "https://auth.example.com/introspect",
			PushedAuthorizationRequest: "https://auth.example.com/par",
			DeviceAuthorization:        "https://auth.example.com/device",
			MutualTLSAliases:           oauth2.RFC8705MutualTLSEndpointAliases{Token: "https://mtls.auth.example.com/token"},
		},
		DPoPEnabled: true,
		MTLSEnabled: true,
	}

	provider := compose.Compose(config, storage.NewMemoryStore(), &compose.CommonStrategy{CoreStrategy: compose.NewOAuth2HMACStrategy(config)},
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2RefreshTokenGrantFactory,
	)

	metadata, err := provider.NewOAuth2AuthorizationServerMetadata(context.Background())
	require.NoError(t, err)

	members := marshalMembers(t, metadata)

	for _, name := range []string{
		consts.DiscoveryPushedAuthorizationRequestEndpoint,
		consts.DiscoveryRequirePushedAuthorizationRequests,
		consts.DiscoveryDeviceAuthorizationEndpoint,
		consts.DiscoveryDPoPSigningAlgValuesSupported,
		consts.DiscoveryTLSClientCertificateBoundAccessTokens,
		consts.DiscoveryAuthorizationSigningAlgValuesSupported,
		consts.DiscoveryAuthorizationEncryptionAlgValuesSupported,
		consts.DiscoveryAuthorizationEncryptionEncValuesSupported,
		consts.DiscoveryAuthorizationDetailsTypesSupported,
		consts.DiscoveryClientIDMetadataDocumentSupported,
		consts.DiscoveryCodeChallengeMethodsSupported,
		consts.DiscoveryRevocationEndpoint,
		consts.DiscoveryIntrospectionEndpoint,
		consts.DiscoveryRegistrationEndpoint,
	} {
		assert.NotContains(t, members, name)
	}

	assert.Equal(t, "https://auth.example.com", metadata.Issuer)
	assert.Equal(t, "https://auth.example.com/authorize", metadata.AuthorizationEndpoint)
	assert.Equal(t, "https://auth.example.com/token", metadata.TokenEndpoint)
	assert.Equal(t, []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken}, metadata.GrantTypesSupported)
	assert.Equal(t, []string{consts.ResponseTypeAuthorizationCodeFlow}, metadata.ResponseTypesSupported)
	assert.NotNil(t, metadata.RFC9101JWTSecuredAuthorizationRequestMetadata)
	assert.Equal(t, &oauth2.RFC8705MutualTLSMetadata{MutualTLSEndpointAliases: &oauth2.RFC8705MutualTLSEndpointAliases{Token: "https://mtls.auth.example.com/token"}}, metadata.RFC8705MutualTLSMetadata)
}

func TestOAuth2MetadataMutualTLS(t *testing.T) {
	const (
		mtlsRevocation    = "https://mtls.auth.example.com/revoke"
		mtlsIntrospection = "https://mtls.auth.example.com/introspect"
		mtlsUserInfo      = "https://mtls.auth.example.com/userinfo"
	)

	aliases := oauth2.RFC8705MutualTLSEndpointAliases{Token: "https://mtls.auth.example.com/token"}

	testCases := []struct {
		name     string
		enabled  bool
		handler  bool
		aliases  oauth2.RFC8705MutualTLSEndpointAliases
		expected *oauth2.RFC8705MutualTLSMetadata
	}{
		{name: "ShouldOmitWhenDisabled", handler: true, aliases: aliases},
		{name: "ShouldOmitWithoutTheHandlerOrAliases", enabled: true},
		{
			name:     "ShouldAdvertiseTheAliasesForClientAuthenticationWithoutTheHandler",
			enabled:  true,
			aliases:  aliases,
			expected: &oauth2.RFC8705MutualTLSMetadata{MutualTLSEndpointAliases: &aliases},
		},
		{
			name:     "ShouldAdvertiseBoundTokensWithoutAliases",
			enabled:  true,
			handler:  true,
			expected: &oauth2.RFC8705MutualTLSMetadata{TLSClientCertificateBoundAccessTokens: true},
		},
		{
			name:     "ShouldAdvertiseBoundTokensAndAliases",
			enabled:  true,
			handler:  true,
			aliases:  aliases,
			expected: &oauth2.RFC8705MutualTLSMetadata{TLSClientCertificateBoundAccessTokens: true, MutualTLSEndpointAliases: &aliases},
		},
		{
			name:    "ShouldOmitAliasesOfEndpointsNotAdvertised",
			enabled: true,
			aliases: oauth2.RFC8705MutualTLSEndpointAliases{
				Token:               aliases.Token,
				Revocation:          mtlsRevocation,
				Introspection:       mtlsIntrospection,
				DeviceAuthorization: "https://mtls.auth.example.com/device",
				UserInfo:            mtlsUserInfo,
			},
			expected: &oauth2.RFC8705MutualTLSMetadata{MutualTLSEndpointAliases: &aliases},
		},
		{
			name:    "ShouldOmitWhenNoAliasedEndpointIsAdvertised",
			enabled: true,
			aliases: oauth2.RFC8705MutualTLSEndpointAliases{Introspection: mtlsIntrospection},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &oauth2.Config{
				Issuer: "https://auth.example.com",
				EndpointURLs: oauth2.EndpointURLs{
					Authorization:    "https://auth.example.com/authorize",
					Token:            "https://auth.example.com/token",
					JWKS:             "https://auth.example.com/jwks.json",
					MutualTLSAliases: tc.aliases,
				},
				MTLSEnabled: tc.enabled,
			}

			provider := compose.Compose(config, storage.NewMemoryStore(), &compose.CommonStrategy{CoreStrategy: compose.NewOAuth2HMACStrategy(config)}, compose.OAuth2AuthorizeExplicitFactory)

			if tc.handler {
				config.TokenEndpointBindingHandlers.Append(&rfc8705.Handler{Config: config})
			}

			metadata, err := provider.NewOAuth2AuthorizationServerMetadata(context.Background())
			require.NoError(t, err)

			assert.Equal(t, tc.expected, metadata.RFC8705MutualTLSMetadata)
		})
	}
}

func TestOAuth2MetadataDPoPDisabled(t *testing.T) {
	config := newDiscoveryAllEnabledConfig()
	config.DPoPEnabled = false

	provider := compose.ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey())

	metadata, err := provider.NewOAuth2AuthorizationServerMetadata(context.Background())
	require.NoError(t, err)

	assert.Nil(t, metadata.RFC9449DPoPMetadata)
	assert.NotContains(t, marshalMembers(t, metadata), consts.DiscoveryDPoPSigningAlgValuesSupported)
}

func TestOAuth2MetadataIdentityChainingRequiresTokenExchange(t *testing.T) {
	testCases := []struct {
		name     string
		grant    bool
		chaining bool
		expected *oauth2.DraftIdentityChainingMetadata
	}{
		{
			name:     "ShouldOmitWithoutTheTokenExchangeGrant",
			chaining: true,
		},
		{
			name:  "ShouldOmitWithoutAnAuthorizationGrantTokenType",
			grant: true,
		},
		{
			name:     "ShouldAdvertiseOnlyTheAuthorizationGrantTokenTypes",
			grant:    true,
			chaining: true,
			expected: &oauth2.DraftIdentityChainingMetadata{
				IdentityChainingRequestedTokenTypesSupported: []string{consts.TokenTypeRFC8693JWT},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &oauth2.Config{
				Issuer: "https://auth.example.com",
				EndpointURLs: oauth2.EndpointURLs{
					Authorization: "https://auth.example.com/authorize",
					Token:         "https://auth.example.com/token",
					JWKS:          "https://auth.example.com/jwks.json",
				},
				RFC8693TokenTypes: map[string]oauth2.RFC8693TokenType{
					consts.TokenTypeRFC8693AccessToken: &rfc8693.DefaultTokenType{Name: consts.TokenTypeRFC8693AccessToken},
				},
			}

			if tc.chaining {
				config.RFC8693TokenTypes[consts.TokenTypeRFC8693JWT] = &rfc8693.JWTType{Name: consts.TokenTypeRFC8693JWT, Issue: &rfc8693.JWTIssueConfig{Issuer: "https://auth.example.com", AuthorizationGrant: true}}
			}

			provider := compose.Compose(config, storage.NewMemoryStore(), &compose.CommonStrategy{CoreStrategy: compose.NewOAuth2HMACStrategy(config)}, compose.OAuth2AuthorizeExplicitFactory)

			if tc.grant {
				config.TokenEndpointHandlers.Append(&rfc8693.TokenExchangeGrantHandler{Config: config})
			}

			config.TokenEndpointHandlers.Append(&rfc8693.AccessTokenTypeHandler{Config: config})
			config.TokenEndpointHandlers.Append(&rfc8693.CustomJWTTypeHandler{Config: config})

			metadata, err := provider.NewOAuth2AuthorizationServerMetadata(context.Background())
			require.NoError(t, err)

			assert.Equal(t, tc.expected, metadata.DraftIdentityChainingMetadata)
		})
	}
}

func TestOAuth2MetadataRefreshTokenExpirationTypesSupported(t *testing.T) {
	testCases := []struct {
		name     string
		config   *oauth2.Config
		refresh  bool
		expected []string
	}{
		{
			name:     "ShouldAdvertiseBothTypes",
			config:   &oauth2.Config{},
			refresh:  true,
			expected: []string{consts.RefreshTokenExpirationTypeAuthorization, consts.RefreshTokenExpirationTypeTokenTimeout},
		},
		{
			name:     "ShouldAdvertiseBothTypesWithNonExpiringRefreshTokensAndNoMaximumLifespan",
			config:   &oauth2.Config{RefreshTokenLifespan: -1},
			refresh:  true,
			expected: []string{consts.RefreshTokenExpirationTypeAuthorization, consts.RefreshTokenExpirationTypeTokenTimeout},
		},
		{
			name:    "ShouldOmitWhenTheParametersAreDisabled",
			config:  &oauth2.Config{DisableRefreshTokenExpirationParameters: true},
			refresh: true,
		},
		{
			name:   "ShouldOmitWithoutTheRefreshTokenGrant",
			config: &oauth2.Config{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.config.Issuer = "https://auth.example.com"
			tc.config.EndpointURLs = oauth2.EndpointURLs{
				Authorization: "https://auth.example.com/authorize",
				Token:         "https://auth.example.com/token",
				JWKS:          "https://auth.example.com/jwks.json",
			}

			factories := []compose.Factory{compose.OAuth2AuthorizeExplicitFactory}

			if tc.refresh {
				factories = append(factories, compose.OAuth2RefreshTokenGrantFactory)
			}

			provider := compose.Compose(tc.config, storage.NewMemoryStore(), &compose.CommonStrategy{CoreStrategy: compose.NewOAuth2HMACStrategy(tc.config)}, factories...)

			metadata, err := provider.NewOAuth2AuthorizationServerMetadata(context.Background())
			require.NoError(t, err)

			if tc.expected == nil {
				assert.Nil(t, metadata.DraftRefreshTokenExpirationMetadata)

				return
			}

			require.NotNil(t, metadata.DraftRefreshTokenExpirationMetadata)
			assert.Equal(t, tc.expected, metadata.RefreshTokenExpirationTypesSupported)
		})
	}
}

func TestOAuth2MetadataIDJAGSigningAlgValuesRequireRS256(t *testing.T) {
	testCases := []struct {
		name     string
		key      jose.JSONWebKey
		expected []string
	}{
		{
			name:     "ShouldAdvertiseWithRS256",
			key:      jose.JSONWebKey{Key: gen.MustRSAKey(), KeyID: "rs256", Algorithm: string(jose.RS256), Use: consts.JSONWebTokenUseSignature},
			expected: []string{"RS256"},
		},
		{
			name: "ShouldOmitWithoutRS256",
			key:  jose.JSONWebKey{Key: gen.MustES256Key(), KeyID: "es256", Algorithm: string(jose.ES256), Use: consts.JSONWebTokenUseSignature},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &oauth2.Config{
				Issuer: "https://auth.example.com",
				EndpointURLs: oauth2.EndpointURLs{
					Authorization: "https://auth.example.com/authorize",
					Token:         "https://auth.example.com/token",
					JWKS:          "https://auth.example.com/jwks.json",
				},
			}

			provider := compose.Compose(config, storage.NewMemoryStore(), &compose.CommonStrategy{CoreStrategy: compose.NewOAuth2HMACStrategy(config)}, compose.OAuth2AuthorizeExplicitFactory)

			config.TokenEndpointHandlers.Append(&idjag.IssueHandler{Config: config, Strategy: &jwt.DefaultStrategy{
				Config: config,
				Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{tc.key}}),
			}})

			metadata, err := provider.NewOAuth2AuthorizationServerMetadata(context.Background())
			require.NoError(t, err)

			require.NotNil(t, metadata.DraftIDJAGMetadata)
			assert.Equal(t, tc.expected, metadata.IDJAGSigningAlgValuesSupported)
		})
	}
}

func TestOAuth2MetadataAuthorizationServerIdentification(t *testing.T) {
	testCases := []struct {
		name     string
		disabled bool
		expected bool
	}{
		{name: "ShouldAdvertiseTheISSParameterWhenEnabled", expected: true},
		{name: "ShouldNotAdvertiseTheISSParameterWhenDisabled", disabled: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := newDiscoveryAllEnabledConfig()
			config.DisableAuthorizationServerIdentification = tc.disabled

			provider := compose.ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey())

			metadata, err := provider.NewOAuth2AuthorizationServerMetadata(context.Background())
			require.NoError(t, err)

			if tc.expected {
				require.NotNil(t, metadata.RFC9207AuthorizationServerIssuerIdentificationMetadata)
				assert.Equal(t, true, marshalMembers(t, metadata)[consts.DiscoveryAuthorizationResponseISSParameterSupported])
				assert.NotNil(t, metadata.DraftClientIDMetadataDocumentMetadata)
			} else {
				assert.Nil(t, metadata.RFC9207AuthorizationServerIssuerIdentificationMetadata)
				assert.NotContains(t, marshalMembers(t, metadata), consts.DiscoveryAuthorizationResponseISSParameterSupported)
				assert.Nil(t, metadata.DraftClientIDMetadataDocumentMetadata)
				assert.NotContains(t, marshalMembers(t, metadata), consts.DiscoveryClientIDMetadataDocumentSupported)
			}
		})
	}
}

func TestOAuth2MetadataIssuerErrors(t *testing.T) {
	testCases := []struct {
		name   string
		issuer string
		err    string
	}{
		{"ShouldErrorEmpty", "", "the authorization server metadata requires an issuer"},
		{"ShouldErrorHTTP", "http://auth.example.com", "the authorization server metadata requires an issuer using the 'https' scheme but the issuer 'http://auth.example.com' uses the 'http' scheme"},
		{"ShouldErrorQuery", "https://auth.example.com?tenant=a", "the authorization server metadata requires a valid issuer: the issuer 'https://auth.example.com?tenant=a' must not have a query or fragment component"},
		{"ShouldErrorFragment", "https://auth.example.com#a", "the authorization server metadata requires a valid issuer: the issuer 'https://auth.example.com#a' must not have a query or fragment component"},
		{"ShouldErrorRelative", "auth.example.com", "the authorization server metadata requires a valid issuer: the issuer 'auth.example.com' must be an absolute URL"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := newDiscoveryAllEnabledConfig()
			config.Issuer = tc.issuer
			config.JWTSecuredAuthorizeResponseModeStrategy = nil

			provider := compose.ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey())

			metadata, err := provider.NewOAuth2AuthorizationServerMetadata(context.Background())

			assert.Nil(t, metadata)
			assert.EqualError(t, err, tc.err)

			oidc, err := provider.NewOpenIDConnectProviderMetadata(context.Background())

			assert.Nil(t, oidc)
			assert.EqualError(t, err, tc.err)
		})
	}
}

func TestOAuth2MetadataJWTAuthWithoutAlgsErrors(t *testing.T) {
	config := newDiscoveryAllEnabledConfig()
	config.ClientAssertionSigningAlgValues = []string{consts.JSONWebTokenAlgNone}

	provider := compose.ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey())

	metadata, err := provider.NewOAuth2AuthorizationServerMetadata(context.Background())

	assert.Nil(t, metadata)
	assert.EqualError(t, err, "the authorization server metadata lists a JWT client authentication method in 'token_endpoint_auth_methods_supported' but no 'token_endpoint_auth_signing_alg_values_supported'")
}

func TestOAuth2MetadataRegistrationIntrospectorIgnored(t *testing.T) {
	config := &oauth2.Config{
		Issuer: "https://auth.example.com",
		EndpointURLs: oauth2.EndpointURLs{
			Authorization: "https://auth.example.com/authorize",
			Token:         "https://auth.example.com/token",
			Introspection: "https://auth.example.com/introspect",
		},
	}

	provider := compose.Compose(config, storage.NewMemoryStore(), &compose.CommonStrategy{CoreStrategy: compose.NewOAuth2HMACStrategy(config)}, compose.OAuth2AuthorizeExplicitFactory)

	config.TokenIntrospectionHandlers.Append(&rfc7591.ClientRegistrationTokenIntrospector{})

	metadata, err := provider.NewOAuth2AuthorizationServerMetadata(context.Background())
	require.NoError(t, err)

	assert.Empty(t, metadata.IntrospectionEndpoint)

	config.TokenIntrospectionHandlers.Append(compose.OAuth2TokenIntrospectionFactory(config, storage.NewMemoryStore(), compose.NewOAuth2HMACStrategy(config)).(oauth2.TokenIntrospector))

	metadata, err = provider.NewOAuth2AuthorizationServerMetadata(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "https://auth.example.com/introspect", metadata.IntrospectionEndpoint)
}

func TestOAuth2MetadataECOnlyKeys(t *testing.T) {
	config := &oauth2.Config{
		Issuer: "https://auth.example.com",
		EndpointURLs: oauth2.EndpointURLs{
			Authorization: "https://auth.example.com/authorize",
			Token:         "https://auth.example.com/token",
		},
	}

	config.JWTSecuredAuthorizeResponseModeStrategy = &jwt.DefaultStrategy{
		Config: config,
		Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: gen.MustES256Key(), KeyID: "es256", Algorithm: string(jose.ES256), Use: consts.JSONWebTokenUseSignature},
		}}),
	}

	provider := compose.Compose(config, storage.NewMemoryStore(), &compose.CommonStrategy{CoreStrategy: compose.NewOAuth2HMACStrategy(config)}, compose.OAuth2AuthorizeExplicitFactory)

	metadata, err := provider.NewOAuth2AuthorizationServerMetadata(context.Background())
	require.NoError(t, err)

	require.NotNil(t, metadata.OpenIDConnectJARMMetadata)
	assert.Equal(t, []string{"ES256", "HS256", "HS384", "HS512"}, metadata.AuthorizationSigningAlgValuesSupported)
	assert.NotContains(t, metadata.AuthorizationSigningAlgValuesSupported, "RS256")
}

func TestOAuth2MetadataRequiredMembers(t *testing.T) {
	testCases := []struct {
		name      string
		urls      oauth2.EndpointURLs
		factories []compose.Factory
		expected  string
	}{
		{
			name:      "ShouldRejectNoResponseTypes",
			urls:      oauth2.EndpointURLs{Token: "https://auth.example.com/token"},
			factories: []compose.Factory{compose.OAuth2ClientCredentialsGrantFactory},
			expected:  "the authorization server metadata requires 'response_types_supported' but no handler supports a response type",
		},
		{
			name:      "ShouldRejectAuthorizationCodeWithoutAuthorizationEndpoint",
			urls:      oauth2.EndpointURLs{Token: "https://auth.example.com/token"},
			factories: []compose.Factory{compose.OAuth2AuthorizeExplicitFactory},
			expected:  "the authorization server metadata requires an 'authorization_endpoint' as a supported grant type uses the authorization endpoint",
		},
		{
			name:      "ShouldRejectAuthorizationCodeWithoutTokenEndpoint",
			urls:      oauth2.EndpointURLs{Authorization: "https://auth.example.com/authorize"},
			factories: []compose.Factory{compose.OAuth2AuthorizeExplicitFactory},
			expected:  "the authorization server metadata requires a 'token_endpoint' as a grant type other than 'implicit' is supported",
		},
		{
			name:      "ShouldAllowImplicitOnlyWithoutTokenEndpoint",
			urls:      oauth2.EndpointURLs{Authorization: "https://auth.example.com/authorize"},
			factories: []compose.Factory{compose.OAuth2AuthorizeImplicitFactory},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &oauth2.Config{Issuer: "https://auth.example.com", EndpointURLs: tc.urls}

			provider := compose.Compose(config, storage.NewMemoryStore(), &compose.CommonStrategy{CoreStrategy: compose.NewOAuth2HMACStrategy(config)}, tc.factories...)

			metadata, err := provider.NewOAuth2AuthorizationServerMetadata(context.Background())

			if tc.expected == "" {
				require.NoError(t, err)
				assert.Empty(t, metadata.TokenEndpoint)
				assert.Equal(t, []string{consts.GrantTypeImplicit}, metadata.GrantTypesSupported)

				return
			}

			assert.Nil(t, metadata)
			assert.EqualError(t, err, tc.expected)
		})
	}
}

func TestOAuth2MetadataRevocationAuthSigningFallback(t *testing.T) {
	config := newDiscoveryAllEnabledConfig()
	config.RevocationEndpointAuthMethods = []string{consts.ClientAuthMethodPrivateKeyJWT}
	config.RevocationEndpointAuthSigningAlgValues = nil
	config.ClientAssertionSigningAlgValues = []string{consts.JSONWebTokenAlgNone, "ES256", "RS256"}

	provider := compose.ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey())

	metadata, err := provider.NewOAuth2AuthorizationServerMetadata(context.Background())
	require.NoError(t, err)

	assert.Equal(t, []string{"ES256", "RS256"}, metadata.RevocationEndpointAuthSigningAlgValuesSupported)

	config.RevocationEndpointAuthSigningAlgValues = []string{consts.JSONWebTokenAlgNone, "PS256"}

	metadata, err = provider.NewOAuth2AuthorizationServerMetadata(context.Background())
	require.NoError(t, err)

	assert.Equal(t, []string{"PS256"}, metadata.RevocationEndpointAuthSigningAlgValuesSupported)
}

func TestOAuth2MetadataRevocationAuthWithoutConfiguredMethods(t *testing.T) {
	config := newDiscoveryAllEnabledConfig()
	config.RevocationEndpointAuthMethods = nil
	config.RevocationEndpointAuthSigningAlgValues = nil
	config.IntrospectionEndpointAuthMethods = nil
	config.ClientAssertionSigningAlgValues = []string{consts.JSONWebTokenAlgNone, "ES256"}

	provider := compose.ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey())

	metadata, err := provider.NewOAuth2AuthorizationServerMetadata(context.Background())
	require.NoError(t, err)

	assert.Equal(t, []string{consts.ClientAuthMethodClientSecretBasic, consts.ClientAuthMethodClientSecretPost, consts.ClientAuthMethodClientSecretJWT, consts.ClientAuthMethodPrivateKeyJWT, consts.ClientAuthMethodNone, consts.ClientAuthMethodTLSClientAuth, consts.ClientAuthMethodSelfSignedTLSClientAuth}, metadata.RevocationEndpointAuthMethodsSupported)
	assert.Equal(t, []string{"ES256"}, metadata.RevocationEndpointAuthSigningAlgValuesSupported)
	assert.Nil(t, metadata.IntrospectionEndpointAuthMethodsSupported)
}

func TestOAuth2MetadataIntrospectionAuthSigningFallback(t *testing.T) {
	config := newDiscoveryAllEnabledConfig()
	config.IntrospectionEndpointAuthMethods = []string{consts.ClientAuthMethodClientSecretJWT}
	config.ClientAssertionSigningAlgValues = []string{consts.JSONWebTokenAlgNone, "HS256"}

	provider := compose.ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey())

	metadata, err := provider.NewOAuth2AuthorizationServerMetadata(context.Background())
	require.NoError(t, err)

	assert.Equal(t, []string{"HS256"}, metadata.IntrospectionEndpointAuthSigningAlgValuesSupported)

	config.IntrospectionEndpointAuthMethods = nil
	config.IntrospectionEndpointAuthSigningAlgValues = []string{consts.JSONWebTokenAlgNone, "ES256"}

	metadata, err = provider.NewOAuth2AuthorizationServerMetadata(context.Background())
	require.NoError(t, err)

	assert.Equal(t, []string{"ES256"}, metadata.IntrospectionEndpointAuthSigningAlgValuesSupported)
}

func TestOAuth2MetadataConfiguredEndpointAuthMethodsMustBeSupported(t *testing.T) {
	testCases := []struct {
		name  string
		setup func(config *oauth2.Config)
		err   string
	}{
		{
			name: "ShouldRejectAnMTLSTokenMethodWithoutMTLS",
			setup: func(config *oauth2.Config) {
				config.MTLSEnabled = false
				config.TokenEndpointAuthMethods = []string{consts.ClientAuthMethodTLSClientAuth, consts.ClientAuthMethodPrivateKeyJWT}
			},
			err: "the authorization server metadata lists the client authentication methods 'tls_client_auth' in 'token_endpoint_auth_methods_supported' but the client authentication strategy does not support them",
		},
		{
			name: "ShouldRejectAnUnknownRevocationMethod",
			setup: func(config *oauth2.Config) {
				config.RevocationEndpointAuthMethods = []string{consts.ClientAuthMethodClientSecretBasic, "private_key_jw"}
			},
			err: "the authorization server metadata lists the client authentication methods 'private_key_jw' in 'revocation_endpoint_auth_methods_supported' but the client authentication strategy does not support them",
		},
		{
			name: "ShouldRejectAnAccessTokenTypeForRevocation",
			setup: func(config *oauth2.Config) {
				config.RevocationEndpointAuthMethods = []string{consts.AuthSchemeBearer, consts.ClientAuthMethodClientSecretBasic}
			},
			err: "the authorization server metadata lists the client authentication methods 'Bearer' in 'revocation_endpoint_auth_methods_supported' but the client authentication strategy does not support them",
		},
		{
			name: "ShouldAcceptAccessTokenTypesForIntrospection",
			setup: func(config *oauth2.Config) {
				config.IntrospectionEndpointAuthMethods = []string{consts.AuthSchemeBearer, consts.AuthSchemeDPoP}
			},
		},
		{
			name: "ShouldIgnoreAnUnadvertisedEndpoint",
			setup: func(config *oauth2.Config) {
				config.EndpointURLs.Introspection = ""
				config.IntrospectionEndpointAuthMethods = []string{"private_key_jw"}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := newDiscoveryAllEnabledConfig()
			tc.setup(config)

			provider := compose.ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey())

			metadata, err := provider.NewOAuth2AuthorizationServerMetadata(context.Background())

			if tc.err == "" {
				require.NoError(t, err)

				return
			}

			assert.Nil(t, metadata)
			assert.EqualError(t, err, tc.err)
		})
	}
}

func TestOAuth2MetadataEndpointAuthOmittedWithoutEndpoint(t *testing.T) {
	config := newDiscoveryAllEnabledConfig()
	config.EndpointURLs.Revocation = ""
	config.EndpointURLs.Introspection = ""
	config.RevocationEndpointAuthMethods = []string{consts.ClientAuthMethodPrivateKeyJWT}
	config.RevocationEndpointAuthSigningAlgValues = []string{"PS256"}
	config.IntrospectionEndpointAuthMethods = []string{consts.ClientAuthMethodClientSecretJWT}
	config.IntrospectionEndpointAuthSigningAlgValues = []string{"HS256"}

	provider := compose.ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey())

	metadata, err := provider.NewOAuth2AuthorizationServerMetadata(context.Background())
	require.NoError(t, err)

	assert.Empty(t, metadata.RevocationEndpoint)
	assert.Nil(t, metadata.RevocationEndpointAuthMethodsSupported)
	assert.Nil(t, metadata.RevocationEndpointAuthSigningAlgValuesSupported)
	assert.Empty(t, metadata.IntrospectionEndpoint)
	assert.Nil(t, metadata.IntrospectionEndpointAuthMethodsSupported)
	assert.Nil(t, metadata.IntrospectionEndpointAuthSigningAlgValuesSupported)
}

func TestOAuth2MetadataEndpointAuthSigningEmptyErrors(t *testing.T) {
	testCases := []struct {
		name     string
		setup    func(config *oauth2.Config)
		expected string
	}{
		{
			name: "ShouldErrorRevocation",
			setup: func(config *oauth2.Config) {
				config.RevocationEndpointAuthMethods = []string{consts.ClientAuthMethodPrivateKeyJWT}
				config.RevocationEndpointAuthSigningAlgValues = []string{consts.JSONWebTokenAlgNone}
			},
			expected: "the authorization server metadata lists a JWT client authentication method in 'revocation_endpoint_auth_methods_supported' but no 'revocation_endpoint_auth_signing_alg_values_supported'",
		},
		{
			name: "ShouldErrorIntrospection",
			setup: func(config *oauth2.Config) {
				config.IntrospectionEndpointAuthMethods = []string{consts.ClientAuthMethodClientSecretJWT}
				config.IntrospectionEndpointAuthSigningAlgValues = []string{consts.JSONWebTokenAlgNone}
			},
			expected: "the authorization server metadata lists a JWT client authentication method in 'introspection_endpoint_auth_methods_supported' but no 'introspection_endpoint_auth_signing_alg_values_supported'",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := newDiscoveryAllEnabledConfig()
			tc.setup(config)

			provider := compose.ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey())

			metadata, err := provider.NewOAuth2AuthorizationServerMetadata(context.Background())

			assert.Nil(t, metadata)
			assert.EqualError(t, err, tc.expected)
		})
	}
}

func TestOAuth2MetadataRequestObjectSigningAlgNone(t *testing.T) {
	config := newDiscoveryAllEnabledConfig()
	config.RequestObjectSigningAlgValues = []string{"RS256", consts.JSONWebTokenAlgNone}

	provider := compose.ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey())

	metadata, err := provider.NewOAuth2AuthorizationServerMetadata(context.Background())
	require.NoError(t, err)

	assert.Equal(t, []string{"RS256"}, metadata.RequestObjectSigningAlgValuesSupported)

	config.RequireSignedRequestObject = false

	metadata, err = provider.NewOAuth2AuthorizationServerMetadata(context.Background())
	require.NoError(t, err)

	assert.Equal(t, []string{"RS256", consts.JSONWebTokenAlgNone}, metadata.RequestObjectSigningAlgValuesSupported)
}

const testDiscoveryACRValue = "urn:example:acr:mfa"

func TestOAuth2MetadataACRValuesSupported(t *testing.T) {
	testCases := []struct {
		name     string
		values   []string
		enabled  bool
		expected any
	}{
		{name: "ShouldAdvertiseTheConfiguredValuesWhenEnabled", values: []string{testDiscoveryACRValue}, enabled: true, expected: []any{testDiscoveryACRValue}},
		{name: "ShouldOmitTheMemberWhenNotEnabled", values: []string{testDiscoveryACRValue}},
		{name: "ShouldOmitTheMemberWithoutValues", enabled: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := newDiscoveryAllEnabledConfig()
			config.ACRValuesSupported = tc.values
			config.RFC9470StepUpAuthenticationEnabled = tc.enabled

			provider := compose.ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey())

			metadata, err := provider.NewOAuth2AuthorizationServerMetadata(context.Background())
			require.NoError(t, err)

			// RFC 9470 Section 7.
			members := marshalMembers(t, metadata)

			if tc.expected == nil {
				assert.NotContains(t, members, consts.DiscoveryACRValuesSupported)

				return
			}

			assert.Equal(t, tc.expected, members[consts.DiscoveryACRValuesSupported])
		})
	}
}

func TestOpenIDMetadataACRValuesSupportedWithoutRFC9470(t *testing.T) {
	config := newDiscoveryOpenIDConfig(gen.MustRSAKey())
	config.ACRValuesSupported = []string{testDiscoveryACRValue}

	provider := compose.ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey())

	metadata, err := provider.NewOpenIDConnectProviderMetadata(context.Background())
	require.NoError(t, err)

	assert.Equal(t, []any{testDiscoveryACRValue}, marshalMembers(t, metadata)[consts.DiscoveryACRValuesSupported])
}

func TestOpenIDMetadataComposeAllEnabled(t *testing.T) {
	config := newDiscoveryOpenIDConfig(gen.MustRSAKey())
	provider := compose.ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey())

	metadata, err := provider.NewOpenIDConnectProviderMetadata(context.Background())
	require.NoError(t, err)

	assertGolden(t, filepath.Join("testdata", "discovery", "openid_all_enabled.json"), metadata)
}

func TestOpenIDMetadataRSA15KeyManagement(t *testing.T) {
	members := []string{
		consts.DiscoveryIDTokenEncryptionAlgValuesSupported,
		consts.DiscoveryUserinfoEncryptionAlgValuesSupported,
		consts.DiscoveryIntrospectionEncryptionAlgValuesSupported,
		consts.DiscoveryAuthorizationEncryptionAlgValuesSupported,
	}

	metadata := func(t *testing.T, enabled bool) map[string]any {
		config := newDiscoveryOpenIDConfig(gen.MustRSAKey())
		config.EnableRSA15KeyManagement = enabled

		provider := compose.ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey())

		value, err := provider.NewOpenIDConnectProviderMetadata(context.Background())
		require.NoError(t, err)

		return marshalMembers(t, value)
	}

	t.Run("ShouldNotAdvertiseRSA15ByDefault", func(t *testing.T) {
		actual := metadata(t, false)

		for _, member := range members {
			require.Contains(t, actual, member)
			assert.NotContains(t, actual[member], string(jose.RSA1_5), member)
		}
	})

	t.Run("ShouldAdvertiseRSA15WhenEnabled", func(t *testing.T) {
		actual := metadata(t, true)

		for _, member := range members {
			assert.Contains(t, actual[member], string(jose.RSA1_5), member)
		}
	})
}

func TestOpenIDMetadataMutualTLSAliases(t *testing.T) {
	config := newDiscoveryOpenIDConfig(gen.MustRSAKey())
	advertised := config.EndpointURLs.MutualTLSAliases

	config.EndpointURLs.MutualTLSAliases.UserInfo = "https://mtls.auth.example.com/userinfo"
	config.EndpointURLs.MutualTLSAliases.EndSession = "https://mtls.auth.example.com/logout"
	config.EndpointURLs.MutualTLSAliases.BackChannelAuthentication = "https://mtls.auth.example.com/bc-authorize"

	provider := compose.ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey())

	metadata, err := provider.NewOpenIDConnectProviderMetadata(context.Background())
	require.NoError(t, err)

	expected := advertised
	expected.UserInfo = config.EndpointURLs.MutualTLSAliases.UserInfo
	expected.EndSession = config.EndpointURLs.MutualTLSAliases.EndSession

	assert.Equal(t, &expected, metadata.MutualTLSEndpointAliases)

	oauth, err := provider.NewOAuth2AuthorizationServerMetadata(context.Background())
	require.NoError(t, err)

	assert.Equal(t, &advertised, oauth.MutualTLSEndpointAliases)
}

func TestOpenIDMetadataNotRegistered(t *testing.T) {
	config := newDiscoveryOpenIDConfig(gen.MustRSAKey())

	provider := compose.Compose(config, storage.NewMemoryStore(), &compose.CommonStrategy{CoreStrategy: compose.NewOAuth2HMACStrategy(config)},
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2RefreshTokenGrantFactory,
	)

	metadata, err := provider.NewOpenIDConnectProviderMetadata(context.Background())

	assert.Nil(t, metadata)
	assert.ErrorIs(t, err, oauth2.ErrDiscoveryOpenIDConnectNotRegistered)
}

func TestOpenIDMetadataNoJWKSURIErrors(t *testing.T) {
	config := newDiscoveryOpenIDConfig(gen.MustRSAKey())
	config.EndpointURLs.JWKS = ""

	provider := compose.ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey())

	metadata, err := provider.NewOpenIDConnectProviderMetadata(context.Background())

	assert.Nil(t, metadata)
	assert.EqualError(t, err, "the openid provider metadata requires a 'jwks_uri'")
}

func TestOpenIDMetadataNoSigningAlgsErrors(t *testing.T) {
	config := newDiscoveryOpenIDConfig(gen.MustRSAKey())
	config.JWTStrategy = nil

	provider := composeDiscoveryOpenID(config, &jwt.DefaultStrategy{Config: config})

	metadata, err := provider.NewOpenIDConnectProviderMetadata(context.Background())

	assert.Nil(t, metadata)
	assert.EqualError(t, err, "the openid provider metadata requires 'id_token_signing_alg_values_supported' but the id token issuer has no signing keys")
}

func TestOpenIDMetadataRequiresRS256(t *testing.T) {
	config := newDiscoveryOpenIDConfig(gen.MustRSAKey())
	config.JWTStrategy = nil

	provider := composeDiscoveryOpenID(config, &jwt.DefaultStrategy{
		Config: config,
		Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: gen.MustES256Key(), KeyID: "es256", Algorithm: string(jose.ES256), Use: consts.JSONWebTokenUseSignature},
			{Key: gen.MustES521Key(), KeyID: "es512", Algorithm: string(jose.ES512), Use: consts.JSONWebTokenUseSignature},
		}}),
	})

	metadata, err := provider.NewOpenIDConnectProviderMetadata(context.Background())

	assert.Nil(t, metadata)
	assert.EqualError(t, err, "the openid provider metadata requires 'id_token_signing_alg_values_supported' to include 'RS256' but the id token issuer has no 'RS256' signing key")
}

// FAPI 2.0 Security Profile Section 5.4.1.
func TestOpenIDMetadataFAPI2SecurityProfile(t *testing.T) {
	config := newDiscoveryOpenIDConfig(gen.MustRSAKey())
	config.FAPI2SecurityProfile = true

	provider := composeDiscoveryOpenID(config, &jwt.DefaultStrategy{
		Config: config,
		Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: gen.MustRSAKey(), KeyID: "ps256", Algorithm: string(jose.PS256), Use: consts.JSONWebTokenUseSignature},
			{Key: gen.MustES256Key(), KeyID: "es256", Algorithm: string(jose.ES256), Use: consts.JSONWebTokenUseSignature},
		}}),
	})

	metadata, err := provider.NewOpenIDConnectProviderMetadata(context.Background())
	require.NoError(t, err)

	assert.Equal(t, []string{string(jose.ES256), string(jose.PS256)}, metadata.IDTokenSigningAlgValuesSupported)
	assert.Equal(t, []string{string(jose.ES256)}, metadata.UserinfoSigningAlgValuesSupported)
}

func TestOpenIDMetadataNoSubjectTypesErrors(t *testing.T) {
	config := newDiscoveryOpenIDConfig(gen.MustRSAKey())

	provider := compose.ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey()).(*oauth2.Fosite)
	provider.Config = &noSubjectTypesConfig{Config: config}

	metadata, err := provider.NewOpenIDConnectProviderMetadata(context.Background())

	assert.Nil(t, metadata)
	assert.EqualError(t, err, "the openid provider metadata requires 'subject_types_supported' but none are configured")
}

func TestOpenIDMetadataComposeWithoutJWTStrategy(t *testing.T) {
	config := newDiscoveryOpenIDConfig(gen.MustRSAKey())
	config.JWTStrategy = nil

	provider := compose.ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey())

	metadata, err := provider.NewOpenIDConnectProviderMetadata(context.Background())
	require.NoError(t, err)

	assert.Equal(t, []string{"HS256", "HS384", "HS512", "RS256"}, metadata.IDTokenSigningAlgValuesSupported)
	assert.Equal(t, []string{"HS256", "HS384", "HS512"}, metadata.UserinfoSigningAlgValuesSupported)
}

func TestOpenIDMetadataClaimsParameterRequiresEnforcement(t *testing.T) {
	config := newDiscoveryOpenIDConfig(gen.MustRSAKey())
	config.EnforceClaimsParameter = false

	provider := compose.ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey())

	metadata, err := provider.NewOpenIDConnectProviderMetadata(context.Background())
	require.NoError(t, err)

	assert.False(t, metadata.ClaimsParameterSupported)
	assert.NotContains(t, marshalMembers(t, metadata), consts.DiscoveryClaimsParameterSupported)
}

func TestOpenIDMetadataNoBackChannelStrategy(t *testing.T) {
	config := newDiscoveryOpenIDConfig(gen.MustRSAKey())
	config.BackChannelLogoutTokenStrategy = nil
	config.EndpointURLs.EndSession = ""

	provider := compose.ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey())

	metadata, err := provider.NewOpenIDConnectProviderMetadata(context.Background())
	require.NoError(t, err)

	members := marshalMembers(t, metadata)

	assert.Nil(t, metadata.OpenIDConnectBackChannelLogoutMetadata)
	assert.Nil(t, metadata.OpenIDConnectRPInitiatedLogoutMetadata)
	assert.NotContains(t, members, consts.DiscoveryBackChannelLogoutSupported)
	assert.NotContains(t, members, consts.DiscoveryBackChannelLogoutSessionSupported)
	assert.NotContains(t, members, consts.DiscoveryEndSessionEndpoint)
	assert.Contains(t, members, consts.DiscoveryPromptValuesSupported)
}

func TestDiscoveryMetadataHookDoesNotAlterConfiguration(t *testing.T) {
	testCases := []struct {
		name  string
		build func(provider oauth2.Provider) (metadata *oauth2.OAuth2AuthorizationServerMetadata, err error)
	}{
		{
			name: "ShouldKeepTheConfigurationForTheOAuth2Document",
			build: func(provider oauth2.Provider) (*oauth2.OAuth2AuthorizationServerMetadata, error) {
				return provider.NewOAuth2AuthorizationServerMetadata(context.Background())
			},
		},
		{
			name: "ShouldKeepTheConfigurationForTheOpenIDDocument",
			build: func(provider oauth2.Provider) (*oauth2.OAuth2AuthorizationServerMetadata, error) {
				metadata, err := provider.NewOpenIDConnectProviderMetadata(context.Background())
				if err != nil {
					return nil, err
				}

				return &metadata.OAuth2AuthorizationServerMetadata, nil
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			config := newDiscoveryOpenIDConfig(gen.MustRSAKey())
			config.RequireSignedRequestObject = false
			config.RFC9470StepUpAuthenticationEnabled = true
			config.IntrospectionEndpointAuthMethods = []string{consts.ClientAuthMethodClientSecretBasic, consts.ClientAuthMethodPrivateKeyJWT, "Bearer"}
			config.RequestObjectSigningAlgValues = []string{"RS256", "ES256", "PS256"}
			config.DPoPAllowedJWSAlgorithms = []string{"RS256", "ES256"}
			config.ACRValuesSupported = []string{"internal", testDiscoveryACRValue}
			config.UILocalesSupported = []string{"en-AU", "en-US"}
			config.DiscoveryMetadataHooks = []oauth2.DiscoveryMetadataHook{discoveryHookFunc(func(_ context.Context, metadata *oauth2.OpenIDConnectProviderMetadata) error {
				metadata.IntrospectionEndpointAuthMethodsSupported = slices.DeleteFunc(metadata.IntrospectionEndpointAuthMethodsSupported, func(method string) bool { return method == consts.ClientAuthMethodClientSecretBasic })
				metadata.RequestObjectSigningAlgValuesSupported = slices.DeleteFunc(metadata.RequestObjectSigningAlgValuesSupported, func(alg string) bool { return alg == "RS256" })
				metadata.DPoPSigningAlgValuesSupported = slices.DeleteFunc(metadata.DPoPSigningAlgValuesSupported, func(alg string) bool { return alg == "RS256" })
				metadata.ACRValuesSupported = slices.DeleteFunc(metadata.ACRValuesSupported, func(value string) bool { return value == "internal" })
				metadata.UILocalesSupported = slices.DeleteFunc(metadata.UILocalesSupported, func(locale string) bool { return locale == "en-AU" })

				return nil
			})}

			provider := compose.ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey())

			metadata, err := tc.build(provider)
			require.NoError(t, err)

			assert.Equal(t, []string{consts.ClientAuthMethodPrivateKeyJWT, "Bearer"}, metadata.IntrospectionEndpointAuthMethodsSupported)
			assert.Equal(t, []string{"ES256", "PS256"}, metadata.RequestObjectSigningAlgValuesSupported)
			assert.Equal(t, []string{"ES256"}, metadata.DPoPSigningAlgValuesSupported)
			assert.Equal(t, []string{testDiscoveryACRValue}, metadata.ACRValuesSupported)
			assert.Equal(t, []string{"en-US"}, metadata.UILocalesSupported)

			assert.Equal(t, []string{consts.ClientAuthMethodClientSecretBasic, consts.ClientAuthMethodPrivateKeyJWT, "Bearer"}, config.GetIntrospectionEndpointAuthMethods(ctx))
			assert.Equal(t, []string{"RS256", "ES256", "PS256"}, config.GetRequestObjectSigningAlgValues(ctx))
			assert.Equal(t, []string{"RS256", "ES256"}, config.GetDPoPAllowedJWSAlgorithms(ctx))
			assert.Equal(t, []string{"internal", testDiscoveryACRValue}, config.GetACRValuesSupported(ctx))
			assert.Equal(t, []string{"en-AU", "en-US"}, config.GetUILocalesSupported(ctx))
		})
	}
}

func TestDiscoveryMetadataDoesNotShareConfigurationValues(t *testing.T) {
	testCases := []struct {
		name  string
		build func(provider oauth2.Provider) (metadata any, err error)
	}{
		{
			name: "ShouldOwnEveryValueOfTheOAuth2Document",
			build: func(provider oauth2.Provider) (any, error) {
				return provider.NewOAuth2AuthorizationServerMetadata(context.Background())
			},
		},
		{
			name: "ShouldOwnEveryValueOfTheOpenIDDocument",
			build: func(provider oauth2.Provider) (any, error) {
				return provider.NewOpenIDConnectProviderMetadata(context.Background())
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			inner := newDiscoveryOpenIDConfig(gen.MustRSAKey())
			inner.RequireSignedRequestObject = false
			inner.RFC9470StepUpAuthenticationEnabled = true
			inner.ClaimTypesSupported = []string{"normal"}
			inner.ProtectedResources = []string{"https://api.example.com"}

			provider, ok := compose.ComposeAllEnabled(inner, storage.NewMemoryStore(), gen.MustRSAKey()).(*oauth2.Fosite)
			require.True(t, ok)

			config := &retainedValuesConfig{Config: inner, retained: map[string][]string{}, expected: map[string][]string{}}
			provider.Config = config

			metadata, err := tc.build(provider)
			require.NoError(t, err)

			require.NotZero(t, overwriteStringSlices(reflect.ValueOf(metadata)))
			require.NotEmpty(t, config.retained)

			for name, values := range config.retained {
				assert.Equal(t, config.expected[name], values, name)
			}
		})
	}
}

func newDiscoveryAllEnabledConfig() *oauth2.Config {
	config := &oauth2.Config{
		Issuer: "https://auth.example.com",
		EndpointURLs: oauth2.EndpointURLs{
			Registration:               "https://auth.example.com/register",
			Authorization:              "https://auth.example.com/authorize",
			Token:                      "https://auth.example.com/token",
			UserInfo:                   "https://auth.example.com/userinfo",
			JWKS:                       "https://auth.example.com/jwks.json",
			Revocation:                 "https://auth.example.com/revoke",
			Introspection:              "https://auth.example.com/introspect",
			PushedAuthorizationRequest: "https://auth.example.com/par",
			DeviceAuthorization:        "https://auth.example.com/device",
			EndSession:                 "https://auth.example.com/logout",
			MutualTLSAliases: oauth2.RFC8705MutualTLSEndpointAliases{
				Token:      "https://mtls.auth.example.com/token",
				Revocation: "https://mtls.auth.example.com/revoke",
			},
		},
		RFC7591ClientRegistrationGlobalSecret:  []byte("a-completely-different-secret-at-least-32b"),
		ClientIDMetadataDocumentResolver:       discoveryResolver{},
		AuthorizationDetailsTypeHandlers:       []oauth2.AuthorizationDetailsTypeHandler{internal.PaymentInitiationTypeHandler{}},
		ScopesSupported:                        []string{"profile", "email"},
		RefreshTokenScopes:                     []string{"offline_access"},
		ServiceDocumentation:                   "https://auth.example.com/docs",
		UILocalesSupported:                     []string{"en-AU", "en-US"},
		OPPolicyURI:                            "https://auth.example.com/policy",
		OPTOSURI:                               "https://auth.example.com/tos",
		RevocationEndpointAuthMethods:          []string{consts.ClientAuthMethodClientSecretBasic, consts.ClientAuthMethodPrivateKeyJWT},
		RevocationEndpointAuthSigningAlgValues: []string{"RS256"},
		IntrospectionEndpointAuthMethods:       []string{consts.ClientAuthMethodClientSecretBasic},
		RequirePushedAuthorizationRequests:     true,
		RequireSignedRequestObject:             true,
		DPoPEnabled:                            true,
		MTLSEnabled:                            true,
		RFC8693TokenTypes: map[string]oauth2.RFC8693TokenType{
			consts.TokenTypeRFC8693AccessToken: &rfc8693.DefaultTokenType{Name: consts.TokenTypeRFC8693AccessToken},
			consts.TokenTypeRFC8693IDJAG:       &rfc8693.DefaultTokenType{Name: consts.TokenTypeRFC8693IDJAG},
		},
	}

	config.ResponseModeParameterHandlers = oauth2.ResponseModeParameterHandlers{&oauth2.RFC9207ResponseModeParameterHandler{Config: config}}

	key := gen.MustRSAKey()

	config.JWTSecuredAuthorizeResponseModeStrategy = &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}
	config.IntrospectionJWTResponseStrategy = &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

	return config
}

func newDiscoveryOpenIDConfig(key any) *oauth2.Config {
	config := newDiscoveryAllEnabledConfig()

	config.JWTStrategy = &jwt.DefaultStrategy{
		Config: config,
		Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: gen.MustES256Key(), KeyID: "es256", Algorithm: string(jose.ES256), Use: consts.JSONWebTokenUseSignature},
		}}),
	}
	config.BackChannelLogoutTokenStrategy = &openid.DefaultStrategy{Strategy: &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}, Config: config}
	config.AllowedPromptValues = []string{consts.PromptTypeNone, consts.PromptTypeLogin, consts.PromptTypeConsent, consts.PromptTypeSelectAccount, "create"}
	config.ACRValuesSupported = []string{testDiscoveryACRValue}
	config.DisplayValuesSupported = []string{"page", "popup"}
	config.ClaimsLocalesSupported = []string{"en-AU"}
	config.ClaimsSupported = []string{"email", "name"}
	config.EnforceClaimsParameter = true

	return config
}

func composeDiscoveryOpenID(config *oauth2.Config, strategy jwt.Strategy) oauth2.Provider {
	return compose.Compose(config, storage.NewMemoryStore(),
		&compose.CommonStrategy{
			CoreStrategy:               compose.NewOAuth2HMACStrategy(config),
			OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(nil, strategy, config),
			Strategy:                   strategy,
		},
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OpenIDConnectExplicitFactory,
		compose.OpenIDConnectRefreshFactory,
	)
}

type noSubjectTypesConfig struct {
	*oauth2.Config
}

func (c *noSubjectTypesConfig) GetSubjectTypesSupported(_ context.Context) []string {
	return nil
}

func marshalMembers(t *testing.T, metadata any) map[string]any {
	t.Helper()

	data, err := json.Marshal(metadata)
	require.NoError(t, err)

	members := map[string]any{}

	require.NoError(t, json.Unmarshal(data, &members))

	return members
}

func assertGolden(t *testing.T, path string, metadata any) {
	t.Helper()

	actual, err := json.MarshalIndent(metadata, "", "  ")
	require.NoError(t, err)

	actual = append(actual, '\n')

	if *update {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, actual, 0o600))
	}

	expected, err := os.ReadFile(path)
	require.NoError(t, err)

	assert.JSONEq(t, string(expected), string(actual))
}

type discoveryHookFunc func(ctx context.Context, metadata *oauth2.OpenIDConnectProviderMetadata) (err error)

func (f discoveryHookFunc) HandleDiscoveryMetadata(ctx context.Context, metadata *oauth2.OpenIDConnectProviderMetadata) (err error) {
	return f(ctx, metadata)
}

type retainedValuesConfig struct {
	*oauth2.Config

	retained map[string][]string
	expected map[string][]string
}

func (c *retainedValuesConfig) retain(name string, values []string) []string {
	if retained, ok := c.retained[name]; ok {
		return retained
	}

	c.retained[name] = values
	c.expected[name] = slices.Clone(values)

	return values
}

func (c *retainedValuesConfig) GetClientAuthenticationStrategy(ctx context.Context) oauth2.ClientAuthenticationStrategy {
	return &retainedMethodsStrategy{DefaultClientAuthenticationStrategy: &oauth2.DefaultClientAuthenticationStrategy{Config: c}, config: c}
}

func (c *retainedValuesConfig) GetScopesSupported(ctx context.Context) []string {
	return c.retain("scopes", c.Config.GetScopesSupported(ctx))
}

func (c *retainedValuesConfig) GetRefreshTokenScopes(ctx context.Context) []string {
	return c.retain("refresh_token_scopes", c.Config.GetRefreshTokenScopes(ctx))
}

func (c *retainedValuesConfig) GetClaimsSupported(ctx context.Context) []string {
	return c.retain("claims", c.Config.GetClaimsSupported(ctx))
}

func (c *retainedValuesConfig) GetUILocalesSupported(ctx context.Context) []string {
	return c.retain("ui_locales", c.Config.GetUILocalesSupported(ctx))
}

func (c *retainedValuesConfig) GetClaimsLocalesSupported(ctx context.Context) []string {
	return c.retain("claims_locales", c.Config.GetClaimsLocalesSupported(ctx))
}

func (c *retainedValuesConfig) GetACRValuesSupported(ctx context.Context) []string {
	return c.retain("acr_values", c.Config.GetACRValuesSupported(ctx))
}

func (c *retainedValuesConfig) GetDisplayValuesSupported(ctx context.Context) []string {
	return c.retain("display_values", c.Config.GetDisplayValuesSupported(ctx))
}

func (c *retainedValuesConfig) GetClaimTypesSupported(ctx context.Context) []string {
	return c.retain("claim_types", c.Config.GetClaimTypesSupported(ctx))
}

func (c *retainedValuesConfig) GetSubjectTypesSupported(ctx context.Context) []string {
	return c.retain("subject_types", c.Config.GetSubjectTypesSupported(ctx))
}

func (c *retainedValuesConfig) GetAllowedPrompts(ctx context.Context) []string {
	return c.retain("prompts", c.Config.GetAllowedPrompts(ctx))
}

func (c *retainedValuesConfig) GetProtectedResources(ctx context.Context) []string {
	return c.retain("protected_resources", c.Config.GetProtectedResources(ctx))
}

func (c *retainedValuesConfig) GetTokenEndpointAuthMethods(ctx context.Context) []string {
	return c.retain("token_endpoint_auth_methods", c.Config.GetTokenEndpointAuthMethods(ctx))
}

func (c *retainedValuesConfig) GetRevocationEndpointAuthMethods(ctx context.Context) []string {
	return c.retain("revocation_endpoint_auth_methods", c.Config.GetRevocationEndpointAuthMethods(ctx))
}

func (c *retainedValuesConfig) GetIntrospectionEndpointAuthMethods(ctx context.Context) []string {
	return c.retain("introspection_endpoint_auth_methods", c.Config.GetIntrospectionEndpointAuthMethods(ctx))
}

func (c *retainedValuesConfig) GetRevocationEndpointAuthSigningAlgValues(ctx context.Context) []string {
	return c.retain("revocation_endpoint_auth_signing_alg_values", c.Config.GetRevocationEndpointAuthSigningAlgValues(ctx))
}

func (c *retainedValuesConfig) GetIntrospectionEndpointAuthSigningAlgValues(ctx context.Context) []string {
	return c.retain("introspection_endpoint_auth_signing_alg_values", c.Config.GetIntrospectionEndpointAuthSigningAlgValues(ctx))
}

func (c *retainedValuesConfig) GetClientAssertionSigningAlgValues(ctx context.Context) []string {
	return c.retain("client_assertion_signing_alg_values", c.Config.GetClientAssertionSigningAlgValues(ctx))
}

func (c *retainedValuesConfig) GetRequestObjectSigningAlgValues(ctx context.Context) []string {
	return c.retain("request_object_signing_alg_values", c.Config.GetRequestObjectSigningAlgValues(ctx))
}

func (c *retainedValuesConfig) GetRequestObjectEncryptionAlgValues(ctx context.Context) []string {
	return c.retain("request_object_encryption_alg_values", c.Config.GetRequestObjectEncryptionAlgValues(ctx))
}

func (c *retainedValuesConfig) GetRequestObjectEncryptionEncValues(ctx context.Context) []string {
	return c.retain("request_object_encryption_enc_values", c.Config.GetRequestObjectEncryptionEncValues(ctx))
}

func (c *retainedValuesConfig) GetDPoPAllowedJWSAlgorithms(ctx context.Context) []string {
	return c.retain("dpop_signing_alg_values", c.Config.GetDPoPAllowedJWSAlgorithms(ctx))
}

func (c *retainedValuesConfig) GetResponseEncryptionAlgValues(ctx context.Context, target oauth2.ResponseEncryptionTarget) []string {
	return c.retain("response_encryption_alg_values:"+string(target), c.Config.GetResponseEncryptionAlgValues(ctx, target))
}

func (c *retainedValuesConfig) GetResponseEncryptionEncValues(ctx context.Context, target oauth2.ResponseEncryptionTarget) []string {
	return c.retain("response_encryption_enc_values:"+string(target), c.Config.GetResponseEncryptionEncValues(ctx, target))
}

type retainedMethodsStrategy struct {
	*oauth2.DefaultClientAuthenticationStrategy

	config *retainedValuesConfig
}

func (s *retainedMethodsStrategy) AuthMethodsSupported(ctx context.Context) []string {
	return s.config.retain("client_authentication_strategy_methods", s.DefaultClientAuthenticationStrategy.AuthMethodsSupported(ctx))
}

func overwriteStringSlices(value reflect.Value) (n int) {
	switch value.Kind() {
	case reflect.Pointer:
		if !value.IsNil() {
			n += overwriteStringSlices(value.Elem())
		}
	case reflect.Struct:
		for i := range value.NumField() {
			n += overwriteStringSlices(value.Field(i))
		}
	case reflect.Slice:
		if value.Type().Elem().Kind() != reflect.String {
			return 0
		}

		for i := range value.Len() {
			value.Index(i).SetString("overwritten")
		}

		if value.Len() != 0 {
			n++
		}
	default:
	}

	return n
}

type discoveryResolver struct{}

func (discoveryResolver) ResolveClientIDMetadataDocumentClient(ctx context.Context, id string) (oauth2.Client, error) {
	return nil, oauth2.ErrInvalidClient
}

func TestDiscoveryCIBA(t *testing.T) {
	const (
		endpoint = "https://auth.example.com/bc-authorize"
		alias    = "https://mtls.auth.example.com/bc-authorize"
	)

	members := []string{
		consts.DiscoveryBackChannelAuthenticationEndpoint,
		consts.DiscoveryBackChannelTokenDeliveryModesSupported,
		consts.DiscoveryBackChannelAuthenticationRequestSigningAlgValuesSupported,
		consts.DiscoveryBackChannelUserCodeParameterSupported,
		consts.DiscoveryBackChannelEndpointLoginHintTokenTypesSupported,
	}

	testCases := []struct {
		name     string
		setup    func(config *oauth2.Config)
		composed bool
		expected func(t *testing.T, config *oauth2.Config, metadata *oauth2.OpenIDConnectProviderMetadata)
	}{
		{
			name:     "ShouldAdvertiseTheComposedHandlers",
			composed: true,
			expected: func(t *testing.T, config *oauth2.Config, metadata *oauth2.OpenIDConnectProviderMetadata) {
				members := marshalMembers(t, metadata)

				assert.Equal(t, endpoint, members[consts.DiscoveryBackChannelAuthenticationEndpoint])
				assert.Equal(t, []any{consts.CIBAModePoll, consts.CIBAModePing, consts.CIBAModePush}, members[consts.DiscoveryBackChannelTokenDeliveryModesSupported])
				assert.NotEmpty(t, config.GetCIBARequestSigningAlgValues(context.Background()))
				assert.Equal(t, config.GetCIBARequestSigningAlgValues(context.Background()), metadata.BackChannelAuthenticationRequestSigningAlgValuesSupported)
				assert.NotContains(t, members, consts.DiscoveryBackChannelUserCodeParameterSupported)
				assert.NotContains(t, members, consts.DiscoveryBackChannelEndpointLoginHintTokenTypesSupported)
				assert.Contains(t, metadata.GrantTypesSupported, consts.GrantTypeOpenIDCIBA)
				assert.Equal(t, alias, metadata.MutualTLSEndpointAliases.BackChannelAuthentication)
			},
		},
		{
			name:     "ShouldAdvertiseTheUserCodeParameter",
			composed: true,
			setup: func(config *oauth2.Config) {
				config.CIBAUserCodeSupported = true
			},
			expected: func(t *testing.T, _ *oauth2.Config, metadata *oauth2.OpenIDConnectProviderMetadata) {
				assert.Equal(t, true, marshalMembers(t, metadata)[consts.DiscoveryBackChannelUserCodeParameterSupported])
			},
		},
		{
			name:     "ShouldOmitTheSigningAlgorithmsWhenNoneAreSupported",
			composed: true,
			setup: func(config *oauth2.Config) {
				config.RequestObjectSigningAlgValues = []string{"HS256"}
			},
			expected: func(t *testing.T, _ *oauth2.Config, metadata *oauth2.OpenIDConnectProviderMetadata) {
				members := marshalMembers(t, metadata)

				assert.Equal(t, endpoint, members[consts.DiscoveryBackChannelAuthenticationEndpoint])
				assert.NotContains(t, members, consts.DiscoveryBackChannelAuthenticationRequestSigningAlgValuesSupported)
			},
		},
		{
			name:     "ShouldOmitTheGrantTypeForPushOnly",
			composed: true,
			setup: func(config *oauth2.Config) {
				config.CIBATokenDeliveryModes = []string{consts.CIBAModePush}
			},
			expected: func(t *testing.T, _ *oauth2.Config, metadata *oauth2.OpenIDConnectProviderMetadata) {
				assert.Equal(t, []any{consts.CIBAModePush}, marshalMembers(t, metadata)[consts.DiscoveryBackChannelTokenDeliveryModesSupported])
				assert.NotContains(t, metadata.GrantTypesSupported, consts.GrantTypeOpenIDCIBA)
			},
		},
		{
			name: "ShouldOmitEveryMemberWithoutTheHandlers",
			expected: func(t *testing.T, _ *oauth2.Config, metadata *oauth2.OpenIDConnectProviderMetadata) {
				for _, member := range members {
					assert.NotContains(t, marshalMembers(t, metadata), member)
				}

				assert.NotContains(t, metadata.GrantTypesSupported, consts.GrantTypeOpenIDCIBA)
				assert.Empty(t, metadata.MutualTLSEndpointAliases.BackChannelAuthentication)
			},
		},
		{
			name:     "ShouldOmitEveryMemberWithoutTheEndpointURL",
			composed: true,
			setup: func(config *oauth2.Config) {
				config.EndpointURLs.BackChannelAuthentication = ""
			},
			expected: func(t *testing.T, _ *oauth2.Config, metadata *oauth2.OpenIDConnectProviderMetadata) {
				for _, member := range members {
					assert.NotContains(t, marshalMembers(t, metadata), member)
				}

				assert.Empty(t, metadata.MutualTLSEndpointAliases.BackChannelAuthentication)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := newDiscoveryOpenIDConfig(gen.MustRSAKey())
			config.EndpointURLs.BackChannelAuthentication = endpoint
			config.EndpointURLs.MutualTLSAliases.BackChannelAuthentication = alias

			if tc.setup != nil {
				tc.setup(config)
			}

			factories := []compose.Factory{
				compose.OAuth2AuthorizeExplicitFactory,
				compose.OAuth2RefreshTokenGrantFactory,
				compose.OpenIDConnectExplicitFactory,
				compose.OpenIDConnectRefreshFactory,
			}

			if tc.composed {
				factories = append(factories,
					compose.CIBADecisionFactory,
					compose.CIBATokenFactory,
					compose.OpenIDConnectCIBAFactory,
					compose.CIBAEndpointFactory,
				)
			}

			strategy := &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())}

			provider := compose.Compose(config, storage.NewMemoryStore(),
				&compose.CommonStrategy{
					CoreStrategy:               compose.NewOAuth2HMACStrategy(config),
					OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(nil, strategy, config),
					Strategy:                   strategy,
				},
				factories...,
			)

			metadata, err := provider.NewOpenIDConnectProviderMetadata(context.Background())
			require.NoError(t, err)

			tc.expected(t, config, metadata)
		})
	}
}

func TestDiscoveryLoginHintTokenTypes(t *testing.T) {
	const (
		backChannelEndpoint = "https://auth.example.com/backchannel"
		typeJWT             = "urn:example:login-hint-token:jwt"
		typeOpaque          = "urn:example:login-hint-token:opaque"
	)

	testCases := []struct {
		name     string
		types    []string
		composed bool
		expected any
	}{
		{name: "ShouldAdvertiseTheTypes", types: []string{typeJWT, typeOpaque}, composed: true, expected: []any{typeJWT, typeOpaque}},
		{name: "ShouldOmitAnEmptyList", composed: true},
		{name: "ShouldOmitTheTypesWithoutTheHandlers", types: []string{typeJWT}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := newDiscoveryOpenIDConfig(gen.MustRSAKey())
			config.EndpointURLs.BackChannelAuthentication = backChannelEndpoint
			config.CIBALoginHintTokenTypes = tc.types

			factories := []compose.Factory{compose.OAuth2AuthorizeExplicitFactory, compose.OpenIDConnectExplicitFactory}

			if tc.composed {
				factories = append(factories, compose.CIBAFactories()...)
			}

			strategy := &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())}

			provider := compose.Compose(config, storage.NewMemoryStore(),
				&compose.CommonStrategy{
					CoreStrategy:               compose.NewOAuth2HMACStrategy(config),
					OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(nil, strategy, config),
					Strategy:                   strategy,
				},
				factories...,
			)

			metadata, err := provider.NewOpenIDConnectProviderMetadata(context.Background())
			require.NoError(t, err)

			members := marshalMembers(t, metadata)

			if tc.expected == nil {
				assert.NotContains(t, members, consts.DiscoveryBackChannelEndpointLoginHintTokenTypesSupported)

				return
			}

			assert.Equal(t, tc.expected, members[consts.DiscoveryBackChannelEndpointLoginHintTokenTypesSupported])

			config.CIBALoginHintTokenTypes[0] = "mutated"

			assert.NotContains(t, metadata.BackChannelEndpointLoginHintTokenTypesSupported, "mutated")
		})
	}
}

// cibaLessStore hides the ciba.Storage methods of the MemoryStore: a field at a shallower depth than a promoted method
// removes that method from the method set.
type cibaLessStore struct {
	*storage.MemoryStore

	CreateCIBASession, GetCIBASession, GetCIBASessionByRequestID, UpdateCIBASession, DecideCIBASession, InvalidateCIBASession struct{}
}

func TestComposeAllEnabledExcludesCIBA(t *testing.T) {
	store := &cibaLessStore{MemoryStore: storage.NewMemoryStore()}

	_, ok := any(store).(ciba.Storage)
	require.False(t, ok)

	config := newDiscoveryOpenIDConfig(gen.MustRSAKey())
	config.EndpointURLs.BackChannelAuthentication = "https://auth.example.com/bc-authorize"

	var provider oauth2.Provider

	require.NotPanics(t, func() {
		provider = compose.ComposeAllEnabled(config, store, gen.MustRSAKey())
	})

	metadata, err := provider.NewOpenIDConnectProviderMetadata(context.Background())
	require.NoError(t, err)

	members := marshalMembers(t, metadata)

	assert.NotContains(t, members, consts.DiscoveryBackChannelAuthenticationEndpoint)
	assert.NotContains(t, members, consts.DiscoveryBackChannelTokenDeliveryModesSupported)
	assert.NotContains(t, members, consts.DiscoveryBackChannelAuthenticationRequestSigningAlgValuesSupported)
	assert.NotContains(t, members, consts.DiscoveryBackChannelUserCodeParameterSupported)
	assert.NotContains(t, metadata.GrantTypesSupported, consts.GrantTypeOpenIDCIBA)
}
