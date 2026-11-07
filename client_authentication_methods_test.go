// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

const authMethodsTestSecret = "0123456789abcdef0123456789abcdef"

func TestIntrospectionEndpointAuthMethodsEnforced(t *testing.T) {
	config := &Config{IntrospectionEndpointAuthMethods: []string{consts.ClientAuthMethodPrivateKeyJWT}}

	err := authenticateWithMethodsConfig(t, config, &IntrospectionEndpointClientAuthStrategy{})
	require.Error(t, err)

	assert.True(t, errors.Is(err, ErrInvalidClient))
	assert.Contains(t, ErrorToRFC6749Error(err).HintField, "introspection")

	assert.NoError(t, authenticateWithMethodsConfig(t, config, &TokenEndpointClientAuthStrategy{}))
}

func TestRevocationEndpointAuthMethodsEnforced(t *testing.T) {
	config := &Config{RevocationEndpointAuthMethods: []string{consts.ClientAuthMethodPrivateKeyJWT}}

	err := authenticateWithMethodsConfig(t, config, &RevocationEndpointClientAuthStrategy{})
	require.Error(t, err)

	assert.True(t, errors.Is(err, ErrInvalidClient))
	assert.Contains(t, ErrorToRFC6749Error(err).HintField, "revocation")

	assert.NoError(t, authenticateWithMethodsConfig(t, config, &TokenEndpointClientAuthStrategy{}))
}

func TestTokenEndpointAuthMethodsNarrowed(t *testing.T) {
	config := &Config{TokenEndpointAuthMethods: []string{consts.ClientAuthMethodClientSecretPost}}

	err := authenticateWithMethodsConfig(t, config, &TokenEndpointClientAuthStrategy{})
	require.Error(t, err)

	assert.True(t, errors.Is(err, ErrInvalidClient))
	assert.Contains(t, ErrorToRFC6749Error(err).HintField, "token")

	assert.NoError(t, authenticateWithMethodsConfig(t, config, &IntrospectionEndpointClientAuthStrategy{}))

	config.TokenEndpointAuthMethods = []string{consts.ClientAuthMethodClientSecretBasic}

	assert.NoError(t, authenticateWithMethodsConfig(t, config, &TokenEndpointClientAuthStrategy{}))
	assert.Equal(t, []string{consts.ClientAuthMethodClientSecretBasic}, SupportedTokenEndpointAuthMethods(context.Background(), config))
}

func TestSupportedEndpointAuthMethods(t *testing.T) {
	base := []string{consts.ClientAuthMethodClientSecretBasic, consts.ClientAuthMethodClientSecretPost, consts.ClientAuthMethodClientSecretJWT, consts.ClientAuthMethodPrivateKeyJWT, consts.ClientAuthMethodNone}

	config := &Config{
		TokenEndpointAuthMethods:         []string{consts.ClientAuthMethodClientSecretBasic},
		RevocationEndpointAuthMethods:    []string{consts.ClientAuthMethodPrivateKeyJWT},
		IntrospectionEndpointAuthMethods: []string{consts.ClientAuthMethodClientSecretPost},
	}

	testCases := []struct {
		name     string
		config   *Config
		endpoint ClientAuthEndpoint
		expected []string
	}{
		{"ShouldReturnTheConfiguredTokenMethods", config, ClientAuthEndpointToken, []string{consts.ClientAuthMethodClientSecretBasic}},
		{"ShouldReturnTheConfiguredRevocationMethods", config, ClientAuthEndpointRevocation, []string{consts.ClientAuthMethodPrivateKeyJWT}},
		{"ShouldReturnTheConfiguredIntrospectionMethods", config, ClientAuthEndpointIntrospection, []string{consts.ClientAuthMethodClientSecretPost}},
		{"ShouldFallBackToTheStrategyForRevocation", &Config{}, ClientAuthEndpointRevocation, base},
		{"ShouldFallBackToTheStrategyForIntrospection", &Config{}, ClientAuthEndpointIntrospection, base},
		{"ShouldFallBackToTheStrategyForAnUnknownEndpoint", config, ClientAuthEndpoint("userinfo"), base},
		{"ShouldDropAMethodTheStrategyDoesNotSupport", &Config{TokenEndpointAuthMethods: []string{consts.ClientAuthMethodTLSClientAuth, consts.ClientAuthMethodPrivateKeyJWT, "private_key_jw"}}, ClientAuthEndpointToken, []string{consts.ClientAuthMethodPrivateKeyJWT}},
		{"ShouldKeepAnMTLSMethodWhenMTLSIsEnabled", &Config{MTLSEnabled: true, TokenEndpointAuthMethods: []string{consts.ClientAuthMethodTLSClientAuth}}, ClientAuthEndpointToken, []string{consts.ClientAuthMethodTLSClientAuth}},
		{"ShouldKeepAccessTokenTypesForIntrospection", &Config{IntrospectionEndpointAuthMethods: []string{consts.AuthSchemeBearer, consts.AuthSchemeDPoP, consts.ClientAuthMethodPrivateKeyJWT}}, ClientAuthEndpointIntrospection, []string{consts.AuthSchemeBearer, consts.AuthSchemeDPoP, consts.ClientAuthMethodPrivateKeyJWT}},
		{"ShouldDropAccessTokenTypesForRevocation", &Config{RevocationEndpointAuthMethods: []string{consts.AuthSchemeBearer, consts.ClientAuthMethodPrivateKeyJWT}}, ClientAuthEndpointRevocation, []string{consts.ClientAuthMethodPrivateKeyJWT}},
		{"ShouldReturnEmptyWhenNoConfiguredMethodIsSupported", &Config{TokenEndpointAuthMethods: []string{consts.ClientAuthMethodTLSClientAuth}}, ClientAuthEndpointToken, []string{}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, SupportedEndpointAuthMethods(context.Background(), tc.config, tc.endpoint))
		})
	}
}

func TestIsAccessTokenTypeAuthMethod(t *testing.T) {
	for _, method := range []string{consts.AuthSchemeBearer, consts.AuthSchemeDPoP} {
		assert.True(t, IsAccessTokenTypeAuthMethod(method), method)
	}

	for _, method := range []string{consts.ClientAuthMethodClientSecretBasic, consts.ClientAuthMethodPrivateKeyJWT, consts.ClientAuthMethodNone, consts.ClientAuthMethodTLSClientAuth, "bearer", ""} {
		assert.False(t, IsAccessTokenTypeAuthMethod(method), method)
	}
}

func TestSupportedEndpointAuthSigningAlgValues(t *testing.T) {
	config := &Config{
		ClientAssertionSigningAlgValues:           []string{"RS256", "ES256"},
		RevocationEndpointAuthSigningAlgValues:    []string{"PS256"},
		IntrospectionEndpointAuthSigningAlgValues: []string{"EdDSA"},
	}

	testCases := []struct {
		name     string
		config   *Config
		endpoint ClientAuthEndpoint
		expected []string
	}{
		{"ShouldUseTheClientAssertionAlgorithmsForToken", config, ClientAuthEndpointToken, []string{"RS256", "ES256"}},
		{"ShouldReturnTheConfiguredRevocationAlgorithms", config, ClientAuthEndpointRevocation, []string{"PS256"}},
		{"ShouldReturnTheConfiguredIntrospectionAlgorithms", config, ClientAuthEndpointIntrospection, []string{"EdDSA"}},
		{"ShouldFallBackForRevocation", &Config{ClientAssertionSigningAlgValues: []string{"RS256"}}, ClientAuthEndpointRevocation, []string{"RS256"}},
		{"ShouldFallBackForIntrospection", &Config{ClientAssertionSigningAlgValues: []string{"RS256"}}, ClientAuthEndpointIntrospection, []string{"RS256"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, SupportedEndpointAuthSigningAlgValues(context.Background(), tc.config, tc.endpoint))
		})
	}
}

func TestAuthMethodsSupportedMTLS(t *testing.T) {
	base := []string{consts.ClientAuthMethodClientSecretBasic, consts.ClientAuthMethodClientSecretPost, consts.ClientAuthMethodClientSecretJWT, consts.ClientAuthMethodPrivateKeyJWT, consts.ClientAuthMethodNone}

	off := &DefaultClientAuthenticationStrategy{Config: &Config{}}
	assert.Equal(t, base, off.AuthMethodsSupported(context.Background()))

	on := &DefaultClientAuthenticationStrategy{Config: &Config{MTLSEnabled: true}}
	assert.Equal(t, append(append([]string{}, base...), consts.ClientAuthMethodTLSClientAuth, consts.ClientAuthMethodSelfSignedTLSClientAuth), on.AuthMethodsSupported(context.Background()))

	config := &Config{}
	assert.Equal(t, base, SupportedTokenEndpointAuthMethods(context.Background(), config))
}

func TestUnconfiguredEndpointListsUnchanged(t *testing.T) {
	config := &Config{}

	assert.Nil(t, config.GetTokenEndpointAuthMethods(context.Background()))
	assert.Nil(t, config.GetRevocationEndpointAuthMethods(context.Background()))
	assert.Nil(t, config.GetIntrospectionEndpointAuthMethods(context.Background()))
	assert.Nil(t, config.GetRevocationEndpointAuthSigningAlgValues(context.Background()))
	assert.Nil(t, config.GetIntrospectionEndpointAuthSigningAlgValues(context.Background()))

	for _, s := range []EndpointClientAuthStrategy{&TokenEndpointClientAuthStrategy{}, &RevocationEndpointClientAuthStrategy{}, &IntrospectionEndpointClientAuthStrategy{}} {
		assert.NoError(t, authenticateWithMethodsConfig(t, config, s))
	}
}

func TestEndpointAuthSigningAlgValuesReplaceAllowList(t *testing.T) {
	const audience = "https://as.example.com"

	key := gen.MustRSAKey()

	set := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{KeyID: "kid-foo", Use: "sig", Algorithm: "RS256", Key: &key.PublicKey}}}

	claims := jwt.MapClaims{
		consts.ClaimSubject:        "test",
		consts.ClaimIssuer:         "test",
		consts.ClaimJWTID:          "12345",
		consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
		consts.ClaimAudience:       []string{audience},
	}

	form := url.Values{
		consts.FormParameterClientAssertion:     []string{mustGenerateClientAssertion(t, claims, jose.RS256, jwt.JSONWebTokenTypeClientAuthentication, "kid-foo", key)},
		consts.FormParameterClientAssertionType: []string{consts.ClientAssertionTypeJWTBearer},
	}

	testCases := []struct {
		name     string
		config   *Config
		strategy EndpointClientAuthStrategy
		err      bool
	}{
		{"ShouldRejectRevocationAssertionOutsideList", &Config{RevocationEndpointAuthSigningAlgValues: []string{"ES256"}}, &RevocationEndpointClientAuthStrategy{}, true},
		{"ShouldAcceptRevocationAssertionInsideList", &Config{RevocationEndpointAuthSigningAlgValues: []string{"RS256"}}, &RevocationEndpointClientAuthStrategy{}, false},
		{"ShouldRejectIntrospectionAssertionOutsideList", &Config{IntrospectionEndpointAuthSigningAlgValues: []string{"ES256"}}, &IntrospectionEndpointClientAuthStrategy{}, true},
		{"ShouldNotApplyRevocationListAtToken", &Config{RevocationEndpointAuthSigningAlgValues: []string{"ES256"}}, &TokenEndpointClientAuthStrategy{}, false},
		{"ShouldReplaceGlobalAllowList", &Config{ClientAssertionSigningAlgValues: []string{"ES256"}, RevocationEndpointAuthSigningAlgValues: []string{"RS256"}}, &RevocationEndpointClientAuthStrategy{}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.config.JWKSFetcherStrategy = NewDefaultJWKSFetcherStrategy()
			tc.config.AllowedJWTAssertionAudiences = []string{audience}
			tc.config.JWTStrategy = &jwt.DefaultStrategy{Config: tc.config, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

			store := storage.NewMemoryStore()
			store.Clients["test"] = &DefaultJARClient{
				DefaultClient:           &DefaultClient{ID: "test"},
				JSONWebKeys:             set,
				TokenEndpointAuthMethod: consts.ClientAuthMethodPrivateKeyJWT,
			}

			provider := &Fosite{Store: store, Config: tc.config}

			_, _, err := provider.AuthenticateClientWithAuthHandler(context.Background(), &http.Request{Header: http.Header{}}, form, tc.strategy)

			if tc.err {
				require.Error(t, err)

				return
			}

			require.NoError(t, ErrorToDebugRFC6749Error(err))
		})
	}
}

func TestIntrospectionBearerCredentialHonoursAuthMethods(t *testing.T) {
	testCases := []struct {
		name    string
		methods []string
		scheme  string
		err     bool
	}{
		{"ShouldRejectBearerWhenOnlyPrivateKeyJWTListed", []string{consts.ClientAuthMethodPrivateKeyJWT}, "Bearer", true},
		{"ShouldAcceptBearerWhenBearerListed", []string{"Bearer"}, "Bearer", false},
		{"ShouldRejectDPoPWhenOnlyBearerListed", []string{"Bearer"}, "DPoP", true},
		{"ShouldAcceptBearerWithNoList", nil, "Bearer", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{
				IntrospectionEndpointAuthMethods: tc.methods,
				TokenIntrospectionHandlers:       TokenIntrospectionHandlers{&bearerIntrospector{}},
			}

			provider := &Fosite{Store: storage.NewMemoryStore(), Config: config}

			r := httptest.NewRequest(http.MethodPost, "https://as.example.com/introspect", strings.NewReader(url.Values{consts.FormParameterToken: {"target"}}.Encode()))
			r.Header.Set(consts.HeaderContentType, "application/x-www-form-urlencoded")
			r.Header.Set(consts.HeaderAuthorization, tc.scheme+" caller-token")

			_, err := provider.NewIntrospectionRequest(context.Background(), r, &DefaultSession{})

			if tc.err {
				require.Error(t, err)
				assert.True(t, errors.Is(err, ErrInvalidClient))
				assert.Contains(t, ErrorToRFC6749Error(err).HintField, "introspection")

				return
			}

			assert.False(t, errors.Is(err, ErrInvalidClient))
		})
	}
}

type customEndpointClientAuthStrategy struct {
	*IntrospectionEndpointClientAuthStrategy
}

func (s *customEndpointClientAuthStrategy) Name() string { return "introspection" }

func TestCustomEndpointStrategyAuthMethodsEnforced(t *testing.T) {
	config := &Config{IntrospectionEndpointAuthMethods: []string{consts.ClientAuthMethodPrivateKeyJWT}}

	err := authenticateWithMethodsConfig(t, config, &customEndpointClientAuthStrategy{&IntrospectionEndpointClientAuthStrategy{}})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidClient))
}

type bearerIntrospector struct{}

func (i *bearerIntrospector) IntrospectToken(_ context.Context, _ string, _ TokenUse, request AccessRequester, _ []string) (TokenUse, error) {
	request.SetSession(&DefaultSession{Subject: "peter"})

	return AccessToken, nil
}

func authenticateWithMethodsConfig(t *testing.T, config *Config, strategy EndpointClientAuthStrategy) error {
	t.Helper()

	store := storage.NewMemoryStore()
	store.Clients["test"] = &DefaultClient{ID: "test", ClientSecret: NewPlainTextClientSecret(authMethodsTestSecret)}

	provider := &Fosite{Store: store, Config: config}

	r := &http.Request{Header: clientBasicAuthHeader("test", authMethodsTestSecret)}

	_, _, err := provider.AuthenticateClientWithAuthHandler(context.Background(), r, url.Values{}, strategy)

	return err
}
