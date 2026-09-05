// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/internal/gen"
)

func TestValidateBearerAuthorizationAudienceFallbackChain(t *testing.T) {
	ctx := context.Background()
	config := &Config{}

	testCases := []struct {
		name     string
		auth     BearerAuthorization
		granted  []string
		expected string
	}{
		{
			name:    "ShouldUseConfiguredListWhenPresent",
			auth:    BearerAuthorization{Audiences: []string{"urn:example:aud"}, Endpoint: "https://as.example.com/register"},
			granted: []string{"urn:example:aud"},
		},
		{
			name:     "ShouldIgnoreEndpointWhenListConfigured",
			auth:     BearerAuthorization{Audiences: []string{"urn:example:aud"}, Endpoint: "https://as.example.com/register"},
			granted:  []string{"https://as.example.com/register"},
			expected: "The access token provided is expired, revoked, malformed, or invalid for other reasons. The credential used to authenticate the request does not have an audience which is permitted at this endpoint. The credential was expected to have an audience matching one of the values 'urn:example:aud' but the audience had the values 'https://as.example.com/register'.",
		},
		{
			name:    "ShouldFallBackToEndpointWhenListEmpty",
			auth:    BearerAuthorization{Endpoint: "https://as.example.com/register"},
			granted: []string{"https://as.example.com/register"},
		},
		{
			name:     "ShouldNotUseRequestURLWhenEndpointConfigured",
			auth:     BearerAuthorization{Endpoint: "https://as.example.com/register"},
			granted:  []string{"https://as.example.com/introspect"},
			expected: "The access token provided is expired, revoked, malformed, or invalid for other reasons. The credential used to authenticate the request does not have an audience which is permitted at this endpoint. The credential was expected to have an audience matching one of the values 'https://as.example.com/register' but the audience had the values 'https://as.example.com/introspect'.",
		},
		{
			name:    "ShouldFallBackToRequestURLWhenNeitherConfigured",
			auth:    BearerAuthorization{},
			granted: []string{"https://as.example.com/introspect"},
		},
		{
			name:     "ShouldRejectTokenWithNoAudience",
			auth:     BearerAuthorization{},
			granted:  nil,
			expected: "The access token provided is expired, revoked, malformed, or invalid for other reasons. The credential used to authenticate the request does not have an audience which is permitted at this endpoint. The credential was expected to have an audience matching one of the values 'https://as.example.com/introspect' but it does not have an audience.",
		},
		{
			name:    "ShouldMatchAnyOfTheConfiguredList",
			auth:    BearerAuthorization{Audiences: []string{"urn:a", "urn:b"}},
			granted: []string{"urn:b"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateBearerAuthorization(ctx, config, newBearerRequest(), newBearerRequester(nil, tc.granted), "token", tc.auth)

			if tc.expected != "" {
				require.Error(t, err)
				assert.EqualError(t, ErrorToDebugRFC6749Error(err), tc.expected)

				return
			}

			assert.NoError(t, err)
		})
	}
}

func TestValidateBearerAuthorizationScope(t *testing.T) {
	ctx := context.Background()
	config := &Config{}
	auth := BearerAuthorization{Audiences: []string{"urn:aud"}, Scopes: []string{"urn:a", "urn:b"}}

	t.Run("ShouldPermitAnyOneOfTheRequiredScopes", func(t *testing.T) {
		err := ValidateBearerAuthorization(ctx, config, newBearerRequest(), newBearerRequester([]string{"urn:b"}, []string{"urn:aud"}), "token", auth)

		assert.NoError(t, err)
	})

	t.Run("ShouldRejectWhenNoneHeld", func(t *testing.T) {
		err := ValidateBearerAuthorization(ctx, config, newBearerRequest(), newBearerRequester([]string{"read"}, []string{"urn:aud"}), "token", auth)

		require.Error(t, err)
		assert.EqualError(t, ErrorToDebugRFC6749Error(err), "The request requires higher privileges than provided by the Access Token. The credential used to authenticate the request is not granted any of the scopes 'urn:a', 'urn:b', at least one of which is required.")
	})

	t.Run("ShouldSkipCheckWhenNoScopesRequired", func(t *testing.T) {
		err := ValidateBearerAuthorization(ctx, config, newBearerRequest(), newBearerRequester(nil, []string{"urn:aud"}), "token",
			BearerAuthorization{Audiences: []string{"urn:aud"}})

		assert.NoError(t, err)
	})

	t.Run("ShouldNotUseTheScopeStrategyForWildcardMatching", func(t *testing.T) {
		err := ValidateBearerAuthorization(ctx, config, newBearerRequest(), newBearerRequester([]string{"*"}, []string{"urn:aud"}), "token", auth)

		require.Error(t, err)
		assert.EqualError(t, ErrorToDebugRFC6749Error(err), "The request requires higher privileges than provided by the Access Token. The credential used to authenticate the request is not granted any of the scopes 'urn:a', 'urn:b', at least one of which is required.")
	})

	t.Run("ShouldRecordTheRequiredScopesForTheChallenge", func(t *testing.T) {
		err := ValidateBearerAuthorization(ctx, config, newBearerRequest(), newBearerRequester([]string{"read"}, []string{"urn:aud"}), "token", auth)

		require.Error(t, err)
		assert.Equal(t, "urn:a urn:b", ErrorToRFC6749Error(err).ScopeField)
	})

	t.Run("ShouldNotMutateThePackageLevelError", func(t *testing.T) {
		assert.Empty(t, ErrInsufficientScope.ScopeField)
		assert.Empty(t, ErrInsufficientScope.HintField)
	})
}

func TestValidateBearerAuthorizationCheckOrder(t *testing.T) {
	ctx := context.Background()
	config := &Config{}

	err := ValidateBearerAuthorization(ctx, config, newBearerRequest(),
		newBearerRequester([]string{"read"}, []string{"urn:wrong"}), "token",
		BearerAuthorization{Audiences: []string{"urn:aud"}, Scopes: []string{"urn:required"}})

	require.Error(t, err)
	assert.EqualError(t, ErrorToDebugRFC6749Error(err), "The request requires higher privileges than provided by the Access Token. The credential used to authenticate the request is not granted any of the scopes 'urn:required', at least one of which is required.")
}

func TestValidateBearerAuthorizationResourceIndicatorsCountAsAudience(t *testing.T) {
	ctx := context.Background()
	config := &Config{}

	requester := NewRequest()
	requester.Session = &DefaultSession{}
	requester.GrantResource("urn:example:resource")

	err := ValidateBearerAuthorization(ctx, config, newBearerRequest(), requester, "token",
		BearerAuthorization{Audiences: []string{"urn:example:resource"}})

	assert.NoError(t, err)
}

func TestValidateBearerAuthorizationBinding(t *testing.T) {
	ctx := context.Background()

	t.Run("ShouldFailClosedOnUnverifiableDPoPBinding", func(t *testing.T) {
		config := &Config{DPoPEnabled: true}

		requester := NewRequest()
		requester.Session = &DefaultSession{JWKThumbprint: "some-thumbprint"}
		requester.GrantAudience("urn:aud")

		err := ValidateBearerAuthorization(ctx, config, newBearerRequest(), requester, "token",
			BearerAuthorization{Audiences: []string{"urn:aud"}})

		require.Error(t, err)
		rfc := ErrorToRFC6749Error(err)
		assert.EqualError(t, ErrorToDebugRFC6749Error(err), "The access token provided is expired, revoked, malformed, or invalid for other reasons. The access token is invalid or was not presented in the manner it is bound to. The credential used to authenticate the request is bound to a DPoP key but the configured DPoP strategy cannot validate resource access.")
		assert.Equal(t, http.StatusUnauthorized, rfc.CodeField)
	})

	t.Run("ShouldSkipDPoPBindingWhenDisabled", func(t *testing.T) {
		config := &Config{DPoPEnabled: false}

		requester := NewRequest()
		requester.Session = &DefaultSession{JWKThumbprint: "some-thumbprint"}
		requester.GrantAudience("urn:aud")

		err := ValidateBearerAuthorization(ctx, config, newBearerRequest(), requester, "token",
			BearerAuthorization{Audiences: []string{"urn:aud"}})

		assert.NoError(t, err)
	})

	t.Run("ShouldSkipMTLSBindingWhenDisabled", func(t *testing.T) {
		config := &Config{MTLSEnabled: false}

		requester := NewRequest()
		requester.Session = &DefaultSession{ClientCertificateThumbprint: "some-x5t"}
		requester.GrantAudience("urn:aud")

		err := ValidateBearerAuthorization(ctx, config, newBearerRequest(), requester, "token",
			BearerAuthorization{Audiences: []string{"urn:aud"}})

		assert.NoError(t, err)
	})

	t.Run("ShouldRejectMTLSBindingWithNoCertificate", func(t *testing.T) {
		config := &Config{MTLSEnabled: true}

		requester := NewRequest()
		requester.Session = &DefaultSession{ClientCertificateThumbprint: "some-x5t"}
		requester.GrantAudience("urn:aud")

		err := ValidateBearerAuthorization(ctx, config, newBearerRequest(), requester, "token",
			BearerAuthorization{Audiences: []string{"urn:aud"}})

		require.Error(t, err)
		rfc := ErrorToRFC6749Error(err)
		assert.EqualError(t, ErrorToDebugRFC6749Error(err), "The access token provided is expired, revoked, malformed, or invalid for other reasons. The access token is bound to a client certificate but the request was not made over a mutually authenticated TLS connection.")
		assert.Equal(t, http.StatusUnauthorized, rfc.CodeField)
	})

	t.Run("ShouldAdmitAnUnboundCredential", func(t *testing.T) {
		config := &Config{DPoPEnabled: true, MTLSEnabled: true}

		requester := NewRequest()
		requester.Session = &DefaultSession{}
		requester.GrantAudience("urn:aud")

		err := ValidateBearerAuthorization(ctx, config, newBearerRequest(), requester, "token",
			BearerAuthorization{Audiences: []string{"urn:aud"}})

		assert.NoError(t, err)
	})

	t.Run("ShouldAdmitANilSession", func(t *testing.T) {
		config := &Config{DPoPEnabled: true, MTLSEnabled: true}

		requester := NewRequest()
		requester.Session = nil
		requester.GrantAudience("urn:aud")

		err := ValidateBearerAuthorization(ctx, config, newBearerRequest(), requester, "token",
			BearerAuthorization{Audiences: []string{"urn:aud"}})

		assert.NoError(t, err)
	})
}

func TestValidateBearerAuthorizationBindingEnforcement(t *testing.T) {
	ctx := context.Background()
	auth := BearerAuthorization{Audiences: []string{"urn:aud"}}

	testCases := []struct {
		name     string
		config   *Config
		session  Session
		expected string
	}{
		{
			name:     "ShouldRejectAnUnboundCredentialWhenDPoPEnforced",
			config:   &Config{DPoPEnforce: true},
			session:  &DefaultSession{},
			expected: "The access token provided is expired, revoked, malformed, or invalid for other reasons. The credential used to authenticate the request is not bound to a DPoP key. DPoP is enforced, so every credential presented to authenticate a request must be bound to a DPoP key, but this credential records no binding.",
		},
		{
			name:     "ShouldRejectAnUnboundCredentialWhenMTLSEnforced",
			config:   &Config{MTLSEnforce: true},
			session:  &DefaultSession{},
			expected: "The access token provided is expired, revoked, malformed, or invalid for other reasons. The credential used to authenticate the request is not bound to a client certificate. Mutual-TLS client certificate bound access tokens are enforced, so every credential presented to authenticate a request must be bound to a client certificate, but this credential records no binding.",
		},
		{
			name:     "ShouldRejectANilSessionWhenDPoPEnforced",
			config:   &Config{DPoPEnforce: true},
			session:  nil,
			expected: "The access token provided is expired, revoked, malformed, or invalid for other reasons. The credential used to authenticate the request is not bound to a DPoP key. DPoP is enforced, so every credential presented to authenticate a request must be bound to a DPoP key, but this credential records no binding.",
		},
		{
			name:     "ShouldRejectANilSessionWhenMTLSEnforced",
			config:   &Config{MTLSEnforce: true},
			session:  nil,
			expected: "The access token provided is expired, revoked, malformed, or invalid for other reasons. The credential used to authenticate the request is not bound to a client certificate. Mutual-TLS client certificate bound access tokens are enforced, so every credential presented to authenticate a request must be bound to a client certificate, but this credential records no binding.",
		},
		{
			name:     "ShouldRejectASessionThatCannotRecordTheEnforcedBinding",
			config:   &Config{MTLSEnforce: true},
			session:  &bearerEnforcementSession{DefaultSession: &DefaultSession{ClientCertificateThumbprint: "some-x5t"}},
			expected: "The access token provided is expired, revoked, malformed, or invalid for other reasons. The credential used to authenticate the request is not bound to a client certificate. Mutual-TLS client certificate bound access tokens are enforced, so every credential presented to authenticate a request must be bound to a client certificate, but this credential records no binding.",
		},
		{
			name:     "ShouldReportDPoPFirstWhenBothEnforced",
			config:   &Config{DPoPEnforce: true, MTLSEnforce: true},
			session:  &DefaultSession{},
			expected: "The access token provided is expired, revoked, malformed, or invalid for other reasons. The credential used to authenticate the request is not bound to a DPoP key. DPoP is enforced, so every credential presented to authenticate a request must be bound to a DPoP key, but this credential records no binding.",
		},
		{
			name:     "ShouldStillRequireMTLSWhenOnlyDPoPBound",
			config:   &Config{DPoPEnforce: true, MTLSEnforce: true, DPoPStrategy: &bearerResourceStrategy{}},
			session:  &DefaultSession{JWKThumbprint: "some-jkt"},
			expected: "The access token provided is expired, revoked, malformed, or invalid for other reasons. The credential used to authenticate the request is not bound to a client certificate. Mutual-TLS client certificate bound access tokens are enforced, so every credential presented to authenticate a request must be bound to a client certificate, but this credential records no binding.",
		},
		{
			name:    "ShouldNotEnforceADisabledMethod",
			config:  nil,
			session: &DefaultSession{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			requester := NewRequest()
			requester.Session = tc.session
			requester.GrantAudience("urn:aud")

			var config BearerAuthorizationConfig = tc.config

			if tc.config == nil {
				config = &bearerEnforceWithoutEnableConfig{}
			}

			err := ValidateBearerAuthorization(ctx, config, newBearerRequest(), requester, "token", auth)

			if tc.expected == "" {
				assert.NoError(t, err)

				return
			}

			require.Error(t, err)

			assert.Equal(t, http.StatusUnauthorized, ErrorToRFC6749Error(err).CodeField)
			assert.EqualError(t, ErrorToDebugRFC6749Error(err), tc.expected)
		})
	}

	t.Run("ShouldAdmitABoundCredentialWhenEnforced", func(t *testing.T) {
		cert := gen.MustCertificate(gen.CertificateOptions{})
		config := &Config{DPoPEnforce: true, MTLSEnforce: true, DPoPStrategy: &bearerResourceStrategy{}}

		requester := NewRequest()
		requester.Session = &DefaultSession{JWKThumbprint: "some-jkt", ClientCertificateThumbprint: X509CertificateSHA256Thumbprint(cert)}
		requester.GrantAudience("urn:aud")

		r := newBearerRequest()
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}

		assert.NoError(t, ValidateBearerAuthorization(ctx, config, r, requester, "token", auth))
	})

	t.Run("ShouldNotMutateThePackageLevelError", func(t *testing.T) {
		assert.Equal(t, "The access token is invalid or was not presented in the manner it is bound to.", ErrInvalidToken.HintField)
		assert.Empty(t, ErrInvalidToken.DebugField)
	})
}

type bearerEnforceWithoutEnableConfig struct {
	Config
}

func (c *bearerEnforceWithoutEnableConfig) GetDPoPEnabled(ctx context.Context) bool { return false }

func (c *bearerEnforceWithoutEnableConfig) GetDPoPEnforce(ctx context.Context) bool { return true }

func (c *bearerEnforceWithoutEnableConfig) GetMTLSEnabled(ctx context.Context) bool { return false }

func (c *bearerEnforceWithoutEnableConfig) GetMTLSEnforce(ctx context.Context) bool { return true }

type bearerResourceStrategy struct {
	DPoPStrategy
}

func (s *bearerResourceStrategy) ValidateResourceAccess(ctx context.Context, r *http.Request, accessToken, boundJKT string, requireNonce bool) (*DPoPProof, error) {
	return &DPoPProof{Thumbprint: boundJKT}, nil
}

type bearerEnforcementSession struct {
	*DefaultSession
}

func (s *bearerEnforcementSession) GetClientCertificateSHA256Thumbprint() string { return "" }

func (s *bearerEnforcementSession) SetClientCertificateSHA256Thumbprint(string) {}

func newBearerRequest() *http.Request {
	r := httptest.NewRequest(http.MethodPost, "https://as.example.com/introspect", nil)
	r.Host = "as.example.com"

	return r
}

func newBearerRequester(scopes, audience []string) Requester {
	requester := NewRequest()
	requester.Session = &DefaultSession{}

	for _, scope := range scopes {
		requester.GrantScope(scope)
	}

	for _, aud := range audience {
		requester.GrantAudience(aud)
	}

	return requester
}
