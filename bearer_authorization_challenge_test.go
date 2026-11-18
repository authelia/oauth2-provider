// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/x/errorsx"
)

func TestWriteBearerAuthorizationChallenge(t *testing.T) {
	ctx := context.Background()

	testCases := []struct {
		name         string
		dpop         bool
		err          error
		authHeader   string
		location     func(ctx context.Context, r *http.Request) string
		nilRequest   bool
		expectedAuth string
		expectedCode int
	}{
		{
			name:         "ShouldOmitErrorParamsWhenNoCredentialPresented",
			dpop:         true,
			err:          errorsx.WithStack(ErrInvalidToken),
			expectedAuth: `Bearer, DPoP algs="ES256 RS256"`,
			expectedCode: http.StatusUnauthorized,
		},
		{
			name:         "ShouldCarryErrorOnBearerChallengeWhenBearerUsed",
			dpop:         true,
			err:          errorsx.WithStack(ErrInvalidToken),
			authHeader:   "Bearer abc",
			expectedAuth: `Bearer error="invalid_token", error_description="The access token provided is expired, revoked, malformed, or invalid for other reasons.", DPoP algs="ES256 RS256"`,
			expectedCode: http.StatusUnauthorized,
		},
		{
			name:         "ShouldCarryErrorOnDPoPChallengeWhenDPoPUsed",
			dpop:         true,
			err:          errorsx.WithStack(ErrInvalidDPoPProof),
			authHeader:   "DPoP abc",
			expectedAuth: `Bearer, DPoP error="invalid_dpop_proof", error_description="The DPoP proof is missing or invalid.", algs="ES256 RS256"`,
			expectedCode: http.StatusUnauthorized,
		},
		{
			name:         "ShouldOmitDPoPChallengeWhenDPoPDisabled",
			dpop:         false,
			err:          errorsx.WithStack(ErrInvalidToken),
			authHeader:   "Bearer abc",
			expectedAuth: `Bearer error="invalid_token", error_description="The access token provided is expired, revoked, malformed, or invalid for other reasons."`,
			expectedCode: http.StatusUnauthorized,
		},
		{
			name:         "ShouldCarryResourceMetadataWhenNoCredentialPresented",
			dpop:         true,
			err:          errorsx.WithStack(ErrInvalidToken),
			location:     testProtectedResourceMetadataURL,
			expectedAuth: `Bearer resource_metadata="https://rs.example.com/.well-known/oauth-protected-resource", DPoP resource_metadata="https://rs.example.com/.well-known/oauth-protected-resource", algs="ES256 RS256"`,
			expectedCode: http.StatusUnauthorized,
		},
		{
			name:         "ShouldCarryResourceMetadataOnBothChallengesWhenBearerUsed",
			dpop:         true,
			err:          errorsx.WithStack(ErrInvalidToken),
			authHeader:   "Bearer abc",
			location:     testProtectedResourceMetadataURL,
			expectedAuth: `Bearer resource_metadata="https://rs.example.com/.well-known/oauth-protected-resource", error="invalid_token", error_description="The access token provided is expired, revoked, malformed, or invalid for other reasons.", DPoP resource_metadata="https://rs.example.com/.well-known/oauth-protected-resource", algs="ES256 RS256"`,
			expectedCode: http.StatusUnauthorized,
		},
		{
			name:         "ShouldCarryResourceMetadataBeforeErrorWhenDPoPUsed",
			dpop:         true,
			err:          errorsx.WithStack(ErrInvalidDPoPProof),
			authHeader:   "DPoP abc",
			location:     testProtectedResourceMetadataURL,
			expectedAuth: `Bearer resource_metadata="https://rs.example.com/.well-known/oauth-protected-resource", DPoP resource_metadata="https://rs.example.com/.well-known/oauth-protected-resource", error="invalid_dpop_proof", error_description="The DPoP proof is missing or invalid.", algs="ES256 RS256"`,
			expectedCode: http.StatusUnauthorized,
		},
		{
			name:         "ShouldCarryResourceMetadataOnNonceChallenge",
			dpop:         true,
			err:          errorsx.WithStack(ErrUseDPoPNonce.WithDescription("x")),
			authHeader:   "DPoP abc",
			location:     testProtectedResourceMetadataURL,
			expectedAuth: `DPoP resource_metadata="https://rs.example.com/.well-known/oauth-protected-resource", error="use_dpop_nonce", error_description="x", algs="ES256 RS256"`,
			expectedCode: http.StatusUnauthorized,
		},
		{
			name:         "ShouldCarryResourceMetadataWhenDPoPDisabled",
			err:          errorsx.WithStack(ErrInvalidToken),
			location:     testProtectedResourceMetadataURL,
			expectedAuth: `Bearer resource_metadata="https://rs.example.com/.well-known/oauth-protected-resource"`,
			expectedCode: http.StatusUnauthorized,
		},
		{
			name: "ShouldNotConsultProviderWhenRequestNil",
			dpop: true,
			err:  errorsx.WithStack(ErrInvalidToken.WithDescription("x")),
			location: func(ctx context.Context, r *http.Request) string {
				panic("the provider must not be consulted without a request")
			},
			nilRequest:   true,
			expectedAuth: `Bearer error="invalid_token", error_description="x", DPoP error="invalid_token", error_description="x", algs="ES256 RS256"`,
			expectedCode: http.StatusUnauthorized,
		},
		{
			name:         "ShouldOmitResourceMetadataWhenProviderReturnsEmpty",
			dpop:         true,
			err:          errorsx.WithStack(ErrInvalidToken),
			authHeader:   "Bearer abc",
			location:     func(ctx context.Context, r *http.Request) string { return "" },
			expectedAuth: `Bearer error="invalid_token", error_description="The access token provided is expired, revoked, malformed, or invalid for other reasons.", DPoP algs="ES256 RS256"`,
			expectedCode: http.StatusUnauthorized,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{DPoPEnabled: tc.dpop, DPoPAllowedJWSAlgorithms: []string{"ES256", "RS256"}, ProtectedResourceMetadataURL: tc.location}
			f := &Fosite{Config: config}

			var r *http.Request

			if !tc.nilRequest {
				r = httptest.NewRequest(http.MethodPost, "https://as.example.com/introspect", nil)
			}

			if tc.authHeader != "" {
				r.Header.Set("Authorization", tc.authHeader)
			}

			rw := httptest.NewRecorder()

			rfc := f.WriteBearerAuthorizationChallenge(ctx, rw, r, tc.err)

			assert.Equal(t, tc.expectedAuth, rw.Header().Get("WWW-Authenticate"))
			assert.Equal(t, tc.expectedCode, rfc.CodeField)
		})
	}
}

func TestWriteBearerAuthorizationChallengeMultipleAuthorizationHeaders(t *testing.T) {
	f := &Fosite{Config: &Config{DPoPEnabled: true, DPoPAllowedJWSAlgorithms: []string{"ES256"}}}

	r := httptest.NewRequest(http.MethodGet, "https://rs.example.com/resource", nil)
	r.Header.Add("Authorization", "Bearer abc")
	r.Header.Add("Authorization", "DPoP abc")

	rw := httptest.NewRecorder()

	rfc := f.WriteBearerAuthorizationChallenge(context.Background(), rw, r, errorsx.WithStack(ErrInvalidRequest.WithDescription("x")))

	assert.Equal(t, http.StatusBadRequest, rfc.CodeField)

	assert.Equal(t, `Bearer error="invalid_request", error_description="x", DPoP error="invalid_request", error_description="x", algs="ES256"`, rw.Header().Get("WWW-Authenticate"))
}

func TestBearerAuthorizationChallenge(t *testing.T) {
	testCases := []struct {
		name     string
		dpop     bool
		realm    string
		err      error
		schemes  []string
		expected string
	}{
		{
			name:     "ShouldCarryRealmWithoutCredential",
			dpop:     true,
			realm:    "example",
			err:      ErrInvalidToken,
			expected: `Bearer realm="example", DPoP realm="example", algs="ES256"`,
		},
		{
			name:     "ShouldCarryRealmBeforeErrorOnBearer",
			dpop:     true,
			realm:    "example",
			err:      ErrInvalidToken.WithDescription("x"),
			schemes:  []string{"Bearer"},
			expected: `Bearer realm="example", error="invalid_token", error_description="x", DPoP realm="example", algs="ES256"`,
		},
		{
			name:     "ShouldCarryRealmBeforeErrorOnDPoP",
			dpop:     true,
			realm:    "example",
			err:      ErrInvalidDPoPProof.WithDescription("x"),
			schemes:  []string{"dpop"},
			expected: `Bearer realm="example", DPoP realm="example", error="invalid_dpop_proof", error_description="x", algs="ES256"`,
		},
		{
			name:     "ShouldCarryRealmOnNonceChallenge",
			dpop:     true,
			realm:    "example",
			err:      ErrUseDPoPNonce.WithDescription("x"),
			expected: `DPoP realm="example", error="use_dpop_nonce", error_description="x", algs="ES256"`,
		},
		{
			name:     "ShouldCarryRealmWhenDPoPDisabled",
			realm:    "example",
			err:      ErrInvalidToken.WithDescription("x"),
			schemes:  []string{"Bearer"},
			expected: `Bearer realm="example", error="invalid_token", error_description="x"`,
		},
		{
			name:     "ShouldOmitEmptyRealm",
			err:      ErrInvalidToken,
			expected: `Bearer`,
		},
		{
			name:     "ShouldQuoteRealm",
			realm:    "a \"b\" \\ c\r\n",
			err:      ErrInvalidToken,
			expected: `Bearer realm="a \"b\" \\ c"`,
		},
		{
			name:     "ShouldDeliverErrorOnBothWhenSchemesDiffer",
			dpop:     true,
			err:      ErrInvalidRequest.WithDescription("x"),
			schemes:  []string{"Bearer", "DPoP"},
			expected: `Bearer error="invalid_request", error_description="x", DPoP error="invalid_request", error_description="x", algs="ES256"`,
		},
		{
			name:     "ShouldTreatRepeatedSchemeAsEstablished",
			dpop:     true,
			err:      ErrInvalidDPoPProof.WithDescription("x"),
			schemes:  []string{"DPoP", "dpop"},
			expected: `Bearer, DPoP error="invalid_dpop_proof", error_description="x", algs="ES256"`,
		},
		{
			name:     "ShouldDeliverErrorOnBothWhenManySchemesDiffer",
			dpop:     true,
			err:      ErrInvalidRequest.WithDescription("x"),
			schemes:  []string{"Basic", "basic", "Bearer", "DPoP", "Other"},
			expected: `Bearer error="invalid_request", error_description="x", DPoP error="invalid_request", error_description="x", algs="ES256"`,
		},
		{
			name:     "ShouldIgnoreEmptySchemes",
			dpop:     true,
			err:      ErrInvalidToken,
			schemes:  []string{"", ""},
			expected: `Bearer, DPoP algs="ES256"`,
		},
		{
			name:     "ShouldAnswerOtherSchemesOnBearer",
			dpop:     true,
			err:      ErrInvalidToken.WithDescription("x"),
			schemes:  []string{"Basic"},
			expected: `Bearer error="invalid_token", error_description="x", DPoP algs="ES256"`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{DPoPEnabled: tc.dpop, DPoPAllowedJWSAlgorithms: []string{"ES256"}}

			assert.Equal(t, tc.expected, BearerAuthorizationChallenge(context.Background(), config, tc.realm, errorsx.WithStack(tc.err), tc.schemes...))
		})
	}
}

func TestWriteBearerAuthorizationChallengeResourceMetadataRequest(t *testing.T) {
	var actual *http.Request

	const location = "https://rs.example.com/.well-known/oauth-protected-resource/api"

	config := &Config{ProtectedResourceMetadataURL: func(ctx context.Context, r *http.Request) string {
		actual = r

		return location
	}}

	f := &Fosite{Config: config}

	r := httptest.NewRequest(http.MethodGet, "https://other.example.com/api/resource", nil)
	rw := httptest.NewRecorder()

	_ = f.WriteBearerAuthorizationChallenge(context.Background(), rw, r, errorsx.WithStack(ErrInvalidToken))

	assert.Same(t, r, actual)
	assert.Equal(t, `Bearer resource_metadata="`+location+`"`, rw.Header().Get("WWW-Authenticate"))
}

func TestBearerAuthorizationChallengeWithResourceMetadata(t *testing.T) {
	const location = "https://rs.example.com/.well-known/oauth-protected-resource"

	scope := ErrInsufficientScope.WithDescription("x")
	scope.ScopeField = "urn:a urn:b"

	testCases := []struct {
		name     string
		dpop     bool
		realm    string
		location string
		err      error
		schemes  []string
		expected string
	}{
		{
			name:     "ShouldOrderRealmResourceMetadataThenScope",
			dpop:     true,
			realm:    "example",
			location: location,
			err:      scope,
			schemes:  []string{"Bearer"},
			expected: `Bearer realm="example", resource_metadata="https://rs.example.com/.well-known/oauth-protected-resource", error="insufficient_scope", error_description="x", scope="urn:a urn:b", DPoP realm="example", resource_metadata="https://rs.example.com/.well-known/oauth-protected-resource", algs="ES256"`,
		},
		{
			name:     "ShouldOrderRealmResourceMetadataThenScopeOnDPoP",
			dpop:     true,
			realm:    "example",
			location: location,
			err:      scope,
			schemes:  []string{"DPoP"},
			expected: `Bearer realm="example", resource_metadata="https://rs.example.com/.well-known/oauth-protected-resource", DPoP realm="example", resource_metadata="https://rs.example.com/.well-known/oauth-protected-resource", error="insufficient_scope", error_description="x", scope="urn:a urn:b", algs="ES256"`,
		},
		{
			name:     "ShouldCarryResourceMetadataWithoutCredential",
			dpop:     true,
			location: location,
			err:      ErrInvalidToken,
			expected: `Bearer resource_metadata="https://rs.example.com/.well-known/oauth-protected-resource", DPoP resource_metadata="https://rs.example.com/.well-known/oauth-protected-resource", algs="ES256"`,
		},
		{
			name:     "ShouldCarryResourceMetadataOnNonceChallenge",
			dpop:     true,
			location: location,
			err:      ErrUseDPoPNonce.WithDescription("x"),
			expected: `DPoP resource_metadata="https://rs.example.com/.well-known/oauth-protected-resource", error="use_dpop_nonce", error_description="x", algs="ES256"`,
		},
		{
			name:     "ShouldCarryResourceMetadataWhenDPoPDisabled",
			realm:    "example",
			location: location,
			err:      ErrInvalidToken.WithDescription("x"),
			schemes:  []string{"Bearer"},
			expected: `Bearer realm="example", resource_metadata="https://rs.example.com/.well-known/oauth-protected-resource", error="invalid_token", error_description="x"`,
		},
		{
			name:     "ShouldQuoteResourceMetadata",
			location: "https://rs.example.com/a\"b\r\n",
			err:      ErrInvalidToken,
			expected: `Bearer resource_metadata="https://rs.example.com/a\"b"`,
		},
		{
			name:     "ShouldQuoteResourceMetadataBackslash",
			location: `https://rs.example.com/a\b`,
			err:      ErrInvalidToken,
			expected: `Bearer resource_metadata="https://rs.example.com/a\\b"`,
		},
		{
			name:     "ShouldOmitEmptyResourceMetadata",
			dpop:     true,
			realm:    "example",
			err:      ErrInvalidToken.WithDescription("x"),
			schemes:  []string{"Bearer"},
			expected: `Bearer realm="example", error="invalid_token", error_description="x", DPoP realm="example", algs="ES256"`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{DPoPEnabled: tc.dpop, DPoPAllowedJWSAlgorithms: []string{"ES256"}}

			actual := BearerAuthorizationChallengeWithResourceMetadata(context.Background(), config, tc.realm, tc.location, errorsx.WithStack(tc.err), tc.schemes...)

			assert.Equal(t, tc.expected, actual)

			if tc.location == "" {
				assert.Equal(t, BearerAuthorizationChallenge(context.Background(), config, tc.realm, errorsx.WithStack(tc.err), tc.schemes...), actual)
			}
		})
	}
}

func TestWriteBearerAuthorizationChallengeIncludesScope(t *testing.T) {
	ctx := context.Background()
	config := &Config{DPoPAllowedJWSAlgorithms: []string{"ES256"}}
	f := &Fosite{Config: config}

	rfc := ErrInsufficientScope.WithHint("nope")
	rfc.ScopeField = "urn:a urn:b"

	r := httptest.NewRequest(http.MethodPost, "https://as.example.com/register", nil)
	r.Header.Set("Authorization", "Bearer abc")

	rw := httptest.NewRecorder()

	_ = f.WriteBearerAuthorizationChallenge(ctx, rw, r, errorsx.WithStack(rfc))

	assert.Contains(t, rw.Header().Get("WWW-Authenticate"), `scope="urn:a urn:b"`)
	assert.Contains(t, rw.Header().Get("WWW-Authenticate"), `error="insufficient_scope"`)
}

func TestWriteBearerAuthorizationChallengeIncludesAuthenticationRequirements(t *testing.T) {
	ctx := context.Background()

	testCases := []struct {
		name     string
		err      *RFC6749Error
		expected string
	}{
		{
			name:     "ShouldIncludeACRValues",
			err:      ErrInsufficientUserAuthentication.WithDescription("A different authentication level is required").WithExtra("acr_values", "myACR"),
			expected: `Bearer error="insufficient_user_authentication", error_description="A different authentication level is required", acr_values="myACR"`,
		},
		{
			name:     "ShouldIncludeMaxAge",
			err:      ErrInsufficientUserAuthentication.WithDescription("More recent authentication is required").WithExtra("max_age", int64(5)),
			expected: `Bearer error="insufficient_user_authentication", error_description="More recent authentication is required", max_age="5"`,
		},
		{
			name:     "ShouldIncludeBothAndJoinACRValues",
			err:      ErrInsufficientUserAuthentication.WithDescription("x").WithExtra("acr_values", []string{"gold", "silver"}).WithExtra("max_age", 0),
			expected: `Bearer error="insufficient_user_authentication", error_description="x", acr_values="gold silver", max_age="0"`,
		},
		{
			name:     "ShouldOmitRequirementsOnOtherErrors",
			err:      ErrInvalidToken.WithDescription("x").WithExtra("acr_values", "myACR").WithExtra("max_age", 5),
			expected: `Bearer error="invalid_token", error_description="x"`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := &Fosite{Config: &Config{}}

			r := httptest.NewRequest(http.MethodGet, "https://rs.example.com/resource", nil)
			r.Header.Set("Authorization", "Bearer abc")

			rw := httptest.NewRecorder()

			_ = f.WriteBearerAuthorizationChallenge(ctx, rw, r, errorsx.WithStack(tc.err))

			assert.Equal(t, tc.expected, rw.Header().Get("WWW-Authenticate"))
		})
	}
}

func TestWriteBearerAuthorizationChallengePromotesResourceStatuses(t *testing.T) {
	ctx := context.Background()
	config := &Config{DPoPEnabled: true, DPoPAllowedJWSAlgorithms: []string{"ES256"}}
	f := &Fosite{Config: config}

	for _, err := range []*RFC6749Error{ErrInvalidDPoPProof, ErrUseDPoPNonce, ErrInsufficientUserAuthentication} {
		rw := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "https://as.example.com/introspect", nil)

		rfc := f.WriteBearerAuthorizationChallenge(ctx, rw, r, errorsx.WithStack(err))

		assert.Equal(t, http.StatusUnauthorized, rfc.CodeField)
		assert.Equal(t, http.StatusBadRequest, err.CodeField)
	}
}

func TestWriteBearerAuthorizationChallengeNonce(t *testing.T) {
	ctx := context.Background()
	config := &Config{DPoPEnabled: true, DPoPNonceRequired: true, DPoPAllowedJWSAlgorithms: []string{"ES256"}}
	config.DPoPStrategy = testNonceStrategy{}
	f := &Fosite{Config: config}

	t.Run("ShouldEmitDPoPOnlyChallengeAndNonce", func(t *testing.T) {
		rw := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "https://as.example.com/introspect", nil)

		_ = f.WriteBearerAuthorizationChallenge(ctx, rw, r, errorsx.WithStack(ErrUseDPoPNonce))
		assert.Equal(t, `DPoP error="use_dpop_nonce", error_description="Authorization server requires nonce in DPoP proof.", algs="ES256"`, rw.Header().Get("WWW-Authenticate"))
		assert.Equal(t, "fixed-nonce", rw.Header().Get("DPoP-Nonce"))
	})

	t.Run("ShouldBeIdenticalForAnyCredential", func(t *testing.T) {
		auths := []string{"", "DPoP garbage", "DPoP a-perfectly-good-token"}
		headers := make([]string, 0, len(auths))

		for _, auth := range auths {
			rw := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "https://as.example.com/introspect", nil)

			if auth != "" {
				r.Header.Set("Authorization", auth)
			}

			_ = f.WriteBearerAuthorizationChallenge(ctx, rw, r, errorsx.WithStack(ErrUseDPoPNonce))

			headers = append(headers, rw.Header().Get("WWW-Authenticate"))
			require.NotEmpty(t, rw.Header().Get("DPoP-Nonce"))
		}

		assert.Equal(t, headers[0], headers[1])
		assert.Equal(t, headers[1], headers[2])
	})
}

type testNonceStrategy struct {
	DPoPStrategy
}

func (testNonceStrategy) NewDPoPNonce(ctx context.Context) (nonce string, err error) {
	return "fixed-nonce", nil
}

func TestIsBearerCredentialError(t *testing.T) {
	assert.True(t, IsBearerCredentialError(errorsx.WithStack(ErrInsufficientUserAuthentication.WithExtra("max_age", 5))))
	assert.True(t, IsBearerCredentialError(errorsx.WithStack(ErrInsufficientScope)))
	assert.False(t, IsBearerCredentialError(errorsx.WithStack(ErrRequestUnauthorized)))
}

func testProtectedResourceMetadataURL(ctx context.Context, r *http.Request) string {
	return "https://rs.example.com/.well-known/oauth-protected-resource"
}
