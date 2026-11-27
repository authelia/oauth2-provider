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

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

func TestWriteRFC7591ClientRegistrationErrorChallenge(t *testing.T) {
	ctx := context.Background()

	newProvider := func() *Fosite {
		config := &Config{DPoPEnabled: true, DPoPNonceRequired: true, DPoPAllowedJWSAlgorithms: []string{"ES256"}}
		config.DPoPStrategy = testNonceStrategy{}

		return &Fosite{Config: config}
	}

	testCases := []struct {
		name         string
		err          error
		expectedCode int
		expectedAuth string
		expectedNonc string
	}{
		{
			name:         "ShouldEmitANonceChallenge",
			err:          errorsx.WithStack(ErrUseDPoPNonce),
			expectedCode: http.StatusUnauthorized,
			expectedAuth: `DPoP error="use_dpop_nonce", error_description="Authorization server requires nonce in DPoP proof.", algs="ES256"`,
			expectedNonc: "fixed-nonce",
		},
		{
			name:         "ShouldPromoteAProofFailureTo401",
			err:          errorsx.WithStack(ErrInvalidDPoPProof),
			expectedCode: http.StatusUnauthorized,
			expectedAuth: `Bearer error="invalid_dpop_proof", error_description="The DPoP proof is missing or invalid.", DPoP error="invalid_dpop_proof", error_description="The DPoP proof is missing or invalid.", algs="ES256"`,
		},
		{
			name:         "ShouldAdvertiseBothSchemesForAnInvalidToken",
			err:          errorsx.WithStack(ErrInvalidToken),
			expectedCode: http.StatusUnauthorized,
			expectedAuth: `Bearer error="invalid_token", error_description="The access token provided is expired, revoked, malformed, or invalid for other reasons.", DPoP error="invalid_token", error_description="The access token provided is expired, revoked, malformed, or invalid for other reasons.", algs="ES256"`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rw := httptest.NewRecorder()

			newProvider().WriteRFC7591ClientRegistrationError(ctx, rw, nil, nil, tc.err)

			assert.Equal(t, tc.expectedCode, rw.Code)
			assert.Equal(t, tc.expectedAuth, rw.Header().Get(consts.HeaderWWWAuthenticate))
			assert.Equal(t, tc.expectedNonc, rw.Header().Get(consts.HeaderDPoPNonce))
		})
	}

	t.Run("ShouldNameTheRequiredScopeOnAnInsufficientScope", func(t *testing.T) {
		rfc := ErrInsufficientScope.WithHint("nope")
		rfc.ScopeField = "authelia:oauth2:dynamic-client-registration"

		rw := httptest.NewRecorder()

		newProvider().WriteRFC7591ClientRegistrationError(ctx, rw, nil, nil, errorsx.WithStack(rfc))

		assert.Equal(t, http.StatusForbidden, rw.Code)
		assert.Contains(t, rw.Header().Get(consts.HeaderWWWAuthenticate), `error="insufficient_scope"`)
		assert.Contains(t, rw.Header().Get(consts.HeaderWWWAuthenticate), `scope="authelia:oauth2:dynamic-client-registration"`)
	})

	t.Run("ShouldChallengeAnInsufficientUserAuthenticationWith401", func(t *testing.T) {
		rfc := ErrInsufficientUserAuthentication.WithDescription("x").WithExtra("acr_values", []string{"gold", "silver"}).WithExtra("max_age", 5)

		rw := httptest.NewRecorder()

		newProvider().WriteRFC7591ClientRegistrationError(ctx, rw, nil, nil, errorsx.WithStack(rfc))

		assert.Equal(t, http.StatusUnauthorized, rw.Code)
		assert.Equal(t, `Bearer error="insufficient_user_authentication", error_description="x", acr_values="gold silver", max_age="5", DPoP error="insufficient_user_authentication", error_description="x", acr_values="gold silver", max_age="5", algs="ES256"`, rw.Header().Get(consts.HeaderWWWAuthenticate))
		assert.Empty(t, rw.Header().Get(consts.HeaderDPoPNonce))
		assert.JSONEq(t, `{"acr_values":["gold","silver"],"error":"insufficient_user_authentication","error_description":"x","max_age":5}`, rw.Body.String())
	})

	t.Run("ShouldLeaveAMalformedRequestAlone", func(t *testing.T) {
		rw := httptest.NewRecorder()

		newProvider().WriteRFC7591ClientRegistrationError(ctx, rw, nil, nil, errorsx.WithStack(ErrInvalidRequest))

		assert.Equal(t, http.StatusBadRequest, rw.Code)
		assert.Empty(t, rw.Header().Get(consts.HeaderWWWAuthenticate))
	})
}

func TestWriteRFC7592ClientConfigurationErrorKeepsTheBareBearerChallenge(t *testing.T) {
	config := &Config{DPoPEnabled: true, DPoPAllowedJWSAlgorithms: []string{"ES256"}}

	rw := httptest.NewRecorder()

	(&Fosite{Config: config}).WriteRFC7592ClientConfigurationError(context.Background(), rw, nil, nil, errorsx.WithStack(ErrRequestUnauthorized))

	require.Equal(t, http.StatusUnauthorized, rw.Code)
	assert.Equal(t, consts.AuthSchemeBearer, rw.Header().Get(consts.HeaderWWWAuthenticate))
	assert.Empty(t, rw.Header().Get(consts.HeaderDPoPNonce))
}

func TestWriteRFC7591ClientRegistrationErrorResourceMetadata(t *testing.T) {
	const (
		location    = `Bearer resource_metadata="https://rs.example.com/.well-known/oauth-protected-resource", error="invalid_token", error_description="x", DPoP resource_metadata="https://rs.example.com/.well-known/oauth-protected-resource", algs="ES256"`
		unlocated   = `Bearer error="invalid_token", error_description="x", DPoP algs="ES256"`
		unspecified = `Bearer error="invalid_token", error_description="x", DPoP error="invalid_token", error_description="x", algs="ES256"`
	)

	testCases := []struct {
		name     string
		provider func(ctx context.Context, r *http.Request) string
		request  bool
		expected string
	}{
		{
			name:     "ShouldCarryResourceMetadataWithRequestInContext",
			provider: testProtectedResourceMetadataURL,
			request:  true,
			expected: location,
		},
		{
			name:     "ShouldOmitResourceMetadataWithoutRequestInContext",
			provider: testProtectedResourceMetadataURL,
			expected: unspecified,
		},
		{
			name:     "ShouldOmitResourceMetadataWithoutProvider",
			request:  true,
			expected: unlocated,
		},
		{
			name:     "ShouldOmitResourceMetadataWithoutProviderOrRequestInContext",
			expected: unspecified,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{DPoPEnabled: true, DPoPAllowedJWSAlgorithms: []string{"ES256"}, ProtectedResourceMetadataURL: tc.provider}

			var r *http.Request

			if tc.request {
				r = httptest.NewRequest(http.MethodPost, "https://auth.example.com/register", nil)
				r.Header.Set(consts.HeaderAuthorization, "Bearer abc")
			}

			rw := httptest.NewRecorder()

			(&Fosite{Config: config}).WriteRFC7591ClientRegistrationError(context.Background(), rw, r, nil, errorsx.WithStack(ErrInvalidToken.WithDescription("x")))

			require.Equal(t, http.StatusUnauthorized, rw.Code)
			assert.Equal(t, tc.expected, rw.Header().Get(consts.HeaderWWWAuthenticate))
		})
	}
}

func TestWriteRFC7592ClientConfigurationErrorResourceMetadata(t *testing.T) {
	testCases := []struct {
		name     string
		provider func(ctx context.Context, r *http.Request) string
		request  bool
		err      error
		code     int
		expected string
	}{
		{
			name:     "ShouldCarryResourceMetadataWithRequestInContext",
			provider: testProtectedResourceMetadataURL,
			request:  true,
			err:      ErrRequestUnauthorized,
			code:     http.StatusUnauthorized,
			expected: `Bearer resource_metadata="https://rs.example.com/.well-known/oauth-protected-resource"`,
		},
		{
			name: "ShouldQuoteResourceMetadata",
			provider: func(ctx context.Context, r *http.Request) string {
				return `https://rs.example.com/a"b\c`
			},
			request:  true,
			err:      ErrRequestUnauthorized,
			code:     http.StatusUnauthorized,
			expected: `Bearer resource_metadata="https://rs.example.com/a\"b\\c"`,
		},
		{
			name:     "ShouldKeepBareChallengeWithoutRequestInContext",
			provider: testProtectedResourceMetadataURL,
			err:      ErrRequestUnauthorized,
			code:     http.StatusUnauthorized,
			expected: "Bearer",
		},
		{
			name:     "ShouldKeepBareChallengeWithoutProvider",
			request:  true,
			err:      ErrRequestUnauthorized,
			code:     http.StatusUnauthorized,
			expected: "Bearer",
		},
		{
			name: "ShouldKeepBareChallengeWithoutLocation",
			provider: func(ctx context.Context, r *http.Request) string {
				return ""
			},
			request:  true,
			err:      ErrRequestUnauthorized,
			code:     http.StatusUnauthorized,
			expected: "Bearer",
		},
		{
			name:     "ShouldNotChallengeOtherStatuses",
			provider: testProtectedResourceMetadataURL,
			request:  true,
			err:      ErrNotFound,
			code:     http.StatusNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{DPoPEnabled: true, DPoPAllowedJWSAlgorithms: []string{"ES256"}, ProtectedResourceMetadataURL: tc.provider}

			var r *http.Request

			if tc.request {
				r = httptest.NewRequest(http.MethodGet, "https://auth.example.com/register/abc", nil)
			}

			rw := httptest.NewRecorder()

			(&Fosite{Config: config}).WriteRFC7592ClientConfigurationError(context.Background(), rw, r, nil, errorsx.WithStack(tc.err))

			require.Equal(t, tc.code, rw.Code)
			assert.Equal(t, tc.expected, rw.Header().Get(consts.HeaderWWWAuthenticate))
		})
	}
}
