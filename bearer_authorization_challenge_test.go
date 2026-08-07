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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{DPoPEnabled: tc.dpop, DPoPAllowedJWSAlgorithms: []string{"ES256", "RS256"}}
			f := &Fosite{Config: config}

			r := httptest.NewRequest(http.MethodPost, "https://as.example.com/introspect", nil)
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

func TestWriteBearerAuthorizationChallengeIncludesScope(t *testing.T) {
	ctx := context.Background()
	config := &Config{DPoPAllowedJWSAlgorithms: []string{"ES256"}}
	f := &Fosite{Config: config}

	rfc := ErrInsufficientScope.WithHint("nope")
	rfc.ScopeField = "urn:a urn:b"

	r := httptest.NewRequest(http.MethodPost, "https://as.example.com/register", nil)
	r.Header.Set("Authorization", "Bearer abc")

	rw := httptest.NewRecorder()

	f.WriteBearerAuthorizationChallenge(ctx, rw, r, errorsx.WithStack(rfc))

	assert.Contains(t, rw.Header().Get("WWW-Authenticate"), `scope="urn:a urn:b"`)
	assert.Contains(t, rw.Header().Get("WWW-Authenticate"), `error="insufficient_scope"`)
}

func TestWriteBearerAuthorizationChallengePromotesResourceStatuses(t *testing.T) {
	ctx := context.Background()
	config := &Config{DPoPEnabled: true, DPoPAllowedJWSAlgorithms: []string{"ES256"}}
	f := &Fosite{Config: config}

	for _, err := range []*RFC6749Error{ErrInvalidDPoPProof, ErrUseDPoPNonce} {
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

		f.WriteBearerAuthorizationChallenge(ctx, rw, r, errorsx.WithStack(ErrUseDPoPNonce))
		assert.Equal(t, `DPoP error="use_dpop_nonce", error_description="Authorization server requires nonce in DPoP proof.", algs="ES256"`, rw.Header().Get("WWW-Authenticate"))
		assert.Equal(t, "fixed-nonce", rw.Header().Get("DPoP-Nonce"))
	})

	t.Run("ShouldBeIdenticalForAnyCredential", func(t *testing.T) {
		var headers []string

		for _, auth := range []string{"", "DPoP garbage", "DPoP a-perfectly-good-token"} {
			rw := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "https://as.example.com/introspect", nil)

			if auth != "" {
				r.Header.Set("Authorization", auth)
			}

			f.WriteBearerAuthorizationChallenge(ctx, rw, r, errorsx.WithStack(ErrUseDPoPNonce))

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
