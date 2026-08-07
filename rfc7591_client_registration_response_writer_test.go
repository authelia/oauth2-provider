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

			newProvider().WriteRFC7591ClientRegistrationError(ctx, rw, nil, tc.err)

			assert.Equal(t, tc.expectedCode, rw.Code)
			assert.Equal(t, tc.expectedAuth, rw.Header().Get(consts.HeaderWWWAuthenticate))
			assert.Equal(t, tc.expectedNonc, rw.Header().Get(consts.HeaderDPoPNonce))
		})
	}

	t.Run("ShouldNameTheRequiredScopeOnAnInsufficientScope", func(t *testing.T) {
		rfc := ErrInsufficientScope.WithHint("nope")
		rfc.ScopeField = "authelia:oauth2:client_registration"

		rw := httptest.NewRecorder()

		newProvider().WriteRFC7591ClientRegistrationError(ctx, rw, nil, errorsx.WithStack(rfc))

		assert.Equal(t, http.StatusForbidden, rw.Code)
		assert.Contains(t, rw.Header().Get(consts.HeaderWWWAuthenticate), `error="insufficient_scope"`)
		assert.Contains(t, rw.Header().Get(consts.HeaderWWWAuthenticate), `scope="authelia:oauth2:client_registration"`)
	})

	t.Run("ShouldLeaveAMalformedRequestAlone", func(t *testing.T) {
		rw := httptest.NewRecorder()

		newProvider().WriteRFC7591ClientRegistrationError(ctx, rw, nil, errorsx.WithStack(ErrInvalidRequest))

		assert.Equal(t, http.StatusBadRequest, rw.Code)
		assert.Empty(t, rw.Header().Get(consts.HeaderWWWAuthenticate))
	})
}

func TestWriteRFC7592ClientConfigurationErrorKeepsTheBareBearerChallenge(t *testing.T) {
	config := &Config{DPoPEnabled: true, DPoPAllowedJWSAlgorithms: []string{"ES256"}}

	rw := httptest.NewRecorder()

	(&Fosite{Config: config}).WriteRFC7592ClientConfigurationError(context.Background(), rw, nil, errorsx.WithStack(ErrRequestUnauthorized))

	require.Equal(t, http.StatusUnauthorized, rw.Code)
	assert.Equal(t, consts.AuthSchemeBearer, rw.Header().Get(consts.HeaderWWWAuthenticate))
	assert.Empty(t, rw.Header().Get(consts.HeaderDPoPNonce))
}
