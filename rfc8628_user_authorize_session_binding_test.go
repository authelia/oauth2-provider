// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "authelia.com/provider/oauth2"
)

func TestFosite_NewRFC8628UserAuthorizeResponse_SessionBinding(t *testing.T) {
	const (
		jkt       = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
		requested = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
		x5t       = "A4DtL2JmUMhAsvJj5tAtEqYFn7uHnaMbNKmoNcE7dnE"
		other     = "kM1FTfCFVzO9tGKBVBEAWCVoWZ2WcOK1EbSPxNjQfSw"
	)

	jwk := []byte(`{"kty":"EC","crv":"P-256","x":"x","y":"y"}`)

	testCases := []struct {
		name     string
		restored func() Session
		seed     func(session *DefaultSession)
		expected func(t *testing.T, session *DefaultSession)
	}{
		{
			name: "ShouldCarryEveryBindingOntoTheReplacementSession",
			restored: func() Session {
				session := new(DefaultSession)

				session.SetDPoPJWKThumbprint(jkt)
				session.SetRequestedDPoPJWKThumbprint(requested)
				session.SetDPoPPublicKeyJWK(jwk)
				session.SetOIDCKeyBindingGranted(true)
				session.SetClientCertificateSHA256Thumbprint(x5t)

				return session
			},
			expected: func(t *testing.T, session *DefaultSession) {
				assert.Equal(t, jkt, session.GetDPoPJWKThumbprint())
				assert.Equal(t, requested, session.GetRequestedDPoPJWKThumbprint())
				assert.Equal(t, jwk, session.GetDPoPPublicKeyJWK())
				assert.True(t, session.GetOIDCKeyBindingGranted())
				assert.Equal(t, x5t, session.GetClientCertificateSHA256Thumbprint())
			},
		},
		{
			name: "ShouldCarryNothingWhenTheRestoredSessionRecordedNothing",
			restored: func() Session {
				return new(DefaultSession)
			},
			expected: func(t *testing.T, session *DefaultSession) {
				assert.Empty(t, session.GetDPoPJWKThumbprint())
				assert.Empty(t, session.GetRequestedDPoPJWKThumbprint())
				assert.Empty(t, session.GetDPoPPublicKeyJWK())
				assert.False(t, session.GetOIDCKeyBindingGranted())
				assert.Empty(t, session.GetClientCertificateSHA256Thumbprint())
			},
		},
		{
			name: "ShouldLeaveAReplacementValueWhenTheRestoredSessionRecordedNothing",
			restored: func() Session {
				return new(DefaultSession)
			},
			seed: func(session *DefaultSession) {
				session.SetDPoPJWKThumbprint(jkt)
			},
			expected: func(t *testing.T, session *DefaultSession) {
				assert.Equal(t, jkt, session.GetDPoPJWKThumbprint())
			},
		},
		{
			name: "ShouldPreferTheRestoredBindingOverOneTheReplacementSessionCarries",
			restored: func() Session {
				session := new(DefaultSession)

				session.SetDPoPJWKThumbprint(jkt)
				session.SetClientCertificateSHA256Thumbprint(x5t)

				return session
			},
			seed: func(session *DefaultSession) {
				session.SetDPoPJWKThumbprint(other)
				session.SetClientCertificateSHA256Thumbprint(other)
			},
			expected: func(t *testing.T, session *DefaultSession) {
				assert.Equal(t, jkt, session.GetDPoPJWKThumbprint())
				assert.Equal(t, x5t, session.GetClientCertificateSHA256Thumbprint())
			},
		},
		{
			name: "ShouldCarryNothingWhenTheRequesterHasNoSession",
			restored: func() Session {
				return nil
			},
			expected: func(t *testing.T, session *DefaultSession) {
				assert.Empty(t, session.GetDPoPJWKThumbprint())
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			requester := NewDeviceAuthorizeRequest()

			if restored := tc.restored(); restored != nil {
				requester.SetSession(restored)
			}

			session := new(DefaultSession)

			if tc.seed != nil {
				tc.seed(session)
			}

			provider := &Fosite{Config: &Config{}}

			responder, err := provider.NewRFC8628UserAuthorizeResponse(context.Background(), requester, session)

			require.NoError(t, err)
			require.NotNil(t, responder)

			tc.expected(t, session)
		})
	}
}
