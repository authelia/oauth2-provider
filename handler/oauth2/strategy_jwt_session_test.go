// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/clone/clonetest"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestJWTSessionMTLSBinding(t *testing.T) {
	var session *JWTSession

	assert.Empty(t, session.GetClientCertificateSHA256Thumbprint())

	session = &JWTSession{}

	session.SetClientCertificateSHA256Thumbprint("test-x5t")

	assert.Equal(t, "test-x5t", session.GetClientCertificateSHA256Thumbprint())
}

func TestJWTSessionConfirmationRoundTrip(t *testing.T) {
	var source oauth2.MTLSBoundSession = &JWTSession{}

	source.SetClientCertificateSHA256Thumbprint("round-trip-value")

	claims := map[string]any{}

	oauth2.ApplyConfirmation(context.Background(), &oauth2.Config{DPoPEnabled: true, MTLSEnabled: true}, claims, source.(oauth2.Session))

	cnf, ok := claims[jwt.ClaimConfirmation].(map[string]any)
	require.True(t, ok, "expected cnf to be present and a map, got %#v", claims[jwt.ClaimConfirmation])
	assert.Equal(t, "round-trip-value", cnf[jwt.ClaimConfirmationX509SHA256Thumbprint])

	restored := &JWTSession{}

	oauth2.RestoreConfirmation(claims, restored)

	assert.Equal(t, "round-trip-value", restored.GetClientCertificateSHA256Thumbprint())
}

func TestJWTSessionClone(t *testing.T) {
	testCases := []struct {
		name  string
		check func(t *testing.T)
	}{
		{
			name: "ShouldReturnNilForNilReceiver",
			check: func(t *testing.T) {
				var s *JWTSession

				assert.Nil(t, s.Clone())
			},
		},
		{
			name: "ShouldPreserveNilFields",
			check: func(t *testing.T) {
				assert.Equal(t, &JWTSession{}, (&JWTSession{}).Clone())
			},
		},
		{
			name: "ShouldDeepCopyEveryField",
			check: func(t *testing.T) {
				now := time.Unix(1700000000, 0).UTC()

				s := &JWTSession{
					JWTClaims: &jwt.JWTClaims{
						Subject:    "alice",
						Issuer:     "https://auth.example.com",
						Audience:   []string{"https://api.example.com"},
						JTI:        "jti",
						IssuedAt:   now,
						NotBefore:  now,
						ExpiresAt:  now.Add(time.Hour),
						Scope:      []string{"openid"},
						Extra:      map[string]any{"act": map[string]any{"sub": "bob"}},
						ScopeField: jwt.JWTScopeFieldList,
					},
					JWTHeader:                   &jwt.Headers{Extra: map[string]any{"typ": "at+jwt"}},
					ExpiresAt:                   map[oauth2.TokenType]time.Time{oauth2.AccessToken: now.Add(time.Hour)},
					Username:                    "alice@example",
					Subject:                     "alice",
					JWKThumbprint:               "jkt",
					ClientCertificateThumbprint: "x5t",
					RequestedJWKThumbprint:      "requested-jkt",
					PublicKeyJWK:                []byte(`{"kty":"EC"}`),
					KeyBindingGranted:           true,
				}

				clonetest.AssertDeepCopy(t, s, s.Clone())
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, tc.check)
	}
}
