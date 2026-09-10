// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"authelia.com/provider/oauth2/internal/clone/clonetest"
	. "authelia.com/provider/oauth2/token/jwt"
)

func TestClone(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()

	testCases := []struct {
		name  string
		check func(t *testing.T)
	}{
		{
			name: "ShouldReturnNilHeadersForNilReceiver",
			check: func(t *testing.T) {
				var h *Headers

				assert.Nil(t, h.Clone())
			},
		},
		{
			name: "ShouldReturnNilJWTClaimsForNilReceiver",
			check: func(t *testing.T) {
				var c *JWTClaims

				assert.Nil(t, c.Clone())
			},
		},
		{
			name: "ShouldReturnNilIDTokenClaimsForNilReceiver",
			check: func(t *testing.T) {
				var c *IDTokenClaims

				assert.Nil(t, c.Clone())
			},
		},
		{
			name: "ShouldPreserveNilFields",
			check: func(t *testing.T) {
				assert.Equal(t, &Headers{}, (&Headers{}).Clone())
				assert.Equal(t, &JWTClaims{}, (&JWTClaims{}).Clone())
				assert.Equal(t, &IDTokenClaims{}, (&IDTokenClaims{}).Clone())
			},
		},
		{
			name: "ShouldDeepCopyHeaders",
			check: func(t *testing.T) {
				h := &Headers{Extra: map[string]any{"typ": "JWT", "jwk": map[string]any{"kty": "EC"}}}

				clonetest.AssertDeepCopy(t, h, h.Clone())
			},
		},
		{
			name: "ShouldDeepCopyJWTClaims",
			check: func(t *testing.T) {
				c := &JWTClaims{
					Subject:    "alice",
					Issuer:     "https://auth.example.com",
					Audience:   []string{"https://api.example.com"},
					JTI:        "jti",
					IssuedAt:   now,
					NotBefore:  now,
					ExpiresAt:  now.Add(time.Hour),
					Scope:      []string{"openid"},
					Extra:      map[string]any{"act": map[string]any{"sub": "bob"}},
					ScopeField: JWTScopeFieldList,
				}

				clonetest.AssertDeepCopy(t, c, c.Clone())
			},
		},
		{
			name: "ShouldDeepCopyIDTokenClaims",
			check: func(t *testing.T) {
				c := &IDTokenClaims{
					JTI:                                 "jti",
					Issuer:                              "https://auth.example.com",
					Subject:                             "alice",
					Audience:                            []string{"client"},
					ExpirationTime:                      NewNumericDate(now.Add(time.Hour)),
					IssuedAt:                            NewNumericDate(now),
					AuthTime:                            NewNumericDate(now),
					Nonce:                               "nonce",
					SessionID:                           "sid",
					AuthenticationContextClassReference: "acr",
					AuthenticationMethodsReferences:     []string{"pwd"},
					AuthorizedParty:                     "client",
					AccessTokenHash:                     "at_hash",
					CodeHash:                            "c_hash",
					StateHash:                           "s_hash",
					Confirmation:                        map[string]any{"jwk": map[string]any{"kty": "EC"}},
					Extra:                               map[string]any{"groups": []any{"admin"}},
				}

				clonetest.AssertDeepCopy(t, c, c.Clone())
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, tc.check)
	}
}
