// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"
)

func TestDefaultIssuerSigningAlgValues(t *testing.T) {
	rsaKey := mustRSAKey(t, 2048)

	testCases := []struct {
		name     string
		keys     []jose.JSONWebKey
		expected []string
	}{
		{
			"ShouldReturnSortedUniqueSigningAlgorithms",
			[]jose.JSONWebKey{
				{Key: rsaKey, KeyID: "a", Use: JSONWebTokenUseSignature, Algorithm: string(jose.RS256)},
				{Key: rsaKey, KeyID: "b", Use: JSONWebTokenUseSignature, Algorithm: string(jose.ES256)},
				{Key: rsaKey, KeyID: "c", Use: JSONWebTokenUseEncryption, Algorithm: string(jose.RSA_OAEP)},
				{Key: rsaKey, KeyID: "d", Use: JSONWebTokenUseSignature, Algorithm: string(jose.RS256)},
			},
			[]string{"ES256", "RS256"},
		},
		{
			"ShouldExcludeKeysWithoutUseAndNone",
			[]jose.JSONWebKey{
				{Key: rsaKey, KeyID: "a", Algorithm: string(jose.PS256)},
				{Key: rsaKey, KeyID: "b", Use: JSONWebTokenUseSignature, Algorithm: "none"},
				{Key: rsaKey, KeyID: "c", Use: JSONWebTokenUseSignature, Algorithm: string(jose.RS384)},
			},
			[]string{"RS384"},
		},
		{
			"ShouldReturnNilForEmptySet",
			nil,
			nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			issuer := &DefaultIssuer{jwks: &jose.JSONWebKeySet{Keys: tc.keys}}

			assert.Equal(t, tc.expected, issuer.GetIssuerSigningAlgValues(t.Context()))
		})
	}
}

func TestDefaultStrategySigningAlgValues(t *testing.T) {
	rsaKey := mustRSAKey(t, 2048)

	issuer, err := NewDefaultIssuer(jose.JSONWebKey{Key: rsaKey, KeyID: "a", Use: JSONWebTokenUseSignature, Algorithm: string(jose.RS256)})
	require.NoError(t, err)

	assert.Equal(t, []string{"RS256"}, (&DefaultStrategy{Issuer: issuer}).SigningAlgValues(t.Context()))
	assert.Nil(t, (&DefaultStrategy{}).SigningAlgValues(t.Context()))
}
