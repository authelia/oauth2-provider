// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"
)

func TestSearchJWKSOptionalMembers(t *testing.T) {
	rsaKey := &mustRSAKey(t, 2048).PublicKey
	ecKey := func(curve elliptic.Curve) *ecdsa.PublicKey {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)

		return &key.PublicKey
	}
	edKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	p256 := ecKey(elliptic.P256())

	testCases := []struct {
		name     string
		keys     []jose.JSONWebKey
		alg      string
		use      string
		strict   bool
		expected string
	}{
		{name: "ShouldMatchABareRSAKeyForRS256", keys: []jose.JSONWebKey{{KeyID: "a", Key: rsaKey}}, alg: "RS256", use: "sig", expected: "a"},
		{name: "ShouldMatchABareRSAKeyForPS512", keys: []jose.JSONWebKey{{KeyID: "a", Key: rsaKey}}, alg: "PS512", use: "sig", expected: "a"},
		{name: "ShouldMatchABareRSAKeyForEncryption", keys: []jose.JSONWebKey{{KeyID: "a", Key: rsaKey}}, alg: "RSA-OAEP-256", use: "enc", expected: "a"},
		{name: "ShouldMatchABareP256KeyForES256", keys: []jose.JSONWebKey{{KeyID: "a", Key: p256}}, alg: "ES256", use: "sig", expected: "a"},
		{name: "ShouldMatchABareP384KeyForES384", keys: []jose.JSONWebKey{{KeyID: "a", Key: ecKey(elliptic.P384())}}, alg: "ES384", use: "sig", expected: "a"},
		{name: "ShouldMatchABareP521KeyForES512", keys: []jose.JSONWebKey{{KeyID: "a", Key: ecKey(elliptic.P521())}}, alg: "ES512", use: "sig", expected: "a"},
		{name: "ShouldMatchABareECKeyForEncryption", keys: []jose.JSONWebKey{{KeyID: "a", Key: p256}}, alg: "ECDH-ES", use: "enc", expected: "a"},
		{name: "ShouldMatchABareEd25519KeyForEdDSA", keys: []jose.JSONWebKey{{KeyID: "a", Key: edKey}}, alg: "EdDSA", use: "sig", expected: "a"},
		{name: "ShouldMatchAKeyWithOnlyUse", keys: []jose.JSONWebKey{{KeyID: "a", Use: "sig", Key: p256}}, alg: "ES256", use: "sig", expected: "a"},
		{name: "ShouldMatchAKeyWithOnlyAlg", keys: []jose.JSONWebKey{{KeyID: "a", Algorithm: "ES256", Key: p256}}, alg: "ES256", use: "sig", expected: "a"},
		{name: "ShouldPreferAKeyNamingBothMembers", keys: []jose.JSONWebKey{{KeyID: "a", Key: p256}, {KeyID: "b", Use: "sig", Algorithm: "ES256", Key: p256}}, alg: "ES256", use: "sig", strict: true, expected: "b"},
		{name: "ShouldMatchTheFirstOfSeveralBareKeys", keys: []jose.JSONWebKey{{KeyID: "a", Key: p256}, {KeyID: "b", Key: p256}}, alg: "ES256", use: "sig", expected: "a"},
		{name: "ShouldRejectSeveralBareKeysWhenStrict", keys: []jose.JSONWebKey{{KeyID: "a", Key: p256}, {KeyID: "b", Key: p256}}, alg: "ES256", use: "sig", strict: true},
		{name: "ShouldRejectARSAKeyForHS256", keys: []jose.JSONWebKey{{KeyID: "a", Key: rsaKey}}, alg: "HS256", use: "sig"},
		{name: "ShouldRejectASymmetricKeyForHS256", keys: []jose.JSONWebKey{{KeyID: "a", Key: []byte("secret")}}, alg: "HS256", use: "sig"},
		{name: "ShouldRejectARSAKeyForES256", keys: []jose.JSONWebKey{{KeyID: "a", Key: rsaKey}}, alg: "ES256", use: "sig"},
		{name: "ShouldRejectAP256KeyForES384", keys: []jose.JSONWebKey{{KeyID: "a", Key: p256}}, alg: "ES384", use: "sig"},
		{name: "ShouldRejectAnECKeyForRS256", keys: []jose.JSONWebKey{{KeyID: "a", Key: p256}}, alg: "RS256", use: "sig"},
		{name: "ShouldRejectAnEd25519KeyForES256", keys: []jose.JSONWebKey{{KeyID: "a", Key: edKey}}, alg: "ES256", use: "sig"},
		{name: "ShouldRejectASignatureAlgForEncryption", keys: []jose.JSONWebKey{{KeyID: "a", Key: rsaKey}}, alg: "RS256", use: "enc"},
		{name: "ShouldRejectAnEncryptionAlgForSignature", keys: []jose.JSONWebKey{{KeyID: "a", Key: rsaKey}}, alg: "RSA-OAEP", use: "sig"},
		{name: "ShouldRejectADifferentUse", keys: []jose.JSONWebKey{{KeyID: "a", Use: "enc", Key: p256}}, alg: "ES256", use: "sig"},
		{name: "ShouldRejectADifferentAlg", keys: []jose.JSONWebKey{{KeyID: "a", Algorithm: "ES384", Key: p256}}, alg: "ES256", use: "sig"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := SearchJWKS(&jose.JSONWebKeySet{Keys: tc.keys}, "", tc.alg, tc.use, tc.strict)

			if tc.expected == "" {
				assert.Error(t, err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, key.KeyID)
		})
	}

	t.Run("ShouldReturnABareKeyWithTheAlgAndUse", func(t *testing.T) {
		jwks := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{KeyID: "a", Key: rsaKey}}}

		key, err := SearchJWKS(jwks, "", "RSA-OAEP-256", "enc", false)

		require.NoError(t, err)
		assert.Equal(t, "RSA-OAEP-256", key.Algorithm)
		assert.Equal(t, "enc", key.Use)
		assert.Empty(t, jwks.Keys[0].Algorithm)
		assert.Empty(t, jwks.Keys[0].Use)
	})

	t.Run("ShouldEncryptToABareKey", func(t *testing.T) {
		keyEnc, err := SearchJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{KeyID: "a", Key: rsaKey}}}, "", "RSA-OAEP-256", "enc", false)
		require.NoError(t, err)

		keySig := &jose.JSONWebKey{KeyID: "s", Use: "sig", Algorithm: "RS256", Key: mustRSAKey(t, 2048)}

		_, _, err = EncodeNestedCompactEncrypted(context.Background(), MapClaims{"sub": "peter"}, &Headers{}, &Headers{}, keySig, keyEnc, jose.A128CBC_HS256)

		assert.NoError(t, err)
	})

	t.Run("ShouldNotUseABareKeyOfTheIssuer", func(t *testing.T) {
		issuer := NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{KeyID: "a", Key: rsaKey}}})

		_, err := issuer.GetIssuerJWK(context.Background(), "", "RS256", "sig")
		assert.Error(t, err)

		_, err = issuer.GetIssuerStrictJWK(context.Background(), "", "RS256", "sig")
		assert.Error(t, err)
	})
}
