// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustRSAKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)

	return key
}

func TestNewDefaultIssuer(t *testing.T) {
	rsaKey := mustRSAKey(t, 2048)

	sigRS256 := jose.JSONWebKey{
		Key:       rsaKey,
		KeyID:     "rs256-sig",
		Use:       JSONWebTokenUseSignature,
		Algorithm: string(jose.RS256),
	}

	sigRS384 := jose.JSONWebKey{
		Key:       rsaKey,
		KeyID:     "rs384-sig",
		Use:       JSONWebTokenUseSignature,
		Algorithm: string(jose.RS384),
	}

	encRS256 := jose.JSONWebKey{
		Key:       rsaKey,
		KeyID:     "rs256-enc",
		Use:       JSONWebTokenUseEncryption,
		Algorithm: string(jose.RS256),
	}

	testCases := []struct {
		name    string
		keys    []jose.JSONWebKey
		wantErr string
	}{
		{
			name: "ShouldSucceedWithRS256SigKey",
			keys: []jose.JSONWebKey{sigRS256},
		},
		{
			name: "ShouldSucceedWithRS256AmongOthers",
			keys: []jose.JSONWebKey{sigRS384, sigRS256, encRS256},
		},
		{
			name:    "ShouldFailWithoutAnyKeys",
			keys:    nil,
			wantErr: "no RS256 signature algorithm found",
		},
		{
			name:    "ShouldFailWithOnlyEncryptionRS256",
			keys:    []jose.JSONWebKey{encRS256},
			wantErr: "no RS256 signature algorithm found",
		},
		{
			name:    "ShouldFailWithOnlySigButNotRS256",
			keys:    []jose.JSONWebKey{sigRS384},
			wantErr: "no RS256 signature algorithm found",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			issuer, err := NewDefaultIssuer(tc.keys...)

			if tc.wantErr != "" {
				require.Error(t, err)
				assert.EqualError(t, err, tc.wantErr)
				assert.Nil(t, issuer)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, issuer)
		})
	}
}

func TestNewDefaultIssuerFromJWKS(t *testing.T) {
	rsaKey := mustRSAKey(t, 2048)

	rs256Sig := jose.JSONWebKey{
		Key:       rsaKey,
		KeyID:     "rs256-sig",
		Use:       JSONWebTokenUseSignature,
		Algorithm: string(jose.RS256),
	}

	testCases := []struct {
		name    string
		jwks    *jose.JSONWebKeySet
		wantErr string
	}{
		{
			name: "ShouldSucceedWithRS256Sig",
			jwks: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{rs256Sig}},
		},
		{
			name:    "ShouldFailWithEmptyJWKS",
			jwks:    &jose.JSONWebKeySet{},
			wantErr: "no RS256 signature algorithm found",
		},
		{
			name: "ShouldFailWhenAllKeysAreEncryption",
			jwks: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
				{
					Key:       rsaKey,
					KeyID:     "rs256-enc",
					Use:       JSONWebTokenUseEncryption,
					Algorithm: string(jose.RS256),
				},
			}},
			wantErr: "no RS256 signature algorithm found",
		},
		{
			name: "ShouldFailWhenAllSigKeysAreNotRS256",
			jwks: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
				{
					Key:       rsaKey,
					KeyID:     "rs384-sig",
					Use:       JSONWebTokenUseSignature,
					Algorithm: string(jose.RS384),
				},
			}},
			wantErr: "no RS256 signature algorithm found",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			issuer, err := NewDefaultIssuerFromJWKS(tc.jwks)

			if tc.wantErr != "" {
				require.Error(t, err)
				assert.EqualError(t, err, tc.wantErr)
				assert.Nil(t, issuer)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, issuer)
		})
	}
}

func TestNewDefaultIssuerUnverifiedFromJWKS(t *testing.T) {
	jwks := &jose.JSONWebKeySet{}
	issuer := NewDefaultIssuerUnverifiedFromJWKS(jwks)

	require.NotNil(t, issuer)
	assert.Same(t, jwks, issuer.jwks)
}

func TestNewDefaultIssuerRS256(t *testing.T) {
	rsaKey := mustRSAKey(t, 2048)
	smallRSAKey := mustRSAKey(t, 1024)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	testCases := []struct {
		name    string
		key     any
		wantErr string
	}{
		{
			name: "ShouldSucceedWith2048BitRSAKey",
			key:  rsaKey,
		},
		{
			name:    "ShouldFailWithSmallRSAKey",
			key:     smallRSAKey,
			wantErr: "key must be an *rsa.PrivateKey with at least 2048 bits but got 1024",
		},
		{
			name:    "ShouldFailWithNonRSAKey",
			key:     ecKey,
			wantErr: "key must be an *rsa.PrivateKey but got *ecdsa.PrivateKey",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			issuer, err := NewDefaultIssuerRS256(tc.key)

			if tc.wantErr != "" {
				require.Error(t, err)
				assert.EqualError(t, err, tc.wantErr)
				assert.Nil(t, issuer)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, issuer)
			require.Len(t, issuer.jwks.Keys, 1)
			assert.Equal(t, "default", issuer.jwks.Keys[0].KeyID)
			assert.Equal(t, string(jose.RS256), issuer.jwks.Keys[0].Algorithm)
			assert.Equal(t, JSONWebTokenUseSignature, issuer.jwks.Keys[0].Use)
		})
	}
}

func TestNewDefaultIssuerRS256Unverified(t *testing.T) {
	rsaKey := mustRSAKey(t, 2048)

	issuer := NewDefaultIssuerRS256Unverified(rsaKey)
	require.NotNil(t, issuer)
	require.Len(t, issuer.jwks.Keys, 1)
	assert.Equal(t, rsaKey, issuer.jwks.Keys[0].Key)
	assert.Equal(t, "default", issuer.jwks.Keys[0].KeyID)
	assert.Equal(t, string(jose.RS256), issuer.jwks.Keys[0].Algorithm)
	assert.Equal(t, JSONWebTokenUseSignature, issuer.jwks.Keys[0].Use)
}

func TestMustNewDefaultIssuerRS256(t *testing.T) {
	t.Run("ShouldReturnIssuerForValidKey", func(t *testing.T) {
		issuer := MustNewDefaultIssuerRS256(mustRSAKey(t, 2048))
		require.NotNil(t, issuer)
	})

	t.Run("ShouldPanicForInvalidKey", func(t *testing.T) {
		assert.Panics(t, func() {
			MustNewDefaultIssuerRS256("not-a-key")
		})
	})
}

func TestGenDefaultIssuer(t *testing.T) {
	issuer, err := GenDefaultIssuer()
	require.NoError(t, err)
	require.NotNil(t, issuer)
	require.Len(t, issuer.jwks.Keys, 1)
	assert.Equal(t, string(jose.RS256), issuer.jwks.Keys[0].Algorithm)
}

func TestMustGenDefaultIssuer(t *testing.T) {
	issuer := MustGenDefaultIssuer()
	require.NotNil(t, issuer)
}

func TestDefaultIssuer_GetIssuerJWK(t *testing.T) {
	rsaKey := mustRSAKey(t, 2048)
	jwks := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{
			Key:       rsaKey,
			KeyID:     "kid-1",
			Use:       JSONWebTokenUseSignature,
			Algorithm: string(jose.RS256),
		},
	}}

	issuer := NewDefaultIssuerUnverifiedFromJWKS(jwks)

	t.Run("ShouldFindByExactMatch", func(t *testing.T) {
		jwk, err := issuer.GetIssuerJWK(t.Context(), "kid-1", string(jose.RS256), JSONWebTokenUseSignature)
		require.NoError(t, err)
		require.NotNil(t, jwk)
		assert.Equal(t, "kid-1", jwk.KeyID)
	})

	t.Run("ShouldFindStrictByExactMatch", func(t *testing.T) {
		jwk, err := issuer.GetIssuerStrictJWK(t.Context(), "kid-1", string(jose.RS256), JSONWebTokenUseSignature)
		require.NoError(t, err)
		require.NotNil(t, jwk)
		assert.Equal(t, "kid-1", jwk.KeyID)
	})

	t.Run("ShouldErrorWhenStrictMissing", func(t *testing.T) {
		_, err := issuer.GetIssuerStrictJWK(t.Context(), "unknown-kid", string(jose.RS256), JSONWebTokenUseSignature)
		require.Error(t, err)
	})
}
