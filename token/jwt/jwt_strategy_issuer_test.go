// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"
)

func TestDefaultStrategyWithoutAnIssuer(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: &jose.JSONWebKey{Key: key, KeyID: "x"}},
		(&jose.SignerOptions{}).WithType(JSONWebTokenTypeJWT),
	)
	require.NoError(t, err)

	signed, err := signer.Sign([]byte(`{"sub":"peter"}`))
	require.NoError(t, err)

	jws, err := signed.CompactSerialize()
	require.NoError(t, err)

	encrypter, err := jose.NewEncrypter(
		jose.A128GCM,
		jose.Recipient{Algorithm: jose.RSA_OAEP_256, Key: &key.PublicKey, KeyID: "x"},
		(&jose.EncrypterOptions{}).WithContentType(JSONWebTokenTypeJWT).WithType(JSONWebTokenTypeJWT),
	)
	require.NoError(t, err)

	encrypted, err := encrypter.Encrypt([]byte(jws))
	require.NoError(t, err)

	jwe, err := encrypted.CompactSerialize()
	require.NoError(t, err)

	strategy := &DefaultStrategy{}

	t.Run("ShouldFailToDecryptAJWE", func(t *testing.T) {
		_, _, _, err := strategy.Decrypt(t.Context(), jwe)

		var validation *ValidationError

		require.ErrorAs(t, err, &validation)
		assert.Equal(t, ValidationErrorUnverifiable, validation.Errors)
	})

	t.Run("ShouldFailToDecodeAJWE", func(t *testing.T) {
		_, err := strategy.Decode(t.Context(), jwe)

		var validation *ValidationError

		require.ErrorAs(t, err, &validation)
		assert.Equal(t, ValidationErrorUnverifiable, validation.Errors)
	})

	t.Run("ShouldFailToDecodeAJWS", func(t *testing.T) {
		_, err := strategy.Decode(t.Context(), jws)

		var validation *ValidationError

		require.ErrorAs(t, err, &validation)
		assert.Equal(t, ValidationErrorUnverifiable, validation.Errors)
	})

	t.Run("ShouldFailToEncode", func(t *testing.T) {
		_, _, err := strategy.Encode(t.Context(), MapClaims{"sub": "peter"})

		assert.ErrorContains(t, err, "no issuer is configured")
	})
}
