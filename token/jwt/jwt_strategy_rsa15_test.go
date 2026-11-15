// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"
)

func TestRSA15KeyManagement(t *testing.T) {
	f := getAlgorithmFixtures(t)

	claims := MapClaims{ClaimSubject: "rsa15-subject"}

	disabled := &DefaultStrategy{Config: &testConfig{}, Issuer: f.strategy.Issuer}
	enabled := f.strategy

	client := func() *testClient {
		return f.client(jose.ES256, jose.RSA1_5, encKID(jose.RSA1_5, ""), jose.A128GCM)
	}

	t.Run("ShouldNotPermitRSA15ByDefault", func(t *testing.T) {
		ctx := context.Background()

		assert.False(t, IsKeyAlgorithmPermitted(ctx, &testConfig{}, string(jose.RSA1_5)))
		assert.False(t, IsKeyAlgorithmPermitted(ctx, nil, string(jose.RSA1_5)))
		assert.True(t, IsKeyAlgorithmPermitted(ctx, &testConfig{}, string(jose.RSA_OAEP_256)))
		assert.Equal(t, EncryptionKeyAlgorithms, GetEncryptionKeyAlgorithms(ctx, &testConfig{}))
		assert.NotContains(t, EncryptionKeyAlgorithms, jose.RSA1_5)
		assert.Equal(t, []string{string(jose.RSA_OAEP)}, FilterKeyAlgorithms(ctx, &testConfig{}, []string{string(jose.RSA1_5), string(jose.RSA_OAEP)}))
	})

	t.Run("ShouldPermitRSA15WhenEnabled", func(t *testing.T) {
		ctx := context.Background()

		assert.True(t, IsKeyAlgorithmPermitted(ctx, &rsa15TestConfig{}, string(jose.RSA1_5)))
		assert.Equal(t, append([]jose.KeyAlgorithm{jose.RSA1_5}, EncryptionKeyAlgorithms...), GetEncryptionKeyAlgorithms(ctx, &rsa15TestConfig{}))
		assert.Equal(t, []string{string(jose.RSA1_5), string(jose.RSA_OAEP)}, FilterKeyAlgorithms(ctx, &rsa15TestConfig{}, []string{string(jose.RSA1_5), string(jose.RSA_OAEP)}))
	})

	t.Run("ShouldNotEncryptByDefault", func(t *testing.T) {
		_, _, err := disabled.Encode(t.Context(), claims, WithClient(client()))
		require.ErrorContains(t, err, "the JWE key management algorithm 'RSA1_5' is not permitted")
	})

	t.Run("ShouldEncryptAndDecryptWhenEnabled", func(t *testing.T) {
		tokenString, _, err := enabled.Encode(t.Context(), claims, WithClient(client()))
		require.NoError(t, err)

		assertJWEStructure(t, tokenString, jose.RSA1_5, encKID(jose.RSA1_5, ""), jose.A128GCM)

		_, _, jwe, err := enabled.Decrypt(t.Context(), tokenString, WithClient(client()))
		require.NoError(t, err)
		assert.Equal(t, string(jose.RSA1_5), jwe.Header.Algorithm)

		token, err := enabled.Decode(t.Context(), tokenString, WithClient(client()))
		require.NoError(t, err)
		assert.Equal(t, jose.RSA1_5, token.KeyAlgorithm)
	})

	t.Run("ShouldNotDecryptByDefault", func(t *testing.T) {
		tokenString, _, err := enabled.Encode(t.Context(), claims, WithClient(client()))
		require.NoError(t, err)

		_, _, _, err = disabled.Decrypt(t.Context(), tokenString, WithClient(client()))
		assertValidationError(t, err, ValidationErrorMalformed)

		_, _, _, err = disabled.Decrypt(t.Context(), tokenString, WithClient(client()), WithKeyAlgorithm(jose.RSA1_5))
		assertValidationError(t, err, ValidationErrorMalformed)

		_, err = disabled.Decode(t.Context(), tokenString, WithClient(client()))
		assertValidationError(t, err, ValidationErrorMalformed)
	})
}

type rsa15TestConfig struct {
	testConfig
}

func (*rsa15TestConfig) GetEnableRSA15KeyManagement(_ context.Context) bool {
	return true
}

func allEncryptionKeyAlgorithms() []jose.KeyAlgorithm {
	return GetEncryptionKeyAlgorithms(context.Background(), &rsa15TestConfig{})
}
