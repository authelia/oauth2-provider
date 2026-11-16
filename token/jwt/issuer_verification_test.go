// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"
)

func TestDefaultIssuerVerificationOnlyKeys(t *testing.T) {
	issuer := newRotationIssuer(t)

	lookups := map[string]func(ctx context.Context, kid, alg, use string) (*jose.JSONWebKey, error){
		"GetIssuerJWK":             issuer.GetIssuerJWK,
		"GetIssuerStrictJWK":       issuer.GetIssuerStrictJWK,
		"GetIssuerVerificationJWK": issuer.GetIssuerVerificationJWK,
	}

	testCases := []struct {
		name     string
		lookup   string
		kid      string
		alg      string
		use      string
		expected string
		err      string
	}{
		{
			name:     "ShouldReturnIssuingKeyFromJWK",
			lookup:   "GetIssuerJWK",
			kid:      "sig-new",
			alg:      "RS256",
			use:      JSONWebTokenUseSignature,
			expected: "sig-new",
		},
		{
			name:     "ShouldReturnIssuingKeyFromJWKWithoutKeyID",
			lookup:   "GetIssuerJWK",
			alg:      "RS256",
			use:      JSONWebTokenUseSignature,
			expected: "sig-new",
		},
		{
			name:   "ShouldNotReturnVerificationOnlyKeyFromJWK",
			lookup: "GetIssuerJWK",
			kid:    "sig-old",
			alg:    "RS256",
			use:    JSONWebTokenUseSignature,
			err:    "Error occurred retrieving the JSON Web Key. The JSON Web Token uses signing key with kid 'sig-old' which was not found",
		},
		{
			name:   "ShouldNotReturnVerificationOnlyKeyFromJWKByAlgorithm",
			lookup: "GetIssuerJWK",
			alg:    "ES256",
			use:    JSONWebTokenUseSignature,
			err:    "Error occurred retrieving the JSON Web Key. Unable to find JSON web key with kid '', use 'sig', and alg 'ES256' in JSON Web Key Set",
		},
		{
			name:     "ShouldReturnIssuingKeyFromStrictJWKWithoutKeyID",
			lookup:   "GetIssuerStrictJWK",
			alg:      "RS256",
			use:      JSONWebTokenUseSignature,
			expected: "sig-new",
		},
		{
			name:   "ShouldNotReturnVerificationOnlyKeyFromStrictJWK",
			lookup: "GetIssuerStrictJWK",
			kid:    "sig-old",
			alg:    "RS256",
			use:    JSONWebTokenUseSignature,
			err:    "Error occurred retrieving the JSON Web Key. The JSON Web Token uses signing key with kid 'sig-old' which was not found",
		},
		{
			name:   "ShouldNotReturnVerificationOnlyEncryptionKeyFromStrictJWK",
			lookup: "GetIssuerStrictJWK",
			kid:    "enc-old",
			alg:    "RSA-OAEP",
			use:    JSONWebTokenUseEncryption,
			err:    "Error occurred retrieving the JSON Web Key. The JSON Web Token uses signing key with kid 'enc-old' which was not found",
		},
		{
			name:     "ShouldReturnIssuingKeyFromVerificationJWK",
			lookup:   "GetIssuerVerificationJWK",
			kid:      "sig-new",
			alg:      "RS256",
			use:      JSONWebTokenUseSignature,
			expected: "sig-new",
		},
		{
			name:     "ShouldReturnVerificationOnlyKeyFromVerificationJWK",
			lookup:   "GetIssuerVerificationJWK",
			kid:      "sig-old",
			alg:      "RS256",
			use:      JSONWebTokenUseSignature,
			expected: "sig-old",
		},
		{
			name:     "ShouldReturnVerificationOnlyKeyFromVerificationJWKByAlgorithm",
			lookup:   "GetIssuerVerificationJWK",
			alg:      "ES256",
			use:      JSONWebTokenUseSignature,
			expected: "sig-next",
		},
		{
			name:     "ShouldReturnVerificationOnlyEncryptionKeyFromVerificationJWK",
			lookup:   "GetIssuerVerificationJWK",
			kid:      "enc-old",
			alg:      "RSA-OAEP",
			use:      JSONWebTokenUseEncryption,
			expected: "enc-old",
		},
		{
			name:   "ShouldFailVerificationJWKWhenAmbiguous",
			lookup: "GetIssuerVerificationJWK",
			alg:    "RS256",
			use:    JSONWebTokenUseSignature,
			err:    "Error occurred retrieving the JSON Web Key. Unable to find JSON web key with kid '', use 'sig', and alg 'RS256' in JSON Web Key Set",
		},
		{
			name:   "ShouldFailVerificationJWKWhenAlgorithmMismatched",
			lookup: "GetIssuerVerificationJWK",
			kid:    "sig-old",
			alg:    "RS384",
			use:    JSONWebTokenUseSignature,
			err:    "Error occurred retrieving the JSON Web Key. Unable to find JSON web key with kid 'sig-old', use 'sig', and alg 'RS384' in JSON Web Key Set",
		},
		{
			name:   "ShouldFailVerificationJWKWhenUseMismatched",
			lookup: "GetIssuerVerificationJWK",
			kid:    "sig-old",
			alg:    "RS256",
			use:    JSONWebTokenUseEncryption,
			err:    "Error occurred retrieving the JSON Web Key. Unable to find JSON web key with kid 'sig-old', use 'enc', and alg 'RS256' in JSON Web Key Set",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := lookups[tc.lookup](t.Context(), tc.kid, tc.alg, tc.use)

			if tc.err != "" {
				var lookup *JWKLookupError

				require.ErrorAs(t, err, &lookup)
				assert.EqualError(t, err, tc.err)
				assert.Nil(t, key)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, key)
			assert.Equal(t, tc.expected, key.KeyID)
		})
	}
}

func TestDefaultIssuerVerificationOnlyKeysAlgValues(t *testing.T) {
	issuer := newRotationIssuer(t)

	testCases := []struct {
		name       string
		issuer     *DefaultIssuer
		signing    []string
		decryption []string
	}{
		{
			name:       "ShouldExcludeFromSigningAndIncludeInDecryption",
			issuer:     issuer,
			signing:    []string{"RS256"},
			decryption: []string{"RSA-OAEP", "RSA-OAEP-256"},
		},
		{
			name:       "ShouldReplaceTheVerificationOnlyKeys",
			issuer:     issuer.WithVerificationOnlyKeys(),
			signing:    []string{"RS256"},
			decryption: []string{"RSA-OAEP-256"},
		},
		{
			name: "ShouldReturnOnlyDecryptionWithoutIssuingKeys",
			issuer: (*DefaultIssuer)(nil).WithVerificationOnlyKeys(
				jose.JSONWebKey{Key: mustRSAKey(t, 2048), KeyID: "sig", Use: JSONWebTokenUseSignature, Algorithm: "RS256"},
				jose.JSONWebKey{Key: mustRSAKey(t, 2048), KeyID: "enc", Use: JSONWebTokenUseEncryption, Algorithm: "RSA-OAEP"},
			),
			decryption: []string{"RSA-OAEP"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.signing, tc.issuer.GetIssuerSigningAlgValues(t.Context()))
			assert.Equal(t, tc.decryption, tc.issuer.GetIssuerDecryptionAlgValues(t.Context()))
		})
	}

	t.Run("ShouldNotModifyTheReceiver", func(t *testing.T) {
		base := NewDefaultIssuerRS256Unverified(mustRSAKey(t, 2048))

		derived := base.WithVerificationOnlyKeys(jose.JSONWebKey{Key: mustRSAKey(t, 2048), KeyID: "old", Use: JSONWebTokenUseSignature, Algorithm: "RS256"})

		_, err := base.GetIssuerVerificationJWK(t.Context(), "old", "RS256", JSONWebTokenUseSignature)
		assert.Error(t, err)

		_, err = derived.GetIssuerVerificationJWK(t.Context(), "old", "RS256", JSONWebTokenUseSignature)
		assert.NoError(t, err)
	})
}

func TestDefaultIssuerLookupWithoutKeys(t *testing.T) {
	testCases := []struct {
		name   string
		issuer *DefaultIssuer
	}{
		{"ShouldFailWithNilIssuer", nil},
		{"ShouldFailWithZeroValueIssuer", &DefaultIssuer{}},
		{"ShouldFailWithNilSetIssuer", NewDefaultIssuerUnverifiedFromJWKS(nil)},
		{"ShouldFailWithNilIssuerWithoutVerificationOnlyKeys", (*DefaultIssuer)(nil).WithVerificationOnlyKeys()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			lookups := []func(ctx context.Context, kid, alg, use string) (*jose.JSONWebKey, error){
				tc.issuer.GetIssuerJWK,
				tc.issuer.GetIssuerStrictJWK,
				tc.issuer.GetIssuerVerificationJWK,
			}

			for _, lookup := range lookups {
				key, err := lookup(t.Context(), "", "RS256", JSONWebTokenUseSignature)

				var lookupErr *JWKLookupError

				require.ErrorAs(t, err, &lookupErr)
				assert.Nil(t, key)
			}

			assert.Nil(t, tc.issuer.GetIssuerSigningAlgValues(t.Context()))
			assert.Nil(t, tc.issuer.GetIssuerDecryptionAlgValues(t.Context()))
		})
	}
}

func TestDefaultStrategyVerificationOnlyKeys(t *testing.T) {
	issuer := newRotationIssuer(t)

	// The issuer before the rotation, for which the retiring keys are still issuing keys.
	previous := NewDefaultIssuerUnverifiedFromJWKS(issuer.verification)

	signed, _, err := (&DefaultStrategy{Config: &testConfig{}, Issuer: previous}).Encode(t.Context(), MapClaims{ClaimSubject: "peter"}, WithIssuerSigningKeyID("sig-old"))
	require.NoError(t, err)

	old, err := previous.GetIssuerJWK(t.Context(), "enc-old", "RSA-OAEP", JSONWebTokenUseEncryption)
	require.NoError(t, err)

	encrypter, err := jose.NewEncrypter(
		jose.A128GCM,
		jose.Recipient{Algorithm: jose.RSA_OAEP, Key: old.Public().Key, KeyID: "enc-old"},
		(&jose.EncrypterOptions{}).WithContentType(JSONWebTokenTypeJWT).WithType(JSONWebTokenTypeJWT),
	)
	require.NoError(t, err)

	jwe, err := encrypter.Encrypt([]byte(signed))
	require.NoError(t, err)

	encrypted, err := jwe.CompactSerialize()
	require.NoError(t, err)

	strategy := &DefaultStrategy{Config: &testConfig{}, Issuer: issuer}
	fallback := &DefaultStrategy{Config: &testConfig{}, Issuer: struct{ Issuer }{issuer}}

	testCases := []struct {
		name     string
		strategy *DefaultStrategy
		token    string
		err      uint32
	}{
		{"ShouldVerifyWithVerificationOnlyKey", strategy, signed, 0},
		{"ShouldDecryptAndVerifyWithVerificationOnlyKeys", strategy, encrypted, 0},
		{"ShouldNotVerifyWithoutTheOptionalInterface", fallback, signed, ValidationErrorUnverifiable},
		{"ShouldNotDecryptWithoutTheOptionalInterface", fallback, encrypted, ValidationErrorUnverifiable},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token, err := tc.strategy.Decode(t.Context(), tc.token)

			if tc.err != 0 {
				var validation *ValidationError

				require.ErrorAs(t, err, &validation)
				assert.Equal(t, tc.err, validation.Errors)

				return
			}

			require.NoError(t, err)
			assert.True(t, token.IsSignatureValid())
			assert.Equal(t, "sig-old", token.KeyID)
		})
	}

	t.Run("ShouldValidateWithVerificationOnlyKey", func(t *testing.T) {
		token, err := strategy.Decode(t.Context(), signed, WithAllowUnverified())
		require.NoError(t, err)
		require.False(t, token.IsSignatureValid())

		assert.Error(t, fallback.Validate(t.Context(), token))
		assert.NoError(t, strategy.Validate(t.Context(), token))
	})

	t.Run("ShouldVerifyIssuingKeyWithoutTheOptionalInterface", func(t *testing.T) {
		current, _, err := strategy.Encode(t.Context(), MapClaims{ClaimSubject: "peter"})
		require.NoError(t, err)

		token, err := fallback.Decode(t.Context(), current)
		require.NoError(t, err)
		assert.Equal(t, "sig-new", token.KeyID)
	})

	encode := []struct {
		name string
		opts []StrategyOpt
		kid  string
		err  string
	}{
		{
			name: "ShouldEncodeWithIssuingKey",
			kid:  "sig-new",
		},
		{
			name: "ShouldNotEncodeWithVerificationOnlyKeyID",
			opts: []StrategyOpt{WithIssuerSigningKeyID("sig-old")},
			err:  "error occurred retrieving issuer jwk: Error occurred retrieving the JSON Web Key. The JSON Web Token uses signing key with kid 'sig-old' which was not found",
		},
		{
			name: "ShouldNotEncodeWithVerificationOnlyAlgorithm",
			opts: []StrategyOpt{WithIssuerSigningAlg("ES256")},
			err:  "error occurred retrieving issuer jwk: Error occurred retrieving the JSON Web Key. Unable to find JSON web key with kid '', use 'sig', and alg 'ES256' in JSON Web Key Set",
		},
		{
			name: "ShouldNotEncodeWithVerificationOnlyClientKeyID",
			opts: []StrategyOpt{WithClient(&testClient{kid: "sig-old", alg: "RS256"})},
			err:  "error occurred retrieving issuer jwk: Error occurred retrieving the JSON Web Key. The JSON Web Token uses signing key with kid 'sig-old' which was not found",
		},
	}

	for _, tc := range encode {
		t.Run(tc.name, func(t *testing.T) {
			tokenString, _, err := strategy.Encode(t.Context(), MapClaims{ClaimSubject: "peter"}, tc.opts...)

			if tc.err != "" {
				assert.EqualError(t, err, tc.err)

				return
			}

			require.NoError(t, err)

			token, err := strategy.Decode(t.Context(), tokenString)
			require.NoError(t, err)
			assert.Equal(t, tc.kid, token.KeyID)
		})
	}
}

func TestDefaultStrategyIssuerSigningJWK(t *testing.T) {
	strategy := &DefaultStrategy{Config: &testConfig{}, Issuer: newRotationIssuer(t)}

	testCases := []struct {
		name     string
		strategy *DefaultStrategy
		kid      string
		alg      string
		err      string
	}{
		{
			name:     "ShouldReturnIssuingKey",
			strategy: strategy,
			kid:      "sig-new",
			alg:      "RS256",
		},
		{
			name:     "ShouldFailWithUnknownKeyID",
			strategy: strategy,
			kid:      "missing",
			alg:      "RS256",
			err:      "Error occurred retrieving the JSON Web Key. The JSON Web Token uses signing key with kid 'missing' which was not found",
		},
		{
			name:     "ShouldFailWithMismatchedAlgorithm",
			strategy: strategy,
			kid:      "sig-new",
			alg:      "RS384",
			err:      "Error occurred retrieving the JSON Web Key. Unable to find JSON web key with kid 'sig-new', use 'sig', and alg 'RS384' in JSON Web Key Set",
		},
		{
			name:     "ShouldFailWithEncryptionKey",
			strategy: strategy,
			kid:      "enc-new",
			alg:      "RSA-OAEP-256",
			err:      "Error occurred retrieving the JSON Web Key. Unable to find JSON web key with kid 'enc-new', use 'sig', and alg 'RSA-OAEP-256' in JSON Web Key Set",
		},
		{
			name:     "ShouldFailWithVerificationOnlyKey",
			strategy: strategy,
			kid:      "sig-old",
			alg:      "RS256",
			err:      "Error occurred retrieving the JSON Web Key. The JSON Web Token uses signing key with kid 'sig-old' which was not found",
		},
		{
			name:     "ShouldFailWithoutAnIssuer",
			strategy: &DefaultStrategy{Config: &testConfig{}},
			kid:      "sig-new",
			alg:      "RS256",
			err:      "no issuer is configured",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var provider IssuerSigningJWKProvider = tc.strategy

			key, err := provider.IssuerSigningJWK(t.Context(), tc.kid, tc.alg)

			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
				assert.Nil(t, key)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.kid, key.KeyID)
		})
	}
}

func newRotationIssuer(t *testing.T) *DefaultIssuer {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuer := NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: mustRSAKey(t, 2048), KeyID: "sig-new", Use: JSONWebTokenUseSignature, Algorithm: string(jose.RS256)},
		{Key: mustRSAKey(t, 2048), KeyID: "enc-new", Use: JSONWebTokenUseEncryption, Algorithm: string(jose.RSA_OAEP_256)},
	}})

	return issuer.WithVerificationOnlyKeys(
		jose.JSONWebKey{Key: mustRSAKey(t, 2048), KeyID: "sig-old", Use: JSONWebTokenUseSignature, Algorithm: string(jose.RS256)},
		jose.JSONWebKey{Key: key, KeyID: "sig-next", Use: JSONWebTokenUseSignature, Algorithm: string(jose.ES256)},
		jose.JSONWebKey{Key: mustRSAKey(t, 2048), KeyID: "enc-old", Use: JSONWebTokenUseEncryption, Algorithm: string(jose.RSA_OAEP)},
	)
}
