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

func TestDefaultStrategyDecryptPasswordBasedAlgorithmRegistration(t *testing.T) {
	secret := []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoob")

	strategy := &DefaultStrategy{
		Config: &testConfig{},
		Issuer: NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{}),
	}

	encrypting := &testClient{id: "client-id", alg: string(jose.HS256), csigned: true, secret: secret, encAlg: string(jose.PBES2_HS256_A128KW), enc: string(jose.A256GCM)}

	token, _, err := strategy.Encode(t.Context(), MapClaims{ClaimIssuer: "client-id"}, WithHeaders(&Headers{Extra: map[string]any{JSONWebTokenHeaderType: JSONWebTokenTypeJWT}}), WithHeadersJWE(&Headers{}), WithClient(encrypting))
	require.NoError(t, err)
	require.True(t, IsEncryptedJWT(token))

	testCases := []struct {
		name   string
		encAlg string
		err    string
	}{
		{"ShouldDecryptWhenRegistered", string(jose.PBES2_HS256_A128KW), ""},
		{"ShouldRejectWhenNotRegistered", "", "jwe header 'alg' value 'PBES2-HS256+A128KW' is a password based algorithm the client has not registered"},
		{"ShouldRejectWhenAnotherAlgorithmIsRegistered", string(jose.A256KW), "jwe header 'alg' value 'PBES2-HS256+A128KW' is a password based algorithm the client has not registered"},
		{"ShouldRejectWhenAnotherPasswordBasedAlgorithmIsRegistered", string(jose.PBES2_HS512_A256KW), "jwe header 'alg' value 'PBES2-HS256+A128KW' is a password based algorithm the client has not registered"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := &testClient{id: "client-id", alg: string(jose.HS256), csigned: true, secret: secret, encAlg: tc.encAlg, enc: string(jose.A256GCM)}

			_, _, _, err = strategy.Decrypt(t.Context(), token, WithClient(client))

			if tc.err == "" {
				assert.NoError(t, err)

				return
			}

			var verr *ValidationError

			require.ErrorAs(t, err, &verr)
			assert.True(t, verr.Has(ValidationErrorUnverifiable))
			assert.EqualError(t, verr.Inner, tc.err)
		})
	}
}

func TestDefaultStrategyDecryptPasswordBasedCountBounds(t *testing.T) {
	secret := []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoob")

	testCases := []struct {
		name   string
		config StrategyConfig
		count  int
		err    string
	}{
		{"ShouldAcceptDefaultMaximum", &testConfig{}, DefaultJWEPBES2CountMaximum, ""},
		{"ShouldRejectAboveDefaultMaximum", &testConfig{}, DefaultJWEPBES2CountMaximum + 1, "jwe header 'p2c' has an invalid value '600001': more than 600000"},
		{"ShouldRejectBelowDefaultMinimum", &testConfig{}, DefaultJWEPBES2CountMinimum - 1, "jwe header 'p2c' has an invalid value '199999': less than 200000"},
		{"ShouldUseDefaultsWhenUnset", &testPBES2CountConfig{}, DefaultJWEPBES2CountMaximum + 1, "jwe header 'p2c' has an invalid value '600001': more than 600000"},
		{"ShouldAcceptWithinConfiguredBounds", &testPBES2CountConfig{minimum: 1000, maximum: 300000}, 1000, ""},
		{"ShouldRejectAboveConfiguredMaximum", &testPBES2CountConfig{minimum: 1000, maximum: 300000}, 300001, "jwe header 'p2c' has an invalid value '300001': more than 300000"},
		{"ShouldRejectBelowConfiguredMinimum", &testPBES2CountConfig{minimum: 250000, maximum: 300000}, 249999, "jwe header 'p2c' has an invalid value '249999': less than 250000"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			strategy := &DefaultStrategy{
				Config: tc.config,
				Issuer: NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{}),
			}

			client := &testClient{id: "client-id", alg: string(jose.HS256), csigned: true, secret: secret, encAlg: string(jose.PBES2_HS256_A128KW), enc: string(jose.A256GCM)}

			_, _, _, err := strategy.Decrypt(t.Context(), testPBES2Token(t, secret, tc.count), WithClient(client))

			if tc.err == "" {
				assert.NoError(t, err)

				return
			}

			var verr *ValidationError

			require.ErrorAs(t, err, &verr)
			assert.True(t, verr.Has(ValidationErrorMalformed))
			assert.EqualError(t, verr.Inner, tc.err)
		})
	}
}

type testPBES2CountConfig struct {
	testConfig

	minimum, maximum int
}

func (c *testPBES2CountConfig) GetJWEPBES2CountMinimum(_ context.Context) int {
	return c.minimum
}

func (c *testPBES2CountConfig) GetJWEPBES2CountMaximum(_ context.Context) int {
	return c.maximum
}

func testPBES2Token(t *testing.T, secret []byte, count int) string {
	t.Helper()

	key, err := NewClientSecretJWK(t.Context(), secret, "", string(jose.PBES2_HS256_A128KW), string(jose.A256GCM), JSONWebTokenUseEncryption)
	require.NoError(t, err)

	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.PBES2_HS256_A128KW, Key: key.Key, PBES2Count: count}, (&jose.EncrypterOptions{}).WithContentType(JSONWebTokenTypeJWT).WithType(JSONWebTokenTypeJWT))
	require.NoError(t, err)

	object, err := encrypter.Encrypt([]byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJjbGllbnQtaWQifQ.c2lnbmF0dXJl"))
	require.NoError(t, err)

	token, err := object.CompactSerialize()
	require.NoError(t, err)

	return token
}
