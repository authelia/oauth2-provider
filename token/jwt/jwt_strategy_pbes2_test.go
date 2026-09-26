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
