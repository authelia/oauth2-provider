// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"
)

func TestDefaultStrategyDecodeClientSecretAlgorithmWithKeyID(t *testing.T) {
	secret := []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoob")

	strategy := &DefaultStrategy{
		Config: &testConfig{},
		Issuer: NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{}),
	}

	testCases := []struct {
		name string
		alg  jose.SignatureAlgorithm
	}{
		{"ShouldReturnTokenForHS256", jose.HS256},
		{"ShouldReturnTokenForHS384", jose.HS384},
		{"ShouldReturnTokenForHS512", jose.HS512},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token := NewWithClaims(tc.alg, MapClaims{
				ClaimIssuer:         "client-id",
				ClaimSubject:        "client-id",
				ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
			})

			token.Header[JSONWebTokenHeaderKeyIdentifier] = "abc"

			signed, err := token.CompactSignedString(secret)
			require.NoError(t, err)

			decoded, err := strategy.Decode(t.Context(), signed, WithClient(&testClient{id: "client-id", secret: secret, csigned: true, alg: string(tc.alg)}))

			var verr *ValidationError

			require.ErrorAs(t, err, &verr)
			assert.True(t, verr.Has(ValidationErrorHeaderKeyIDInvalid))

			require.NotNil(t, decoded)
			assert.Equal(t, "abc", decoded.KeyID)
			assert.Error(t, decoded.Valid())
		})
	}
}
