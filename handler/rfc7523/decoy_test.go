// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7523

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"
	"authelia.com/provider/jose/jwt"
)

func TestDecoyKeyReachesSignatureVerification(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	secret := []byte("a-secret-that-is-long-enough-for-every-hmac-algorithm-in-use-here")

	keys := map[jose.SignatureAlgorithm]any{
		jose.RS256: jwtBearerKey,
		jose.RS384: jwtBearerKey,
		jose.RS512: jwtBearerKey,
		jose.PS256: jwtBearerKey,
		jose.PS384: jwtBearerKey,
		jose.PS512: jwtBearerKey,
		jose.ES256: p256,
		jose.ES384: p384,
		jose.ES512: p521,
		jose.HS256: secret,
		jose.HS384: secret,
		jose.HS512: secret,
	}

	for _, alg := range assertionAlgorithms {
		t.Run(string(alg), func(t *testing.T) {
			key, ok := keys[alg]
			require.True(t, ok)

			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, nil)
			require.NoError(t, err)

			raw, err := jwt.Signed(signer).Claims(jwt.Claims{Issuer: "trusted_issuer", Subject: "some_ro"}).Serialize()
			require.NoError(t, err)

			token, err := jwt.ParseSigned(raw, assertionAlgorithms)
			require.NoError(t, err)

			decoy := decoyKey(alg)
			require.NotNil(t, decoy)

			assert.ErrorIs(t, token.Claims(decoy, &jwt.Claims{}), jose.ErrCryptoFailure)
			assert.NotPanics(t, func() { verifyDecoy(token) })
		})
	}
}

func TestDecoyKeyIgnoresUnknownAlgorithms(t *testing.T) {
	assert.Nil(t, decoyKey(jose.EdDSA))
	assert.NotPanics(t, func() { verifyDecoy(&jwt.JSONWebToken{}) })
}
