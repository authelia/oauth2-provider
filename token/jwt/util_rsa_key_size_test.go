// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"crypto/rsa"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"
)

func TestValidateRSAKeyMaximumSize(t *testing.T) {
	testCases := []struct {
		name     string
		key      any
		expected string
	}{
		{name: "ShouldAcceptTheMaximumSize", key: rsaPublicKeyOfSize(RSAMaximumKeySize)},
		{name: "ShouldRejectAKeyOverTheMaximumSize", key: rsaPublicKeyOfSize(RSAMaximumKeySize + 1), expected: "the JSON Web Key is a 16385 bit RSA key but keys of at most 16384 bits are permitted"},
		{name: "ShouldIgnoreASymmetricKey", key: make([]byte, 4096)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRSAKeyMaximumSize(&jose.JSONWebKey{Key: tc.key})

			if tc.expected == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expected)
			}
		})
	}
}

func TestFindClientPublicJWKRejectsAnOversizedRSAKey(t *testing.T) {
	jwks := func(bits int) *jose.JSONWebKeySet {
		return &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{KeyID: "a", Use: JSONWebTokenUseSignature, Algorithm: string(jose.RS256), Key: rsaPublicKeyOfSize(bits)}}}
	}

	testCases := []struct {
		name    string
		client  *testClient
		fetcher JWKSFetcherStrategy
		valid   bool
	}{
		{name: "ShouldAcceptTheMaximumSizeFromTheClient", client: &testClient{jwks: jwks(RSAMaximumKeySize)}, valid: true},
		{name: "ShouldRejectAnOversizedKeyFromTheClient", client: &testClient{jwks: jwks(RSAMaximumKeySize + 1)}},
		{name: "ShouldRejectAnOversizedKeyFromTheURI", client: &testClient{jwksURI: "https://example.com/jwks"}, fetcher: &stubFetcher{jwks: jwks(RSAMaximumKeySize + 1)}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := FindClientPublicJWK(t.Context(), tc.client, tc.fetcher, "a", string(jose.RS256), JSONWebTokenUseSignature, true)

			if tc.valid {
				require.NoError(t, err)
				assert.NotNil(t, key)

				return
			}

			var lookup *JWKLookupError

			require.ErrorAs(t, err, &lookup)
			assert.Nil(t, key)
		})
	}
}

func rsaPublicKeyOfSize(bits int) *rsa.PublicKey {
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))

	return &rsa.PublicKey{N: n.SetBit(n, 0, 1), E: 65537}
}
