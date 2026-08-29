// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/token/jose"
)

// TestSignatureAlgorithmsEdDSAValues pins the Edwards-curve 'alg' values the signer accepts against the identifiers
// the specifications register. RFC 8037 Section 3.1 registers the polymorphic 'EdDSA'; RFC 9864 Table 2 registers the
// fully-specified 'Ed25519' and 'Ed448', the latter of which token/jose does not implement and which must therefore
// not be advertised here.
func TestSignatureAlgorithmsEdDSAValues(t *testing.T) {
	edDSA := func(algs []jose.SignatureAlgorithm) (out []string) {
		for _, alg := range algs {
			switch alg {
			case jose.EdDSA, jose.Ed25519:
				out = append(out, string(alg))
			}
		}

		return out
	}

	for _, tc := range []struct {
		name string
		have []jose.SignatureAlgorithm
	}{
		{name: "SignatureAlgorithms", have: SignatureAlgorithms},
		{name: "SignatureAlgorithmsNone", have: SignatureAlgorithmsNone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, []string{"EdDSA", "Ed25519"}, edDSA(tc.have))

			for _, alg := range tc.have {
				assert.NotEqual(t, jose.SignatureAlgorithm("Ed448"), alg,
					"Ed448 is registered by RFC 9864 but token/jose does not implement it")
			}
		})
	}

	t.Run("ShouldNotCarryUnregisteredSpellings", func(t *testing.T) {
		for _, unregistered := range []string{"ED25519", "ed25519", "EDDSA", "eddsa", "Ed25519ph", "Ed25519ctx"} {
			assert.False(t, slices.Contains(SignatureAlgorithmsNone, jose.SignatureAlgorithm(unregistered)),
				"'%s' is not a registered JOSE 'alg' value", unregistered)
		}
	})
}

// TestSignatureAlgorithmsEdDSARoundTrip proves the advertised values are ones the signer can actually produce and
// the parser accept, rather than names alone.
func TestSignatureAlgorithmsEdDSARoundTrip(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	for _, alg := range []jose.SignatureAlgorithm{jose.EdDSA, jose.Ed25519} {
		t.Run(string(alg), func(t *testing.T) {
			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: private}, nil)
			require.NoError(t, err)

			object, err := signer.Sign([]byte(`{"sub":"peter"}`))
			require.NoError(t, err)

			serialized, err := object.CompactSerialize()
			require.NoError(t, err)

			parsed, err := jose.ParseSigned(serialized, SignatureAlgorithms)
			require.NoError(t, err, "the signer accepts %s so the parser must too", alg)

			payload, err := parsed.Verify(public)
			require.NoError(t, err)
			assert.JSONEq(t, `{"sub":"peter"}`, string(payload))
		})
	}
}
