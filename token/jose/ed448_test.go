// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jose

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"

	"authelia.com/provider/oauth2/token/jose/ed448"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEd448SignAndVerify(t *testing.T) {
	public, private, err := ed448.GenerateKey(rand.Reader)
	require.NoError(t, err)

	payload := []byte(`{"sub":"peter"}`)

	signer, err := NewSigner(SigningKey{Algorithm: Ed448, Key: private}, nil)
	require.NoError(t, err)

	object, err := signer.Sign(payload)
	require.NoError(t, err)

	serialized, err := object.CompactSerialize()
	require.NoError(t, err)

	parsed, err := ParseSigned(serialized, []SignatureAlgorithm{Ed448})
	require.NoError(t, err)

	verified, err := parsed.Verify(public)
	require.NoError(t, err)
	assert.Equal(t, payload, verified)

	t.Run("ShouldProduceASignatureTheBarePrimitiveAccepts", func(t *testing.T) {
		// The signing input is the compact serialization's first two segments. Verifying it with ed448.Verify
		// directly proves the JOSE layer signs the bytes the primitive expects, with the empty context RFC 8037 and
		// RFC 9864 give JOSE no way to carry.
		signingInput := serialized[:len(serialized)-len(parsed.Signatures[0].Signature)*0]
		idx := 0
		for i := len(signingInput) - 1; i >= 0; i-- {
			if signingInput[i] == '.' {
				idx = i
				break
			}
		}

		assert.True(t, ed448.Verify(public, []byte(serialized[:idx]), parsed.Signatures[0].Signature, ""))
	})

	t.Run("ShouldRejectAnEd25519Header", func(t *testing.T) {
		_, err := ParseSigned(serialized, []SignatureAlgorithm{Ed25519, EdDSA})
		require.Error(t, err, "an Ed448 token must not be accepted under an Ed25519 or polymorphic EdDSA allow list")
	})
}

func TestEd448JSONWebKeyRoundTrip(t *testing.T) {
	public, private, err := ed448.GenerateKey(rand.Reader)
	require.NoError(t, err)

	t.Run("PublicKey", func(t *testing.T) {
		data, err := json.Marshal(&JSONWebKey{Key: public, KeyID: "k", Algorithm: "Ed448", Use: "sig"})
		require.NoError(t, err)

		var raw map[string]any
		require.NoError(t, json.Unmarshal(data, &raw))
		assert.Equal(t, "OKP", raw["kty"])
		assert.Equal(t, "Ed448", raw["crv"])
		assert.NotContains(t, raw, "d")

		var decoded JSONWebKey
		require.NoError(t, json.Unmarshal(data, &decoded))

		got, ok := decoded.Key.(ed448.PublicKey)
		require.True(t, ok, "got %T", decoded.Key)
		assert.Equal(t, []byte(public), []byte(got))
		assert.True(t, decoded.IsPublic())
		assert.True(t, decoded.Valid())
	})

	t.Run("PrivateKey", func(t *testing.T) {
		data, err := json.Marshal(&JSONWebKey{Key: private, KeyID: "k", Algorithm: "Ed448", Use: "sig"})
		require.NoError(t, err)

		var decoded JSONWebKey
		require.NoError(t, json.Unmarshal(data, &decoded))

		got, ok := decoded.Key.(ed448.PrivateKey)
		require.True(t, ok, "got %T", decoded.Key)
		assert.Equal(t, []byte(private), []byte(got))
		assert.False(t, decoded.IsPublic())
		assert.True(t, decoded.Valid())

		pub, ok := decoded.Public().Key.(ed448.PublicKey)
		require.True(t, ok)
		assert.Equal(t, []byte(public), []byte(pub))
	})

	t.Run("ShouldRejectAPrivateKeyWhoseXDoesNotMatchD", func(t *testing.T) {
		_, other, err := ed448.GenerateKey(rand.Reader)
		require.NoError(t, err)

		data, err := json.Marshal(&JSONWebKey{Key: private})
		require.NoError(t, err)

		var raw map[string]any
		require.NoError(t, json.Unmarshal(data, &raw))

		mismatched, err := json.Marshal(&JSONWebKey{Key: other})
		require.NoError(t, err)

		var rawOther map[string]any
		require.NoError(t, json.Unmarshal(mismatched, &rawOther))

		raw["d"] = rawOther["d"]

		swapped, err := json.Marshal(raw)
		require.NoError(t, err)

		var decoded JSONWebKey
		require.Error(t, json.Unmarshal(swapped, &decoded))
	})
}

func TestEd448Thumbprint(t *testing.T) {
	public, private, err := ed448.GenerateKey(rand.Reader)
	require.NoError(t, err)

	key := &JSONWebKey{Key: public}

	first, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	require.NotEmpty(t, first)

	second, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	assert.Equal(t, first, second)

	// RFC 7638 Section 3 computes the thumbprint over the public members only, so the private key must produce the
	// same value rather than a different one or an error, as the Ed25519 path does.
	t.Run("ShouldThumbprintAPrivateKeyAsItsPublicKey", func(t *testing.T) {
		fromPrivate, err := (&JSONWebKey{Key: private}).Thumbprint(crypto.SHA256)
		require.NoError(t, err)
		assert.Equal(t, first, fromPrivate)
	})

	t.Run("ShouldRejectAMalformedPrivateKey", func(t *testing.T) {
		_, err := (&JSONWebKey{Key: ed448.PrivateKey(private[:ed448.PrivateKeySize-1])}).Thumbprint(crypto.SHA256)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "wrong length")
	})
}

// TestEdDSAVariantFollowsTheKeyCurve pins RFC 8037 Section 3.1: "The EdDSA variant used is determined by the subtype
// of the key (Ed25519 for "Ed25519" and Ed448 for "Ed448")". The polymorphic identifier therefore selects the curve
// of whichever key it is given, while the fully-specified identifiers of RFC 9864 Section 2.2 name one curve each and
// cannot be paired with the other's key.
func TestEdDSAVariantFollowsTheKeyCurve(t *testing.T) {
	ed25519Public, ed25519Private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	ed448Public, ed448Private, err := ed448.GenerateKey(rand.Reader)
	require.NoError(t, err)

	testCases := []struct {
		name    string
		alg     SignatureAlgorithm
		private any
		public  any
		header  string
		err     bool
	}{
		{name: "ShouldSelectEd25519ForThePolymorphicAlgWithAnEd25519Key", alg: EdDSA, private: ed25519Private, public: ed25519Public, header: "EdDSA"},
		{name: "ShouldSelectEd448ForThePolymorphicAlgWithAnEd448Key", alg: EdDSA, private: ed448Private, public: ed448Public, header: "EdDSA"},
		{name: "ShouldAcceptTheFullySpecifiedEd25519", alg: Ed25519, private: ed25519Private, public: ed25519Public, header: "Ed25519"},
		{name: "ShouldAcceptTheFullySpecifiedEd448", alg: Ed448, private: ed448Private, public: ed448Public, header: "Ed448"},
		{name: "ShouldRejectTheEd25519AlgWithAnEd448Key", alg: Ed25519, private: ed448Private, err: true},
		{name: "ShouldRejectTheEd448AlgWithAnEd25519Key", alg: Ed448, private: ed25519Private, err: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			signer, err := NewSigner(SigningKey{Algorithm: tc.alg, Key: tc.private}, nil)

			if tc.err {
				require.Error(t, err, "a fully-specified identifier must not accept the other curve's key")

				return
			}

			require.NoError(t, err)

			object, err := signer.Sign([]byte(`{"sub":"peter"}`))
			require.NoError(t, err)

			serialized, err := object.CompactSerialize()
			require.NoError(t, err)

			parsed, err := ParseSigned(serialized, []SignatureAlgorithm{EdDSA, Ed25519, Ed448})
			require.NoError(t, err)

			assert.Equal(t, tc.header, string(parsed.Signatures[0].Header.Algorithm),
				"the header carries the identifier that was asked for, not the resolved curve")

			payload, err := parsed.Verify(tc.public)
			require.NoError(t, err, "verification resolves the curve from the key, as signing did")
			assert.JSONEq(t, `{"sub":"peter"}`, string(payload))
		})
	}

	// The curve is the key's, so a signature made under the polymorphic identifier with one curve must not verify
	// against a key of the other.
	t.Run("ShouldNotVerifyAcrossCurvesUnderThePolymorphicAlg", func(t *testing.T) {
		signer, err := NewSigner(SigningKey{Algorithm: EdDSA, Key: ed448Private}, nil)
		require.NoError(t, err)

		object, err := signer.Sign([]byte(`{"sub":"peter"}`))
		require.NoError(t, err)

		serialized, err := object.CompactSerialize()
		require.NoError(t, err)

		parsed, err := ParseSigned(serialized, []SignatureAlgorithm{EdDSA})
		require.NoError(t, err)

		_, err = parsed.Verify(ed25519Public)
		require.Error(t, err)
	})
}
