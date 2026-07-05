// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc9449

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
)

var testAlgs = []jose.SignatureAlgorithm{jose.ES256}

func newTestProofKey(t *testing.T) *jose.JSONWebKey {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	return &jose.JSONWebKey{Key: priv, Algorithm: string(jose.ES256)}
}

func signProof(t *testing.T, key *jose.JSONWebKey, typ string, claims map[string]any) string {
	t.Helper()

	// EmbedJWK embeds the public part of the *jose.JSONWebKey signing key as the 'jwk' header, which ParseProof reads
	// back via header.JSONWebKey.
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(key.Algorithm), Key: key},
		(&jose.SignerOptions{EmbedJWK: true}).WithType(jose.ContentType(typ)),
	)
	require.NoError(t, err)

	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)

	return raw
}

func TestParseProofValid(t *testing.T) {
	key := newTestProofKey(t)
	raw := signProof(t, key, "dpop+jwt", map[string]any{
		"jti": "id-1",
		"htm": "POST",
		"htu": "https://as.example.com/token",
		"iat": 1000,
	})

	proof, err := ParseProof(raw, testAlgs)
	require.NoError(t, err)

	assert.Equal(t, "id-1", proof.ID)
	assert.Equal(t, "POST", proof.Method)
	assert.Equal(t, "https://as.example.com/token", proof.URL)
	assert.NotEmpty(t, proof.Thumbprint)
}

func TestParseProofRejectsWrongType(t *testing.T) {
	key := newTestProofKey(t)
	raw := signProof(t, key, "JWT", map[string]any{"jti": "x", "htm": "POST", "htu": "https://as/token", "iat": 1})

	_, err := ParseProof(raw, testAlgs)
	assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
}

func TestParseProofRejectsBadSignature(t *testing.T) {
	key := newTestProofKey(t)
	raw := signProof(t, key, "dpop+jwt", map[string]any{"jti": "x", "htm": "POST", "htu": "https://as/token", "iat": 1})

	// Tamper with the signature by flipping all the bits of its first byte. This is done on the decoded bytes (rather
	// than mutating the trailing base64 character directly) because the final base64url character of a raw P-256
	// ECDSA signature only encodes 2 real bits (the rest is zero-padding that decoders discard), so naively swapping
	// the last character can - for ~1/4 of randomly generated keys - decode back to the exact same signature bytes
	// and flakily fail to invalidate the signature.
	parts := strings.Split(raw, ".")
	require.Len(t, parts, 3)

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	require.NotEmpty(t, sig)

	sig[0] ^= 0xFF

	tampered := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig)

	_, err = ParseProof(tampered, testAlgs)
	assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
}

func TestParseProofRejectsMissingJTI(t *testing.T) {
	key := newTestProofKey(t)
	raw := signProof(t, key, "dpop+jwt", map[string]any{"htm": "POST", "htu": "https://as/token", "iat": 1})

	_, err := ParseProof(raw, testAlgs)
	assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
}

func TestParseProofRejectsDisallowedAlg(t *testing.T) {
	key := newTestProofKey(t)
	raw := signProof(t, key, "dpop+jwt", map[string]any{"jti": "x", "htm": "POST", "htu": "https://as/token", "iat": 1})

	// Only RS256 permitted, proof is ES256.
	_, err := ParseProof(raw, []jose.SignatureAlgorithm{jose.RS256})
	assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
}

// TestParseProofRejectsJSONSerialization confirms that RFC 9449 §4.2 compact serialization is enforced: a proof
// value that is JSON (General/Flattened JWS Serialization) rather than the required compact form must be rejected,
// even though go-jose's general ParseSigned would otherwise happily accept it.
func TestParseProofRejectsJSONSerialization(t *testing.T) {
	key := newTestProofKey(t)
	raw := signProof(t, key, "dpop+jwt", map[string]any{
		"jti": "json-1", "htm": "POST", "htu": "https://as.example.com/token", "iat": 1,
	})

	parts := strings.Split(raw, ".")
	require.Len(t, parts, 3)

	// Build the flattened JSON serialization of the same JWS. jose.ParseSigned (general parsing) accepts this; the
	// RFC 9449 compact-only parser must not.
	json := `{"protected":"` + parts[0] + `","payload":"` + parts[1] + `","signature":"` + parts[2] + `"}`

	_, err := ParseProof(json, testAlgs)
	assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
}
