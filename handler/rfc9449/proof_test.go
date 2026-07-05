// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc9449

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	ijwt "authelia.com/provider/oauth2/token/jwt"
)

func TestParseProofValid(t *testing.T) {
	key := newTestProofKey(t)
	raw := signProof(t, key, ijwt.JSONWebTokenTypeDPoP, map[string]any{
		ijwt.ClaimJWTID:      "id-1",
		ijwt.ClaimHTTPMethod: http.MethodPost,
		ijwt.ClaimHTTPURI:    "https://as.example.com/token",
		ijwt.ClaimIssuedAt:   1000,
	})

	proof, err := ParseProof(raw, testAlgs)
	require.NoError(t, err)

	assert.Equal(t, "id-1", proof.ID)
	assert.Equal(t, http.MethodPost, proof.Method)
	assert.Equal(t, "https://as.example.com/token", proof.URL)
	assert.NotEmpty(t, proof.Thumbprint)
}

func TestParseProofRejectsWrongType(t *testing.T) {
	key := newTestProofKey(t)
	raw := signProof(t, key, ijwt.JSONWebTokenTypeJWT, map[string]any{ijwt.ClaimJWTID: "x", ijwt.ClaimHTTPMethod: http.MethodPost, ijwt.ClaimHTTPURI: "https://as/token", ijwt.ClaimIssuedAt: 1})

	_, err := ParseProof(raw, testAlgs)
	assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
}

func TestParseProofRejectsBadSignature(t *testing.T) {
	key := newTestProofKey(t)
	raw := signProof(t, key, ijwt.JSONWebTokenTypeDPoP, map[string]any{ijwt.ClaimJWTID: "x", ijwt.ClaimHTTPMethod: http.MethodPost, ijwt.ClaimHTTPURI: "https://as/token", ijwt.ClaimIssuedAt: 1})

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
	raw := signProof(t, key, ijwt.JSONWebTokenTypeDPoP, map[string]any{ijwt.ClaimHTTPMethod: http.MethodPost, ijwt.ClaimHTTPURI: "https://as/token", ijwt.ClaimIssuedAt: 1})

	_, err := ParseProof(raw, testAlgs)
	assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
}

func TestParseProofRejectsDisallowedAlg(t *testing.T) {
	key := newTestProofKey(t)
	raw := signProof(t, key, ijwt.JSONWebTokenTypeDPoP, map[string]any{ijwt.ClaimJWTID: "x", ijwt.ClaimHTTPMethod: http.MethodPost, ijwt.ClaimHTTPURI: "https://as/token", ijwt.ClaimIssuedAt: 1})

	_, err := ParseProof(raw, []jose.SignatureAlgorithm{jose.RS256})
	assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
}

func TestParseProofRejectsJSONSerialization(t *testing.T) {
	key := newTestProofKey(t)
	raw := signProof(t, key, ijwt.JSONWebTokenTypeDPoP, map[string]any{
		ijwt.ClaimJWTID: "json-1", ijwt.ClaimHTTPMethod: http.MethodPost, ijwt.ClaimHTTPURI: "https://as.example.com/token", ijwt.ClaimIssuedAt: 1,
	})

	parts := strings.Split(raw, ".")
	require.Len(t, parts, 3)

	json := `{"protected":"` + parts[0] + `","payload":"` + parts[1] + `","signature":"` + parts[2] + `"}`

	_, err := ParseProof(json, testAlgs)
	assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
}

var testAlgs = []jose.SignatureAlgorithm{jose.ES256}

func newTestProofKey(t *testing.T) *jose.JSONWebKey {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	return &jose.JSONWebKey{Key: priv, Algorithm: string(jose.ES256)}
}

func signProof(t *testing.T, key *jose.JSONWebKey, typ string, claims map[string]any) string {
	t.Helper()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(key.Algorithm), Key: key},
		(&jose.SignerOptions{EmbedJWK: true}).WithType(jose.ContentType(typ)),
	)
	require.NoError(t, err)

	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)

	return raw
}
