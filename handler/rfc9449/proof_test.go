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

func TestParseProof(t *testing.T) {
	testCases := []struct {
		name    string
		raw     func(t *testing.T, key *jose.JSONWebKey) string
		algs    []jose.SignatureAlgorithm
		wantErr error
		check   func(t *testing.T, proof *oauth2.DPoPProof)
	}{
		{
			name: "Valid",
			raw: func(t *testing.T, key *jose.JSONWebKey) string {
				return signProof(t, key, ijwt.JSONWebTokenTypeDPoP, map[string]any{
					ijwt.ClaimJWTID:      "id-1",
					ijwt.ClaimHTTPMethod: http.MethodPost,
					ijwt.ClaimHTTPURI:    "https://as.example.com/token",
					ijwt.ClaimIssuedAt:   1000,
				})
			},
			check: func(t *testing.T, proof *oauth2.DPoPProof) {
				assert.Equal(t, "id-1", proof.ID)
				assert.Equal(t, http.MethodPost, proof.Method)
				assert.Equal(t, "https://as.example.com/token", proof.URL)
				assert.NotEmpty(t, proof.Thumbprint)
			},
		},
		{
			name: "RejectsWrongType",
			raw: func(t *testing.T, key *jose.JSONWebKey) string {
				return signProof(t, key, ijwt.JSONWebTokenTypeJWT, map[string]any{ijwt.ClaimJWTID: "x", ijwt.ClaimHTTPMethod: http.MethodPost, ijwt.ClaimHTTPURI: "https://as/token", ijwt.ClaimIssuedAt: 1})
			},
			wantErr: oauth2.ErrInvalidDPoPProof,
		},
		{
			name: "RejectsBadSignature",
			raw: func(t *testing.T, key *jose.JSONWebKey) string {
				raw := signProof(t, key, ijwt.JSONWebTokenTypeDPoP, map[string]any{ijwt.ClaimJWTID: "x", ijwt.ClaimHTTPMethod: http.MethodPost, ijwt.ClaimHTTPURI: "https://as/token", ijwt.ClaimIssuedAt: 1})

				parts := strings.Split(raw, ".")
				require.Len(t, parts, 3)

				sig, err := base64.RawURLEncoding.DecodeString(parts[2])
				require.NoError(t, err)
				require.NotEmpty(t, sig)

				sig[0] ^= 0xFF

				return parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig)
			},
			wantErr: oauth2.ErrInvalidDPoPProof,
		},
		{
			name: "RejectsMissingJTI",
			raw: func(t *testing.T, key *jose.JSONWebKey) string {
				return signProof(t, key, ijwt.JSONWebTokenTypeDPoP, map[string]any{ijwt.ClaimHTTPMethod: http.MethodPost, ijwt.ClaimHTTPURI: "https://as/token", ijwt.ClaimIssuedAt: 1})
			},
			wantErr: oauth2.ErrInvalidDPoPProof,
		},
		{
			name: "RejectsDisallowedAlg",
			raw: func(t *testing.T, key *jose.JSONWebKey) string {
				return signProof(t, key, ijwt.JSONWebTokenTypeDPoP, map[string]any{ijwt.ClaimJWTID: "x", ijwt.ClaimHTTPMethod: http.MethodPost, ijwt.ClaimHTTPURI: "https://as/token", ijwt.ClaimIssuedAt: 1})
			},
			algs:    []jose.SignatureAlgorithm{jose.RS256},
			wantErr: oauth2.ErrInvalidDPoPProof,
		},
		{
			name: "RejectsJSONSerialization",
			raw: func(t *testing.T, key *jose.JSONWebKey) string {
				raw := signProof(t, key, ijwt.JSONWebTokenTypeDPoP, map[string]any{
					ijwt.ClaimJWTID: "json-1", ijwt.ClaimHTTPMethod: http.MethodPost, ijwt.ClaimHTTPURI: "https://as.example.com/token", ijwt.ClaimIssuedAt: 1,
				})

				parts := strings.Split(raw, ".")
				require.Len(t, parts, 3)

				return `{"protected":"` + parts[0] + `","payload":"` + parts[1] + `","signature":"` + parts[2] + `"}`
			},
			wantErr: oauth2.ErrInvalidDPoPProof,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key := newTestProofKey(t)

			algs := testAlgs
			if tc.algs != nil {
				algs = tc.algs
			}

			proof, err := ParseProof(tc.raw(t, key), algs)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			if tc.check != nil {
				tc.check(t, proof)
			}
		})
	}
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
