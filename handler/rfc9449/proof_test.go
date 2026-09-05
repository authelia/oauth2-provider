// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc9449

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/token/jose"
	"authelia.com/provider/oauth2/token/jose/jwt"
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
			name: "RejectsOversizedJTI",
			raw: func(t *testing.T, key *jose.JSONWebKey) string {
				return signProof(t, key, ijwt.JSONWebTokenTypeDPoP, map[string]any{
					ijwt.ClaimJWTID: strings.Repeat("j", JTIMaxLength+1), ijwt.ClaimHTTPMethod: http.MethodPost, ijwt.ClaimHTTPURI: "https://as/token", ijwt.ClaimIssuedAt: 1,
				})
			},
			wantErr: oauth2.ErrInvalidDPoPProof,
		},
		{
			name: "AcceptsMaximumLengthJTI",
			raw: func(t *testing.T, key *jose.JSONWebKey) string {
				return signProof(t, key, ijwt.JSONWebTokenTypeDPoP, map[string]any{
					ijwt.ClaimJWTID: strings.Repeat("j", JTIMaxLength), ijwt.ClaimHTTPMethod: http.MethodPost, ijwt.ClaimHTTPURI: "https://as/token", ijwt.ClaimIssuedAt: 1,
				})
			},
			check: func(t *testing.T, proof *oauth2.DPoPProof) {
				assert.Len(t, proof.ID, JTIMaxLength)
			},
		},
		{
			name: "RejectsOversizedNonce",
			raw: func(t *testing.T, key *jose.JSONWebKey) string {
				return signProof(t, key, ijwt.JSONWebTokenTypeDPoP, map[string]any{
					ijwt.ClaimJWTID: "nonce-long", ijwt.ClaimHTTPMethod: http.MethodPost, ijwt.ClaimHTTPURI: "https://as/token", ijwt.ClaimIssuedAt: 1,
					ijwt.ClaimNonce: strings.Repeat("n", NonceMaxLength+1),
				})
			},
			wantErr: oauth2.ErrInvalidDPoPProof,
		},
		{
			name: "AcceptsMaximumLengthNonce",
			raw: func(t *testing.T, key *jose.JSONWebKey) string {
				return signProof(t, key, ijwt.JSONWebTokenTypeDPoP, map[string]any{
					ijwt.ClaimJWTID: "nonce-max", ijwt.ClaimHTTPMethod: http.MethodPost, ijwt.ClaimHTTPURI: "https://as/token", ijwt.ClaimIssuedAt: 1,
					ijwt.ClaimNonce: strings.Repeat("n", NonceMaxLength),
				})
			},
			check: func(t *testing.T, proof *oauth2.DPoPProof) {
				assert.Len(t, proof.Nonce, NonceMaxLength)
			},
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

func TestParseProofRSAKeySize(t *testing.T) {
	testCases := []struct {
		name    string
		bits    int
		wantErr bool
	}{
		{"ShouldRejectBelowTheMinimum", 1024, true},
		{"ShouldAcceptTheMinimum", RSAMinimumKeySize, false},
		{"ShouldAcceptAboveTheMinimum", 3072, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			priv, err := rsa.GenerateKey(rand.Reader, tc.bits)
			require.NoError(t, err)

			claims := map[string]any{
				ijwt.ClaimJWTID:      "rsa-1",
				ijwt.ClaimHTTPMethod: http.MethodPost,
				ijwt.ClaimHTTPURI:    "https://as.example.com/token",
				ijwt.ClaimIssuedAt:   1000,
			}

			var raw string

			if tc.bits < RSAMinimumKeySize {
				raw = signProofRSARaw(t, priv, ijwt.JSONWebTokenTypeDPoP, claims)
			} else {
				key := &jose.JSONWebKey{Key: priv, Algorithm: string(jose.RS256), KeyID: "rsa"}
				raw = signProof(t, key, ijwt.JSONWebTokenTypeDPoP, claims)
			}

			proof, err := ParseProof(raw, []jose.SignatureAlgorithm{jose.RS256})

			if tc.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The DPoP proof is missing or invalid. The DPoP proof 'jwk' header contains a 1024 bit RSA key but keys of at least 2048 bits are required.")

				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, proof.Thumbprint)
		})
	}
}

func TestParseProofAcceptsEllipticAndEdDSAKeys(t *testing.T) {
	t.Run("ES256", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		key := &jose.JSONWebKey{Key: priv, Algorithm: string(jose.ES256)}

		raw := signProof(t, key, ijwt.JSONWebTokenTypeDPoP, map[string]any{
			ijwt.ClaimJWTID: "ec-1", ijwt.ClaimHTTPMethod: http.MethodPost, ijwt.ClaimHTTPURI: "https://as.example.com/token", ijwt.ClaimIssuedAt: 1000,
		})

		_, err = ParseProof(raw, []jose.SignatureAlgorithm{jose.ES256})
		require.NoError(t, err)
	})

	t.Run("EdDSA", func(t *testing.T) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		key := &jose.JSONWebKey{Key: priv, Algorithm: string(jose.EdDSA)}

		raw := signProof(t, key, ijwt.JSONWebTokenTypeDPoP, map[string]any{
			ijwt.ClaimJWTID: "ed-1", ijwt.ClaimHTTPMethod: http.MethodPost, ijwt.ClaimHTTPURI: "https://as.example.com/token", ijwt.ClaimIssuedAt: 1000,
		})

		_, err = ParseProof(raw, []jose.SignatureAlgorithm{jose.EdDSA})
		require.NoError(t, err)
	})
}

func TestParseProofRejectsUnsignedAndSymmetricProofs(t *testing.T) {
	claims := map[string]any{
		ijwt.ClaimJWTID:      "alg-1",
		ijwt.ClaimHTTPMethod: http.MethodPost,
		ijwt.ClaimHTTPURI:    "https://as.example.com/token",
		ijwt.ClaimIssuedAt:   1000,
	}

	t.Run("ShouldRejectAlgNone", func(t *testing.T) {
		raw := signProofNoneRaw(t, newTestProofKey(t), ijwt.JSONWebTokenTypeDPoP, claims)

		for _, algs := range [][]jose.SignatureAlgorithm{
			{jose.ES256},
			{"none"},
			{jose.ES256, "none"},
		} {
			_, err := ParseProof(raw, algs)

			assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof, "the unsigned proof was accepted with the algorithms %v", algs)
		}
	})

	t.Run("ShouldRejectASymmetricAlgorithm", func(t *testing.T) {
		secret := []byte("0123456789abcdef0123456789abcdef")

		signer, err := jose.NewSigner(
			jose.SigningKey{Algorithm: jose.HS256, Key: secret},
			(&jose.SignerOptions{}).
				WithType(jose.ContentType(ijwt.JSONWebTokenTypeDPoP)).
				WithHeader("jwk", map[string]any{"kty": "oct", "k": base64.RawURLEncoding.EncodeToString(secret)}),
		)
		require.NoError(t, err)

		raw, err := jwt.Signed(signer).Claims(claims).Serialize()
		require.NoError(t, err)

		_, err = ParseProof(raw, []jose.SignatureAlgorithm{jose.HS256})

		assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
	})
}

func TestParseProof_JWKAndCodeHash(t *testing.T) {
	key := newTestProofKey(t)

	t.Run("ShouldParseCodeHashAndJWK", func(t *testing.T) {
		raw := signProof(t, key, ijwt.JSONWebTokenTypeDPoP, map[string]any{
			ijwt.ClaimJWTID:        "p1",
			ijwt.ClaimHTTPMethod:   http.MethodPost,
			ijwt.ClaimHTTPURI:      "https://as.example.com/token",
			ijwt.ClaimIssuedAt:     time.Now().Unix(),
			ijwt.ClaimDPoPCodeHash: "o1uBp9eSe3DsmScN0jYriFgKKFdK-BLywC9WRpV5GG8",
		})

		proof, err := ParseProof(raw, []jose.SignatureAlgorithm{jose.ES256})
		require.NoError(t, err)

		assert.Equal(t, "o1uBp9eSe3DsmScN0jYriFgKKFdK-BLywC9WRpV5GG8", proof.CodeHash)

		require.NotNil(t, proof.JWK)
		assert.True(t, proof.JWK.IsPublic())

		thumbprint, err := ijwt.ThumbprintJWK(proof.JWK)
		require.NoError(t, err)
		assert.Equal(t, proof.Thumbprint, thumbprint)
	})

	t.Run("ShouldLeaveCodeHashEmptyWhenAbsent", func(t *testing.T) {
		raw := signProof(t, key, ijwt.JSONWebTokenTypeDPoP, map[string]any{
			ijwt.ClaimJWTID:      "p2",
			ijwt.ClaimHTTPMethod: http.MethodPost,
			ijwt.ClaimHTTPURI:    "https://as.example.com/token",
			ijwt.ClaimIssuedAt:   time.Now().Unix(),
		})

		proof, err := ParseProof(raw, []jose.SignatureAlgorithm{jose.ES256})
		require.NoError(t, err)

		assert.Empty(t, proof.CodeHash)
		assert.NotNil(t, proof.JWK)
	})
}

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

func signProofRSARaw(t *testing.T, priv *rsa.PrivateKey, typ string, claims map[string]any) string {
	t.Helper()

	jwk, err := (&jose.JSONWebKey{Key: &priv.PublicKey, Algorithm: string(jose.RS256), KeyID: "rsa"}).MarshalJSON()
	require.NoError(t, err)

	header, err := json.Marshal(map[string]any{
		"alg": string(jose.RS256),
		"typ": typ,
		"jwk": json.RawMessage(jwk),
	})
	require.NoError(t, err)

	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)

	digest := sha256.Sum256([]byte(signing))

	signature, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	require.NoError(t, err)

	return signing + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func signProofNoneRaw(t *testing.T, key *jose.JSONWebKey, typ string, claims map[string]any) string {
	t.Helper()

	public := key.Public()

	jwk, err := public.MarshalJSON()
	require.NoError(t, err)

	header, err := json.Marshal(map[string]any{
		"alg": "none",
		"typ": typ,
		"jwk": json.RawMessage(jwk),
	})
	require.NoError(t, err)

	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
}

var testAlgs = []jose.SignatureAlgorithm{jose.ES256}
