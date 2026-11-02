// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"math/big"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"
	josejwt "authelia.com/provider/jose/jwt"
)

func TestSupportedAlgorithmsAreCovered(t *testing.T) {
	t.Run("ShouldPinSignatureAlgorithms", func(t *testing.T) {
		assert.ElementsMatch(t, []jose.SignatureAlgorithm{jose.HS256, jose.HS384, jose.HS512, jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512, jose.EdDSA, jose.Ed25519}, SignatureAlgorithms)
		assert.ElementsMatch(t, append([]jose.SignatureAlgorithm{SigningMethodNone}, SignatureAlgorithms...), SignatureAlgorithmsNone)
	})

	t.Run("ShouldPinKeyAlgorithms", func(t *testing.T) {
		assert.ElementsMatch(t, []jose.KeyAlgorithm{jose.RSA1_5, jose.RSA_OAEP, jose.RSA_OAEP_256, jose.A128KW, jose.A192KW, jose.A256KW, jose.DIRECT, jose.ECDH_ES, jose.ECDH_ES_A128KW, jose.ECDH_ES_A192KW, jose.ECDH_ES_A256KW, jose.A128GCMKW, jose.A192GCMKW, jose.A256GCMKW, jose.PBES2_HS256_A128KW, jose.PBES2_HS384_A192KW, jose.PBES2_HS512_A256KW}, EncryptionKeyAlgorithms)
	})

	t.Run("ShouldPinContentEncryptionAlgorithms", func(t *testing.T) {
		assert.ElementsMatch(t, []jose.ContentEncryption{jose.A128CBC_HS256, jose.A192CBC_HS384, jose.A256CBC_HS512, jose.A128GCM, jose.A192GCM, jose.A256GCM}, ContentEncryptionAlgorithms)
	})

	t.Run("ShouldHaveSignatureFixture", func(t *testing.T) {
		for _, alg := range SignatureAlgorithms {
			assert.NotZero(t, algHash(alg), "no hash for %s", alg)
		}
	})

	t.Run("ShouldClassifyClientSecretAlgorithms", func(t *testing.T) {
		for _, alg := range SignatureAlgorithms {
			assert.Equal(t, strings.HasPrefix(string(alg), "HS"), IsSignedJWTClientSecretAlg(alg), "%s", alg)
		}

		for _, alg := range EncryptionKeyAlgorithms {
			asymmetric := strings.HasPrefix(string(alg), "RSA") || strings.HasPrefix(string(alg), "ECDH")

			assert.Equal(t, !asymmetric, IsEncryptedJWTClientSecretAlg(alg), "%s", alg)
			assert.Equal(t, strings.HasPrefix(string(alg), "PBES2"), IsEncryptedJWTPasswordBasedAlg(alg), "%s", alg)
		}
	})
}

func TestSignatureAlgorithmsMatrix(t *testing.T) {
	f := getAlgorithmFixtures(t)

	claims := MapClaims{ClaimIssuer: "example.com", ClaimSubject: "john"}

	for _, alg := range SignatureAlgorithms {
		t.Run(string(alg), func(t *testing.T) {
			kid := f.signKID(alg)
			issuer := f.client(alg, "", "", "")

			t.Run("ShouldSignUsingTheClientConfiguration", func(t *testing.T) {
				tokenString, signature, err := f.strategy.Encode(t.Context(), claims, WithClient(issuer))
				require.NoError(t, err)
				require.True(t, IsSignedJWT(tokenString))

				parts := strings.Split(tokenString, ".")
				assert.Equal(t, parts[2], signature)

				header := decodeJOSEHeader(t, parts[0])
				assert.Equal(t, string(alg), header[JSONWebTokenHeaderAlgorithm])
				assert.Equal(t, JSONWebTokenTypeJWT, header[JSONWebTokenHeaderType])

				if kid == "" {
					assert.NotContains(t, header, JSONWebTokenHeaderKeyIdentifier)
				} else {
					assert.Equal(t, kid, header[JSONWebTokenHeaderKeyIdentifier])
				}

				verifySignatureIndependently(t, f, alg, tokenString)

				token, err := f.strategy.Decode(t.Context(), tokenString, WithClient(issuer))
				require.NoError(t, err)
				assert.True(t, token.IsSignatureValid())
				assert.NoError(t, token.Valid(ValidateAlgorithm(string(alg))))
				assert.Equal(t, alg, token.SignatureAlgorithm)
				assert.Equal(t, kid, token.KeyID)
				assert.Equal(t, "john", token.Claims.ToMapClaims()[ClaimSubject])
			})

			t.Run("ShouldSignUsingTheIssuerWithoutAClient", func(t *testing.T) {
				if IsSignedJWTClientSecretAlg(alg) {
					t.Skip("a symmetric algorithm always uses the client secret")
				}

				tokenString, _, err := f.strategy.Encode(t.Context(), claims, WithIssuerSigningAlg(string(alg)))
				require.NoError(t, err)

				verifySignatureIndependently(t, f, alg, tokenString)

				token, err := f.strategy.Decode(t.Context(), tokenString)
				require.NoError(t, err)
				assert.True(t, token.IsSignatureValid())
				assert.Equal(t, alg, token.SignatureAlgorithm)
			})

			tokenString, _, err := f.strategy.Encode(t.Context(), claims, WithClient(issuer))
			require.NoError(t, err)

			parts := strings.Split(tokenString, ".")

			t.Run("ShouldVerifySignatureFromAnotherImplementation", func(t *testing.T) {
				foreign := signIndependently(t, f, alg, kid, `{"iss":"foreign","sub":"jane"}`)

				token, err := f.strategy.Decode(t.Context(), foreign, WithClient(issuer))
				require.NoError(t, err)
				assert.True(t, token.IsSignatureValid())
				assert.Equal(t, "jane", token.Claims.ToMapClaims()[ClaimSubject])
			})

			t.Run("ShouldRejectTamperedSignature", func(t *testing.T) {
				token, err := f.strategy.Decode(t.Context(), joinSegments(parts[0], parts[1], flipSegment(t, parts[2])), WithClient(issuer))
				assertValidationError(t, err, ValidationErrorSignatureInvalid)

				if token != nil {
					assert.False(t, token.IsSignatureValid())
				}
			})

			t.Run("ShouldRejectTamperedPayload", func(t *testing.T) {
				payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"example.com","sub":"mallory"}`))

				_, err := f.strategy.Decode(t.Context(), joinSegments(parts[0], payload, parts[2]), WithClient(issuer))
				assertValidationError(t, err, ValidationErrorSignatureInvalid)
			})

			t.Run("ShouldRejectSignatureFromAnotherKey", func(t *testing.T) {
				_, err := f.strategy.Decode(t.Context(), tokenString, WithClient(f.clientWithOtherKeys(alg)))
				assertValidationError(t, err, ValidationErrorSignatureInvalid)
			})

			t.Run("ShouldRejectWhenTheAlgorithmIsNotPermitted", func(t *testing.T) {
				permitted := slices.DeleteFunc(slices.Clone(SignatureAlgorithms), func(other jose.SignatureAlgorithm) bool { return other == alg })

				_, err := f.strategy.Decode(t.Context(), tokenString, WithClient(issuer), WithSigAlgorithm(permitted...))
				assertValidationError(t, err, ValidationErrorMalformed)
			})

			t.Run("ShouldRejectStrippedSignature", func(t *testing.T) {
				_, err := f.strategy.Decode(t.Context(), joinSegments(parts[0], parts[1], ""), WithClient(issuer))
				require.Error(t, err)
			})

			t.Run("ShouldRejectAlgorithmSubstitution", func(t *testing.T) {
				for _, other := range SignatureAlgorithms {
					if other == alg {
						continue
					}

					t.Run(string(other), func(t *testing.T) {
						header := base64.RawURLEncoding.EncodeToString(fmt.Appendf(nil, `{"alg":%q,"kid":%q,"typ":"JWT"}`, other, kid))
						key := f.verificationKey(alg)

						_, err := f.strategy.Decode(t.Context(), joinSegments(header, parts[1], parts[2]), WithKeyFunc(func(_ context.Context, _ *josejwt.JSONWebToken, _ MapClaims) (*jose.JSONWebKey, error) {
							return &jose.JSONWebKey{Key: key, KeyID: kid, Use: JSONWebTokenUseSignature}, nil
						}))
						require.Error(t, err)
					})
				}
			})
		})
	}

	t.Run("ShouldRejectSymmetricSigningWithAnRSAPublicKeyAsTheSecret", func(t *testing.T) {
		secret := f.keys.rsa.N.Bytes()

		tokenString, err := NewWithClaims(jose.HS256, claims).CompactSignedString(secret)
		require.NoError(t, err)

		_, err = f.strategy.Decode(t.Context(), tokenString)
		assertValidationError(t, err, ValidationErrorUnverifiable)
	})

	t.Run("ShouldRejectUnsignedTokenWhenAnAlgorithmIsRegistered", func(t *testing.T) {
		tokenString, err := NewWithClaims(SigningMethodNone, claims).CompactSignedString(UnsafeAllowNoneSignatureType)
		require.NoError(t, err)

		_, err = f.strategy.Decode(t.Context(), tokenString, WithClient(f.client(jose.RS256, "", "", "")))
		assertValidationError(t, err, ValidationErrorMalformed)
	})

	t.Run("ShouldRejectClientSecretShorterThanTheMACKey", func(t *testing.T) {
		for alg, octets := range map[jose.SignatureAlgorithm]int{jose.HS256: 32, jose.HS384: 48, jose.HS512: 64} {
			t.Run(string(alg), func(t *testing.T) {
				client := f.client(alg, "", "", "")
				client.secret = client.secret[:octets-1]

				_, _, err := f.strategy.Encode(t.Context(), claims, WithClient(client))
				require.ErrorContains(t, err, fmt.Sprintf("requires a MAC key of at least %d octets", octets))

				client.secret = f.secret[:octets]

				_, _, err = f.strategy.Encode(t.Context(), claims, WithClient(client))
				require.NoError(t, err)
			})
		}
	})

	t.Run("ShouldRejectPublicClientUsingSymmetricSignature", func(t *testing.T) {
		for _, alg := range []jose.SignatureAlgorithm{jose.HS256, jose.HS384, jose.HS512} {
			client := f.client(alg, "", "", "")
			client.public = true

			_, _, err := f.strategy.Encode(t.Context(), claims, WithClient(client))
			require.ErrorContains(t, err, descriptionPublicClientSymmetric, "%s", alg)
		}
	})

	t.Run("ShouldRejectKeyWhichCannotUseTheAlgorithm", func(t *testing.T) {
		testCases := []struct {
			alg jose.SignatureAlgorithm
			key any
		}{
			{jose.RS256, f.keys.p256},
			{jose.PS256, f.keys.ed25519},
			{jose.ES256, f.keys.p384},
			{jose.ES384, f.keys.p521},
			{jose.ES512, f.keys.p256},
			{jose.ES256, f.keys.rsa},
			{jose.EdDSA, f.keys.rsa},
			{jose.Ed25519, f.keys.p256},
		}

		for _, tc := range testCases {
			t.Run(fmt.Sprintf("%s/%T", tc.alg, tc.key), func(t *testing.T) {
				_, _, err := EncodeCompactSigned(t.Context(), claims, &Headers{}, &jose.JSONWebKey{Key: tc.key, KeyID: "mismatch", Algorithm: string(tc.alg), Use: JSONWebTokenUseSignature})
				require.Error(t, err)
			})
		}
	})
}

func TestEncryptionAlgorithmsMatrix(t *testing.T) {
	f := getAlgorithmFixtures(t)

	claims := MapClaims{ClaimIssuer: "example.com", ClaimSubject: "john"}

	for _, tc := range f.encryptionCases() {
		for _, enc := range ContentEncryptionAlgorithms {
			t.Run(tc.name+"/"+string(enc), func(t *testing.T) {
				t.Parallel()

				client := f.client(jose.ES256, tc.alg, tc.kid, enc)

				tokenString, signature, err := f.strategy.Encode(t.Context(), claims, WithClient(client))
				require.NoError(t, err)
				require.True(t, IsEncryptedJWT(tokenString))
				assert.NotEmpty(t, signature)

				assertJWEStructure(t, tokenString, tc.alg, tc.kid, enc)

				inner := decryptIndependently(t, tokenString, tc.private, f.secret)

				verifySignatureIndependently(t, f, jose.ES256, string(inner))

				decrypted, innerSignature, jwe, err := f.strategy.Decrypt(t.Context(), tokenString, WithClient(client))
				require.NoError(t, err)
				require.NotNil(t, jwe)
				assert.Equal(t, string(inner), decrypted)
				assert.Equal(t, signature, innerSignature)

				token, err := f.strategy.Decode(t.Context(), tokenString, WithClient(client))
				require.NoError(t, err)
				assert.True(t, token.IsSignatureValid())
				assert.NoError(t, token.Valid(ValidateAlgorithm(string(jose.ES256)), ValidateKeyAlgorithm(string(tc.alg)), ValidateContentEncryption(string(enc)), ValidateEncryptionKeyID(tc.kid)))
				assert.Equal(t, tc.alg, token.KeyAlgorithm)
				assert.Equal(t, enc, token.ContentEncryption)
				assert.Equal(t, tc.kid, token.EncryptionKeyID)
				assert.Equal(t, "john", token.Claims.ToMapClaims()[ClaimSubject])

				t.Run("ShouldRejectWhenTheKeyAlgorithmIsNotPermitted", func(t *testing.T) {
					permitted := slices.DeleteFunc(slices.Clone(EncryptionKeyAlgorithms), func(other jose.KeyAlgorithm) bool { return other == tc.alg })

					_, _, _, err := f.strategy.Decrypt(t.Context(), tokenString, WithClient(client), WithKeyAlgorithm(permitted...))
					assertValidationError(t, err, ValidationErrorMalformed)
				})

				t.Run("ShouldRejectWhenTheContentEncryptionIsNotPermitted", func(t *testing.T) {
					permitted := slices.DeleteFunc(slices.Clone(ContentEncryptionAlgorithms), func(other jose.ContentEncryption) bool { return other == enc })

					_, _, _, err := f.strategy.Decrypt(t.Context(), tokenString, WithClient(client), WithContentEncryption(permitted...))
					assertValidationError(t, err, ValidationErrorMalformed)
				})

				// PBKDF2 makes each attempt expensive, so the password based algorithms are only tampered with once per
				// key algorithm as the content encryption code is shared with every other key algorithm.
				if IsEncryptedJWTPasswordBasedAlg(tc.alg) && enc != jose.A128GCM {
					return
				}

				parts := strings.Split(tokenString, ".")

				for i, segment := range []string{"Header", "EncryptedKey", "InitializationVector", "Ciphertext", "AuthenticationTag"} {
					t.Run("ShouldRejectTampered"+segment, func(t *testing.T) {
						if parts[i] == "" {
							t.Skip("the segment is empty for this key algorithm")
						}

						tampered := slices.Clone(parts)

						if i == 0 {
							tampered[i] = addHeaderMember(t, parts[i])
						} else {
							tampered[i] = flipSegment(t, parts[i])
						}

						_, _, _, err := f.strategy.Decrypt(t.Context(), joinSegments(tampered...), WithClient(client))
						assertValidationError(t, err, ValidationErrorMalformed)
					})
				}

				t.Run("ShouldRejectUnexpectedEncryptedKey", func(t *testing.T) {
					if parts[1] != "" {
						t.Skip("the segment is not empty for this key algorithm")
					}

					tampered := slices.Clone(parts)
					tampered[1] = base64.RawURLEncoding.EncodeToString(make([]byte, 32))

					_, _, _, err := f.strategy.Decrypt(t.Context(), joinSegments(tampered...), WithClient(client))
					assertValidationError(t, err, ValidationErrorMalformed)
				})

				t.Run("ShouldRejectAnotherKey", func(t *testing.T) {
					other := f.client(jose.ES256, tc.alg, tc.kid, enc)
					other.secret = f.otherSecret

					_, _, _, err := f.otherStrategy.Decrypt(t.Context(), tokenString, WithClient(other))
					assertValidationError(t, err, ValidationErrorMalformed)
				})
			})
		}
	}

	t.Run("ShouldDefaultContentEncryption", func(t *testing.T) {
		tokenString, _, err := f.strategy.Encode(t.Context(), claims, WithClient(f.client(jose.ES256, jose.A128KW, "", "")))
		require.NoError(t, err)

		assertJWEStructure(t, tokenString, jose.A128KW, "", jose.A128CBC_HS256)
	})

	t.Run("ShouldRejectPublicClientUsingSymmetricEncryption", func(t *testing.T) {
		for _, alg := range EncryptionKeyAlgorithms {
			if !IsEncryptedJWTClientSecretAlg(alg) {
				continue
			}

			client := f.client(jose.ES256, alg, "", jose.A128GCM)
			client.public = true

			_, _, err := f.strategy.Encode(t.Context(), claims, WithClient(client))
			require.ErrorContains(t, err, descriptionPublicClientSymmetric, "%s", alg)
		}
	})

	t.Run("ShouldRejectUnsupportedContentEncryption", func(t *testing.T) {
		_, _, err := f.strategy.Encode(t.Context(), claims, WithClient(f.client(jose.ES256, jose.DIRECT, "", "A128GCM-BAD")))
		require.ErrorContains(t, err, "Unsupported content encryption")
	})

	t.Run("ShouldRejectKeyWhichCannotUseTheAlgorithm", func(t *testing.T) {
		testCases := []struct {
			alg jose.KeyAlgorithm
			key any
		}{
			{jose.RSA_OAEP_256, &f.keys.p256.PublicKey},
			{jose.RSA1_5, f.keys.ed25519.Public()},
			{jose.ECDH_ES, &f.keys.rsa.PublicKey},
			{jose.ECDH_ES_A256KW, f.keys.ed25519.Public()},
		}

		for _, tc := range testCases {
			t.Run(fmt.Sprintf("%s/%T", tc.alg, tc.key), func(t *testing.T) {
				client := f.client(jose.ES256, tc.alg, "mismatch", jose.A128GCM)
				client.jwks = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: tc.key, KeyID: "mismatch"}}}

				_, _, err := f.strategy.Encode(t.Context(), claims, WithClient(client))
				require.Error(t, err)
			})
		}
	})
}

func TestSignatureAndEncryptionAlgorithmsCombined(t *testing.T) {
	f := getAlgorithmFixtures(t)

	claims := MapClaims{ClaimIssuer: "example.com", ClaimSubject: "john"}

	for _, alg := range SignatureAlgorithms {
		for _, tc := range f.encryptionCases() {
			encs := ContentEncryptionAlgorithms

			if IsEncryptedJWTPasswordBasedAlg(tc.alg) {
				encs = []jose.ContentEncryption{jose.A128GCM}
			}

			for _, enc := range encs {
				t.Run(string(alg)+"/"+tc.name+"/"+string(enc), func(t *testing.T) {
					t.Parallel()

					client := f.client(alg, tc.alg, tc.kid, enc)

					tokenString, _, err := f.strategy.Encode(t.Context(), claims, WithClient(client))
					require.NoError(t, err)

					token, err := f.strategy.Decode(t.Context(), tokenString, WithClient(client))
					require.NoError(t, err)
					assert.True(t, token.IsSignatureValid())
					assert.Equal(t, alg, token.SignatureAlgorithm)
					assert.Equal(t, tc.alg, token.KeyAlgorithm)
					assert.Equal(t, enc, token.ContentEncryption)
					assert.Equal(t, "john", token.Claims.ToMapClaims()[ClaimSubject])
				})
			}
		}
	}
}

type algorithmKeys struct {
	rsa              *rsa.PrivateKey
	p256, p384, p521 *ecdsa.PrivateKey
	ed25519          ed25519.PrivateKey
}

type encryptionCase struct {
	name    string
	alg     jose.KeyAlgorithm
	kid     string
	private any
}

type algorithmFixtures struct {
	keys, other         *algorithmKeys
	secret, otherSecret []byte

	strategy, otherStrategy *DefaultStrategy

	clientKeys, otherClientKeys *jose.JSONWebKeySet
}

var getAlgorithmFixturesOnce = sync.OnceValues(newAlgorithmFixtures)

func getAlgorithmFixtures(t *testing.T) *algorithmFixtures {
	t.Helper()

	f, err := getAlgorithmFixturesOnce()
	require.NoError(t, err)

	return f
}

func newAlgorithmFixtures() (f *algorithmFixtures, err error) {
	f = &algorithmFixtures{
		secret:      bytes.Repeat([]byte("client-secret-0123456789"), 3),
		otherSecret: bytes.Repeat([]byte("another-secret-987654321"), 3),
	}

	if f.keys, err = newAlgorithmKeys(); err != nil {
		return nil, err
	}

	if f.other, err = newAlgorithmKeys(); err != nil {
		return nil, err
	}

	var issuer *jose.JSONWebKeySet

	issuer, f.clientKeys = f.keySets(f.keys)
	f.strategy = &DefaultStrategy{Config: &testConfig{}, Issuer: NewDefaultIssuerUnverifiedFromJWKS(issuer)}

	issuer, f.otherClientKeys = f.keySets(f.other)
	f.otherStrategy = &DefaultStrategy{Config: &testConfig{}, Issuer: NewDefaultIssuerUnverifiedFromJWKS(issuer)}

	return f, nil
}

func newAlgorithmKeys() (keys *algorithmKeys, err error) {
	keys = &algorithmKeys{}

	if keys.rsa, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		return nil, err
	}

	if keys.p256, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return nil, err
	}

	if keys.p384, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader); err != nil {
		return nil, err
	}

	if keys.p521, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader); err != nil {
		return nil, err
	}

	if _, keys.ed25519, err = ed25519.GenerateKey(rand.Reader); err != nil {
		return nil, err
	}

	return keys, nil
}

func (f *algorithmFixtures) keySets(keys *algorithmKeys) (issuer, client *jose.JSONWebKeySet) {
	issuer, client = &jose.JSONWebKeySet{}, &jose.JSONWebKeySet{}

	add := func(private crypto.Signer, kid, alg, use string) {
		issuer.Keys = append(issuer.Keys, jose.JSONWebKey{Key: private, KeyID: kid, Algorithm: alg, Use: use})
		client.Keys = append(client.Keys, jose.JSONWebKey{Key: private.Public(), KeyID: kid, Algorithm: alg, Use: use})
	}

	for _, alg := range SignatureAlgorithms {
		if !IsSignedJWTClientSecretAlg(alg) {
			add(keys.signer(alg), f.signKID(alg), string(alg), JSONWebTokenUseSignature)
		}
	}

	for _, alg := range EncryptionKeyAlgorithms {
		switch {
		case IsEncryptedJWTClientSecretAlg(alg):
		case strings.HasPrefix(string(alg), "RSA"):
			add(keys.rsa, encKID(alg, ""), string(alg), JSONWebTokenUseEncryption)
		default:
			for curve, key := range keys.curves() {
				add(key, encKID(alg, curve), string(alg), JSONWebTokenUseEncryption)
			}
		}
	}

	return issuer, client
}

func (k *algorithmKeys) curves() map[string]*ecdsa.PrivateKey {
	return map[string]*ecdsa.PrivateKey{"P-256": k.p256, "P-384": k.p384, "P-521": k.p521}
}

func (k *algorithmKeys) signer(alg jose.SignatureAlgorithm) crypto.Signer {
	switch alg {
	case jose.ES256:
		return k.p256
	case jose.ES384:
		return k.p384
	case jose.ES512:
		return k.p521
	case jose.EdDSA, jose.Ed25519:
		return k.ed25519
	default:
		return k.rsa
	}
}

func (f *algorithmFixtures) signKID(alg jose.SignatureAlgorithm) string {
	if IsSignedJWTClientSecretAlg(alg) {
		return ""
	}

	return "sig-" + string(alg)
}

func encKID(alg jose.KeyAlgorithm, curve string) string {
	if curve == "" {
		return "enc-" + string(alg)
	}

	return "enc-" + string(alg) + "-" + curve
}

// client returns a client which holds the secret and the public keys of the fixture, so the same value is able to both
// produce and consume a token.
func (f *algorithmFixtures) client(alg jose.SignatureAlgorithm, encAlg jose.KeyAlgorithm, kid string, enc jose.ContentEncryption) *testClient {
	return &testClient{
		id:      "client",
		secret:  f.secret,
		kid:     f.signKID(alg),
		alg:     string(alg),
		encKID:  kid,
		encAlg:  string(encAlg),
		enc:     string(enc),
		csigned: true,
		jwks:    f.clientKeys,
	}
}

func (f *algorithmFixtures) clientWithOtherKeys(alg jose.SignatureAlgorithm) *testClient {
	client := f.client(alg, "", "", "")
	client.secret = f.otherSecret
	client.jwks = f.otherClientKeys

	return client
}

func (f *algorithmFixtures) verificationKey(alg jose.SignatureAlgorithm) any {
	if IsSignedJWTClientSecretAlg(alg) {
		return f.secret
	}

	return f.keys.signer(alg).Public()
}

func (f *algorithmFixtures) encryptionCases() (cases []encryptionCase) {
	for _, alg := range EncryptionKeyAlgorithms {
		switch {
		case IsEncryptedJWTClientSecretAlg(alg):
			cases = append(cases, encryptionCase{name: string(alg), alg: alg})
		case strings.HasPrefix(string(alg), "RSA"):
			cases = append(cases, encryptionCase{name: string(alg), alg: alg, kid: encKID(alg, ""), private: f.keys.rsa})
		default:
			for _, curve := range []string{"P-256", "P-384", "P-521"} {
				cases = append(cases, encryptionCase{name: string(alg) + "/" + curve, alg: alg, kid: encKID(alg, curve), private: f.keys.curves()[curve]})
			}
		}
	}

	return cases
}

func algHash(alg jose.SignatureAlgorithm) crypto.Hash {
	switch alg {
	case jose.HS256, jose.RS256, jose.PS256, jose.ES256:
		return crypto.SHA256
	case jose.HS384, jose.RS384, jose.PS384, jose.ES384:
		return crypto.SHA384
	case jose.HS512, jose.RS512, jose.PS512, jose.ES512, jose.EdDSA, jose.Ed25519:
		return crypto.SHA512
	default:
		return 0
	}
}

func digest(alg jose.SignatureAlgorithm, input string) []byte {
	h := algHash(alg).New()
	h.Write([]byte(input))

	return h.Sum(nil)
}

// verifySignatureIndependently verifies a JWS using only the standard library per RFC 7518 Section 3 and RFC 8037
// Section 3.1, including the signature length each algorithm requires.
func verifySignatureIndependently(t *testing.T, f *algorithmFixtures, alg jose.SignatureAlgorithm, tokenString string) {
	t.Helper()

	parts := strings.Split(tokenString, ".")
	require.Len(t, parts, 3)

	input := parts[0] + "." + parts[1]

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)

	switch alg {
	case jose.HS256, jose.HS384, jose.HS512:
		mac := hmac.New(algHash(alg).New, f.secret)
		mac.Write([]byte(input))
		assert.True(t, hmac.Equal(mac.Sum(nil), signature))
		assert.Len(t, signature, algHash(alg).Size())
	case jose.RS256, jose.RS384, jose.RS512:
		assert.Len(t, signature, f.keys.rsa.Size())
		assert.NoError(t, rsa.VerifyPKCS1v15(&f.keys.rsa.PublicKey, algHash(alg), digest(alg, input), signature))
	case jose.PS256, jose.PS384, jose.PS512:
		assert.Len(t, signature, f.keys.rsa.Size())
		assert.NoError(t, rsa.VerifyPSS(&f.keys.rsa.PublicKey, algHash(alg), digest(alg, input), signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}))
	case jose.ES256, jose.ES384, jose.ES512:
		key := f.keys.signer(alg).(*ecdsa.PrivateKey)
		size := (key.Curve.Params().BitSize + 7) / 8

		require.Len(t, signature, size*2)
		assert.True(t, ecdsa.Verify(&key.PublicKey, digest(alg, input), new(big.Int).SetBytes(signature[:size]), new(big.Int).SetBytes(signature[size:])))
	case jose.EdDSA, jose.Ed25519:
		assert.Len(t, signature, ed25519.SignatureSize)
		assert.True(t, ed25519.Verify(f.keys.ed25519.Public().(ed25519.PublicKey), []byte(input), signature))
	default:
		require.FailNow(t, "no independent verification", "%s", alg)
	}
}

func signIndependently(t *testing.T, f *algorithmFixtures, alg jose.SignatureAlgorithm, kid, payload string) string {
	t.Helper()

	header := map[string]string{JSONWebTokenHeaderAlgorithm: string(alg), JSONWebTokenHeaderType: JSONWebTokenTypeJWT}

	if kid != "" {
		header[JSONWebTokenHeaderKeyIdentifier] = kid
	}

	raw, err := json.Marshal(header)
	require.NoError(t, err)

	input := base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload))

	var signature []byte

	switch alg {
	case jose.HS256, jose.HS384, jose.HS512:
		mac := hmac.New(algHash(alg).New, f.secret)
		mac.Write([]byte(input))
		signature = mac.Sum(nil)
	case jose.RS256, jose.RS384, jose.RS512:
		signature, err = rsa.SignPKCS1v15(rand.Reader, f.keys.rsa, algHash(alg), digest(alg, input))
	case jose.PS256, jose.PS384, jose.PS512:
		signature, err = rsa.SignPSS(rand.Reader, f.keys.rsa, algHash(alg), digest(alg, input), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case jose.ES256, jose.ES384, jose.ES512:
		key := f.keys.signer(alg).(*ecdsa.PrivateKey)
		size := (key.Curve.Params().BitSize + 7) / 8

		var r, s *big.Int

		r, s, err = ecdsa.Sign(rand.Reader, key, digest(alg, input))
		require.NoError(t, err)

		signature = append(r.FillBytes(make([]byte, size)), s.FillBytes(make([]byte, size))...)
	case jose.EdDSA, jose.Ed25519:
		signature = ed25519.Sign(f.keys.ed25519, []byte(input))
	default:
		require.FailNow(t, "no independent signer", "%s", alg)
	}

	require.NoError(t, err)

	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// contentEncryptionSizes returns the CEK and authentication tag octets per RFC 7518 Sections 5.2 and 5.3.
func contentEncryptionSizes(t *testing.T, enc jose.ContentEncryption) (cek, iv, tag int) {
	t.Helper()

	switch enc {
	case jose.A128CBC_HS256:
		return 32, 16, 16
	case jose.A192CBC_HS384:
		return 48, 16, 24
	case jose.A256CBC_HS512:
		return 64, 16, 32
	case jose.A128GCM:
		return 16, 12, 16
	case jose.A192GCM:
		return 24, 12, 16
	case jose.A256GCM:
		return 32, 12, 16
	default:
		require.FailNow(t, "no sizes", "%s", enc)

		return 0, 0, 0
	}
}

func keyWrapSize(alg jose.KeyAlgorithm) int {
	switch alg {
	case jose.A128KW, jose.A128GCMKW, jose.ECDH_ES_A128KW, jose.PBES2_HS256_A128KW:
		return 16
	case jose.A192KW, jose.A192GCMKW, jose.ECDH_ES_A192KW, jose.PBES2_HS384_A192KW:
		return 24
	default:
		return 32
	}
}

// assertJWEStructure checks the JOSE Header and segment lengths of a Nested JWT per RFC 7516 Section 7.1, RFC 7518
// Section 4 and RFC 7519 Section 5.2.
func assertJWEStructure(t *testing.T, tokenString string, alg jose.KeyAlgorithm, kid string, enc jose.ContentEncryption) {
	t.Helper()

	parts := strings.Split(tokenString, ".")
	require.Len(t, parts, 5)

	header := decodeJOSEHeader(t, parts[0])

	assert.Equal(t, string(alg), header[JSONWebTokenHeaderAlgorithm])
	assert.Equal(t, string(enc), header[JSONWebTokenHeaderEncryptionAlgorithm])
	assert.Equal(t, JSONWebTokenTypeJWT, header[JSONWebTokenHeaderContentType])
	assert.Equal(t, JSONWebTokenTypeJWT, header[JSONWebTokenHeaderType])

	if kid == "" {
		assert.NotContains(t, header, JSONWebTokenHeaderKeyIdentifier)
	} else {
		assert.Equal(t, kid, header[JSONWebTokenHeaderKeyIdentifier])
	}

	cekSize, ivSize, tagSize := contentEncryptionSizes(t, enc)

	encryptedKey := mustDecodeSegment(t, parts[1])

	switch {
	case alg == jose.DIRECT, alg == jose.ECDH_ES:
		assert.Empty(t, encryptedKey)
	case strings.HasPrefix(string(alg), "RSA"):
		assert.Len(t, encryptedKey, 256)
	case alg == jose.A128GCMKW, alg == jose.A192GCMKW, alg == jose.A256GCMKW:
		assert.Len(t, encryptedKey, cekSize)
	default:
		assert.Len(t, encryptedKey, cekSize+8)
	}

	assert.Len(t, mustDecodeSegment(t, parts[2]), ivSize)
	assert.Len(t, mustDecodeSegment(t, parts[4]), tagSize)

	gcmkw := alg == jose.A128GCMKW || alg == jose.A192GCMKW || alg == jose.A256GCMKW
	ecdhes := strings.HasPrefix(string(alg), "ECDH")
	pbes2 := IsEncryptedJWTPasswordBasedAlg(alg)

	for member, expected := range map[string]bool{"iv": gcmkw, "tag": gcmkw, "epk": ecdhes, "p2s": pbes2, "p2c": pbes2} {
		if expected {
			assert.Contains(t, header, member)
		} else {
			assert.NotContains(t, header, member)
		}
	}

	if pbes2 {
		assert.GreaterOrEqual(t, len(mustDecodeSegment(t, header["p2s"].(string))), 8)
		assert.GreaterOrEqual(t, header["p2c"], float64(DefaultJWEPBES2CountMinimum))
		assert.LessOrEqual(t, header["p2c"], float64(DefaultJWEPBES2CountMaximum))
	}
}

// decryptIndependently decrypts a compact JWE using only the standard library per RFC 7518 Sections 4 and 5.
func decryptIndependently(t *testing.T, tokenString string, private any, secret []byte) []byte {
	t.Helper()

	parts := strings.Split(tokenString, ".")
	require.Len(t, parts, 5)

	header := decodeJOSEHeader(t, parts[0])

	alg, enc := jose.KeyAlgorithm(header[JSONWebTokenHeaderAlgorithm].(string)), jose.ContentEncryption(header[JSONWebTokenHeaderEncryptionAlgorithm].(string))

	cek := unwrapCEKIndependently(t, header, alg, enc, mustDecodeSegment(t, parts[1]), private, secret)

	cekSize, _, _ := contentEncryptionSizes(t, enc)
	require.Len(t, cek, cekSize)

	iv, ciphertext, tag := mustDecodeSegment(t, parts[2]), mustDecodeSegment(t, parts[3]), mustDecodeSegment(t, parts[4])
	aad := []byte(parts[0])

	if enc == jose.A128GCM || enc == jose.A192GCM || enc == jose.A256GCM {
		return openGCM(t, cek, iv, append(ciphertext, tag...), aad)
	}

	macKey, encKey := cek[:len(cek)/2], cek[len(cek)/2:]

	h := map[jose.ContentEncryption]func() hash.Hash{jose.A128CBC_HS256: sha256.New, jose.A192CBC_HS384: sha512.New384, jose.A256CBC_HS512: sha512.New}[enc]

	mac := hmac.New(h, macKey)
	mac.Write(aad)
	mac.Write(iv)
	mac.Write(ciphertext)
	require.NoError(t, binary.Write(mac, binary.BigEndian, uint64(len(aad))*8))
	require.True(t, hmac.Equal(mac.Sum(nil)[:len(macKey)], tag), "authentication tag mismatch")

	block, err := aes.NewCipher(encKey)
	require.NoError(t, err)

	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)

	padding := int(plaintext[len(plaintext)-1])
	require.True(t, padding > 0 && padding <= aes.BlockSize)

	return plaintext[:len(plaintext)-padding]
}

func unwrapCEKIndependently(t *testing.T, header map[string]any, alg jose.KeyAlgorithm, enc jose.ContentEncryption, encryptedKey []byte, private any, secret []byte) (cek []byte) {
	t.Helper()

	var err error

	switch alg {
	case jose.RSA1_5:
		cek, err = rsa.DecryptPKCS1v15(rand.Reader, private.(*rsa.PrivateKey), encryptedKey) //nolint:staticcheck
	case jose.RSA_OAEP:
		cek, err = rsa.DecryptOAEP(sha1.New(), rand.Reader, private.(*rsa.PrivateKey), encryptedKey, nil) //nolint:gosec
	case jose.RSA_OAEP_256:
		cek, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, private.(*rsa.PrivateKey), encryptedKey, nil)
	case jose.DIRECT:
		cek = deriveClientSecretKey(t, alg, enc, secret)
	case jose.A128KW, jose.A192KW, jose.A256KW:
		cek = aesKeyUnwrap(t, deriveClientSecretKey(t, alg, enc, secret), encryptedKey)
	case jose.A128GCMKW, jose.A192GCMKW, jose.A256GCMKW:
		iv, tag := mustDecodeSegment(t, header["iv"].(string)), mustDecodeSegment(t, header["tag"].(string))
		cek = openGCM(t, deriveClientSecretKey(t, alg, enc, secret), iv, append(slices.Clone(encryptedKey), tag...), nil)
	case jose.PBES2_HS256_A128KW, jose.PBES2_HS384_A192KW, jose.PBES2_HS512_A256KW:
		h := map[jose.KeyAlgorithm]func() hash.Hash{jose.PBES2_HS256_A128KW: sha256.New, jose.PBES2_HS384_A192KW: sha512.New384, jose.PBES2_HS512_A256KW: sha512.New}[alg]

		salt := append(append([]byte(alg), 0), mustDecodeSegment(t, header["p2s"].(string))...)

		var kek []byte

		kek, err = pbkdf2.Key(h, string(deriveClientSecretKey(t, alg, enc, secret)), salt, int(header["p2c"].(float64)), keyWrapSize(alg))
		require.NoError(t, err)

		cek = aesKeyUnwrap(t, kek, encryptedKey)
	case jose.ECDH_ES:
		size, _, _ := contentEncryptionSizes(t, enc)
		cek = concatKDF(t, header, private.(*ecdsa.PrivateKey), string(enc), size)
	case jose.ECDH_ES_A128KW, jose.ECDH_ES_A192KW, jose.ECDH_ES_A256KW:
		cek = aesKeyUnwrap(t, concatKDF(t, header, private.(*ecdsa.PrivateKey), string(alg), keyWrapSize(alg)), encryptedKey)
	default:
		require.FailNow(t, "no independent key unwrap", "%s", alg)
	}

	require.NoError(t, err)

	return cek
}

// deriveClientSecretKey derives the key per OpenID Connect Core 1.0 Section 10.2. The password based algorithms are not
// described by that section, so the hash follows the PRF of the algorithm.
func deriveClientSecretKey(t *testing.T, alg jose.KeyAlgorithm, enc jose.ContentEncryption, secret []byte) []byte {
	t.Helper()

	var size int

	switch alg {
	case jose.DIRECT:
		size, _, _ = contentEncryptionSizes(t, enc)
	default:
		size = keyWrapSize(alg)
	}

	var sum []byte

	switch {
	case alg == jose.PBES2_HS384_A192KW:
		v := sha512.Sum384(secret)
		sum = v[:]
	case alg == jose.PBES2_HS512_A256KW:
		v := sha512.Sum512(secret)
		sum = v[:]
	case size <= 32:
		v := sha256.Sum256(secret)
		sum = v[:]
	case size <= 48:
		v := sha512.Sum384(secret)
		sum = v[:]
	default:
		v := sha512.Sum512(secret)
		sum = v[:]
	}

	return sum[:size]
}

func openGCM(t *testing.T, key, iv, sealed, aad []byte) []byte {
	t.Helper()

	block, err := aes.NewCipher(key)
	require.NoError(t, err)

	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)

	plaintext, err := aead.Open(nil, iv, sealed, aad)
	require.NoError(t, err)

	return plaintext
}

// aesKeyUnwrap implements RFC 3394 Section 2.2.2.
func aesKeyUnwrap(t *testing.T, kek, wrapped []byte) []byte {
	t.Helper()

	require.Zero(t, len(wrapped)%8)

	block, err := aes.NewCipher(kek)
	require.NoError(t, err)

	n := len(wrapped)/8 - 1

	a := binary.BigEndian.Uint64(wrapped[:8])
	r := slices.Clone(wrapped[8:])

	buffer := make([]byte, aes.BlockSize)

	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			binary.BigEndian.PutUint64(buffer[:8], a^uint64(n*j+i)) //nolint:gosec
			copy(buffer[8:], r[(i-1)*8:i*8])
			block.Decrypt(buffer, buffer)

			a = binary.BigEndian.Uint64(buffer[:8])
			copy(r[(i-1)*8:i*8], buffer[8:])
		}
	}

	expected := make([]byte, 8)
	binary.BigEndian.PutUint64(expected, a)

	require.Equal(t, 1, subtle.ConstantTimeCompare(expected, bytes.Repeat([]byte{0xA6}, 8)), "key unwrap integrity check failed")

	return r
}

// concatKDF implements RFC 7518 Section 4.6.2 with the hash fixed to SHA-256.
func concatKDF(t *testing.T, header map[string]any, private *ecdsa.PrivateKey, algorithmID string, size int) []byte {
	t.Helper()

	epk := header["epk"].(map[string]any)

	byteLen := (private.Curve.Params().BitSize + 7) / 8

	uncompressed := make([]byte, 1, 1+byteLen*2)
	uncompressed[0] = 4
	uncompressed = append(uncompressed, leftPad(mustDecodeSegment(t, epk["x"].(string)), byteLen)...)
	uncompressed = append(uncompressed, leftPad(mustDecodeSegment(t, epk["y"].(string)), byteLen)...)

	curve := map[int]ecdh.Curve{256: ecdh.P256(), 384: ecdh.P384(), 521: ecdh.P521()}[private.Curve.Params().BitSize]

	public, err := curve.NewPublicKey(uncompressed)
	require.NoError(t, err)

	own, err := private.ECDH()
	require.NoError(t, err)

	z, err := own.ECDH(public)
	require.NoError(t, err)

	otherInfo := lengthPrefixed([]byte(algorithmID))

	for _, member := range []string{"apu", "apv"} {
		var value []byte

		if encoded, ok := header[member].(string); ok {
			value = mustDecodeSegment(t, encoded)
		}

		otherInfo = append(otherInfo, lengthPrefixed(value)...)
	}

	otherInfo = binary.BigEndian.AppendUint32(otherInfo, uint32(size)*8) //nolint:gosec

	var output []byte

	for counter := uint32(1); len(output) < size; counter++ {
		h := sha256.New()
		require.NoError(t, binary.Write(h, binary.BigEndian, counter))
		h.Write(z)
		h.Write(otherInfo)
		output = h.Sum(output)
	}

	return output[:size]
}

func lengthPrefixed(value []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(value))), value...) //nolint:gosec
}

func leftPad(value []byte, size int) []byte {
	return append(make([]byte, size-len(value)), value...)
}

func decodeJOSEHeader(t *testing.T, segment string) (header map[string]any) {
	t.Helper()

	require.NoError(t, json.Unmarshal(mustDecodeSegment(t, segment), &header))

	return header
}

func mustDecodeSegment(t *testing.T, segment string) []byte {
	t.Helper()

	value, err := base64.RawURLEncoding.DecodeString(segment)
	require.NoError(t, err)

	return value
}

func flipSegment(t *testing.T, segment string) string {
	t.Helper()

	value := mustDecodeSegment(t, segment)
	value[0] ^= 0x01

	return base64.RawURLEncoding.EncodeToString(value)
}

func addHeaderMember(t *testing.T, segment string) string {
	t.Helper()

	header := decodeJOSEHeader(t, segment)
	header["tampered"] = true

	raw, err := json.Marshal(header)
	require.NoError(t, err)

	return base64.RawURLEncoding.EncodeToString(raw)
}

func joinSegments(segments ...string) string {
	return strings.Join(segments, ".")
}

func assertValidationError(t *testing.T, err error, flag uint32) {
	t.Helper()

	var verr *ValidationError

	require.ErrorAs(t, err, &verr)
	assert.True(t, verr.Has(flag), "expected validation error flag %d, got %d: %v", flag, verr.Errors, err)
}
