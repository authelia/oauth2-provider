// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"
	"authelia.com/provider/jose/jwt"

	"authelia.com/provider/oauth2/internal/gen"
)

func TestDefaultStrategy(t *testing.T) {
	ctx := t.Context()

	config := &testConfig{}

	issuerRS256, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	issuerES512, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	issuerES512enc, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	clientES512, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	clientES512enc, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	issuerJWKS := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				KeyID:     "rs256-sig",
				Key:       issuerRS256,
				Use:       JSONWebTokenUseSignature,
				Algorithm: string(jose.RS256),
			},
			{
				KeyID:     "es512-sig",
				Key:       issuerES512,
				Use:       JSONWebTokenUseSignature,
				Algorithm: string(jose.ES512),
			},
			{
				KeyID:     "es512-enc",
				Key:       issuerES512enc,
				Use:       JSONWebTokenUseEncryption,
				Algorithm: string(jose.ECDH_ES_A256KW),
			},
		},
	}

	issuerClientJWKS := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				KeyID:     "rs256-sig",
				Key:       &issuerRS256.PublicKey,
				Use:       JSONWebTokenUseSignature,
				Algorithm: string(jose.RS256),
			},
			{
				KeyID:     "es512-sig",
				Key:       &issuerES512.PublicKey,
				Use:       JSONWebTokenUseSignature,
				Algorithm: string(jose.ES512),
			},
			{
				KeyID:     "es512-enc",
				Key:       &issuerES512enc.PublicKey,
				Use:       JSONWebTokenUseEncryption,
				Algorithm: string(jose.ECDH_ES_A256KW),
			},
		},
	}

	issuer := &DefaultIssuer{
		jwks: issuerJWKS,
	}

	clientIssuerJWKS := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				KeyID:     "es512-sig",
				Key:       clientES512,
				Use:       JSONWebTokenUseSignature,
				Algorithm: string(jose.ES512),
			},
			{
				KeyID:     "es512-enc",
				Key:       clientES512enc,
				Use:       JSONWebTokenUseEncryption,
				Algorithm: string(jose.ECDH_ES_A256KW),
			},
		},
	}

	clientJWKS := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				KeyID:     "es512-sig",
				Key:       &clientES512.PublicKey,
				Use:       JSONWebTokenUseSignature,
				Algorithm: string(jose.ES512),
			},
			{
				KeyID:     "es512-enc",
				Key:       &clientES512enc.PublicKey,
				Use:       JSONWebTokenUseEncryption,
				Algorithm: string(jose.ECDH_ES_A256KW),
			},
		},
	}

	issuerJWKSenc := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				KeyID:     "es512-sig",
				Key:       &issuerES512.PublicKey,
				Use:       JSONWebTokenUseSignature,
				Algorithm: string(jose.ES512),
			},
			{
				KeyID:     "es512-enc",
				Key:       &issuerES512enc.PublicKey,
				Use:       JSONWebTokenUseEncryption,
				Algorithm: string(jose.ECDH_ES_A256KW),
			},
		},
	}

	clientJWKSenc := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				KeyID:     "es512-sig",
				Key:       &clientES512.PublicKey,
				Use:       JSONWebTokenUseSignature,
				Algorithm: string(jose.ES512),
			},
			{
				KeyID:     "es512-enc",
				Key:       &clientES512enc.PublicKey,
				Use:       JSONWebTokenUseEncryption,
				Algorithm: string(jose.ECDH_ES_A256KW),
			},
		},
	}

	client := &testClient{
		kid:     "es512-sig",
		alg:     "ES512",
		encKID:  "",
		encAlg:  "",
		enc:     "",
		csigned: false,
		jwks:    clientJWKS,
		jwksURI: "",
	}

	clientEnc := &testClient{
		kid:     "es512-sig",
		alg:     "ES512",
		encKID:  "es512-enc",
		encAlg:  string(jose.ECDH_ES_A256KW),
		enc:     string(jose.A256GCM),
		csigned: false,
		jwks:    clientJWKSenc,
		jwksURI: "",
	}

	key128 := make([]byte, 64)

	_, err = rand.Read(key128)
	require.NoError(t, err)

	clientAsymmetric := &testClient{
		alg:     "HS512",
		csigned: true,
		secret:  key128,
		jwks:    issuerJWKSenc,
		jwksURI: "",
	}

	clientEncAsymmetric := &testClient{
		kid:     "es512-sig",
		alg:     "ES512",
		encKID:  "",
		encAlg:  string(jose.PBES2_HS256_A128KW),
		enc:     string(jose.A256GCM),
		csigned: true,
		secret:  key128,
		jwks:    issuerJWKSenc,
		jwksURI: "",
	}

	strategy := &DefaultStrategy{
		Config: config,
		Issuer: issuer,
	}

	claims := MapClaims{
		"value": 1,
	}

	headers1 := &Headers{
		Extra: map[string]any{
			JSONWebTokenHeaderType: JSONWebTokenTypeAccessToken,
		},
	}

	var headersEnc *Headers

	var (
		token1, signature1 string
	)

	token1, signature1, err = strategy.Encode(ctx, claims, WithHeaders(headers1), WithClient(client))
	require.NoError(t, err)
	assert.NotEmpty(t, signature1)

	require.True(t, IsSignedJWT(token1))

	headersEnc = &Headers{}

	var (
		token2, signature2 string
	)

	headers2 := &Headers{
		Extra: map[string]any{
			JSONWebTokenHeaderType: JSONWebTokenTypeJWT,
		},
	}

	token2, signature2, err = strategy.Encode(ctx, claims, WithHeaders(headers2), WithHeadersJWE(headersEnc), WithClient(clientEnc))
	require.NoError(t, err)
	require.True(t, IsEncryptedJWT(token2))
	require.NotEmpty(t, signature2)

	var (
		token3sig, signature3sig string
	)

	token3sig, signature3sig, err = strategy.Encode(ctx, claims, WithHeaders(headers1), WithClient(clientAsymmetric))
	require.NoError(t, err)
	assert.NotEmpty(t, signature3sig)

	var (
		token3, signature3 string
	)

	token3, signature3, err = strategy.Encode(ctx, claims, WithHeaders(headers1), WithHeadersJWE(headersEnc), WithClient(clientEncAsymmetric))
	require.NoError(t, err)
	assert.NotEmpty(t, signature3)

	clientIssuer := &DefaultIssuer{
		jwks: clientIssuerJWKS,
	}

	clientStrategy := &DefaultStrategy{
		Config: config,
		Issuer: clientIssuer,
	}

	issuerClient := &testClient{
		kid:     "es512-sig",
		alg:     "ES512",
		encKID:  "",
		encAlg:  "",
		enc:     "",
		csigned: true,
		jwks:    issuerClientJWKS,
		jwksURI: "",
	}

	tokenString, signature, jwe, err := clientStrategy.Decrypt(ctx, token2, WithClient(clientEncAsymmetric))
	require.NoError(t, err)
	assert.NotEmpty(t, signature)
	assert.NotEmpty(t, tokenString)
	assert.NotNil(t, jwe)

	tokenString, signature, jwe, err = clientStrategy.Decrypt(ctx, token3, WithClient(clientEncAsymmetric))
	assert.NotEmpty(t, tokenString)
	assert.NotEmpty(t, signature)
	assert.NotNil(t, jwe)
	assert.NoError(t, err)

	tok, err := clientStrategy.Decode(ctx, token1, WithClient(issuerClient))
	assert.NoError(t, err)
	assert.NotNil(t, tok)

	tok, err = clientStrategy.Decode(ctx, token2, WithClient(issuerClient))
	assert.NoError(t, err)
	assert.NotNil(t, tok)

	tok, err = clientStrategy.Decode(ctx, token3sig, WithClient(clientAsymmetric))
	assert.NoError(t, err)
	assert.NotNil(t, tok)
	assert.Equal(t, jose.HS512, tok.SignatureAlgorithm)

	tok, err = clientStrategy.Decode(ctx, token3, WithClient(clientEncAsymmetric))
	require.NoError(t, err)
	require.NotNil(t, tok)
}

func TestDefaultStrategy_Decode_RejectNonCompactSerializedJWT(t *testing.T) {
	testCases := []struct {
		name     string
		strategy Strategy
		input    string
	}{
		{
			name:     "ShouldRejectEmptyOnRS256",
			strategy: &DefaultStrategy{},
			input:    "",
		},
		{
			name:     "ShouldRejectSpaceOnRS256",
			strategy: &DefaultStrategy{},
			input:    " ",
		},
		{
			name:     "ShouldRejectTwoPartsOnRS256",
			strategy: &DefaultStrategy{},
			input:    "foo.bar",
		},
		{
			name:     "ShouldRejectTrailingDotOnRS256",
			strategy: &DefaultStrategy{},
			input:    "foo.",
		},
		{
			name:     "ShouldRejectEmptyOnES256",
			strategy: &DefaultStrategy{},
			input:    "",
		},
		{
			name:     "ShouldRejectSpaceOnES256",
			strategy: &DefaultStrategy{},
			input:    " ",
		},
		{
			name:     "ShouldRejectTwoPartsOnES256",
			strategy: &DefaultStrategy{},
			input:    "foo.bar",
		},
		{
			name:     "ShouldRejectTrailingDotOnES256",
			strategy: &DefaultStrategy{},
			input:    "foo.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.strategy.Decode(t.Context(), tc.input)

			assert.EqualError(t, err, "Provided value does not appear to be a JWE or JWS compact serialized JWT")
		})
	}
}

func TestNestedJWTEncodeDecode(t *testing.T) {
	claims := MapClaims{
		"iss": "example.com",
		"sub": "john",
		"iat": time.Now().UTC().Unix(),
		"exp": time.Now().Add(time.Hour).UTC().Unix(),
		"aud": []string{"test"},
	}

	providerStrategy := &DefaultStrategy{
		Config: &testConfig{},
		Issuer: NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				testKeySigRSA,
				testKeySigECDSA,
			},
		}),
	}

	encodeClientRSA := &testClient{
		id:     "test",
		kid:    "test-rsa-sig",
		alg:    string(jose.RS256),
		encKID: "test-rsa-enc",
		encAlg: string(jose.RSA_OAEP_256),
		enc:    string(jose.A128GCM),
		jwks: &jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				testKeyPublicEncRSA,
				testKeyPublicEncECDSA,
			},
		},
	}

	tokenString, sig, err := providerStrategy.Encode(t.Context(), claims, WithClient(encodeClientRSA))
	require.NoError(t, err)
	assert.NotEmpty(t, sig)
	assert.NotEmpty(t, tokenString)

	clientStrategy := &DefaultStrategy{
		Config: &testConfig{},
		Issuer: NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				testKeyEncRSA,
				testKeyEncECDSA,
			},
		}),
	}

	decodeClientRSA := &testClient{
		id:     "test",
		kid:    "test-rsa-sig",
		alg:    string(jose.RS256),
		encKID: "test-rsa-enc",
		encAlg: string(jose.RSA_OAEP_256),
		enc:    string(jose.A128GCM),
		jwks: &jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				testKeyPublicSigRSA,
				testKeyPublicSigECDSA,
			},
		},
		csigned: true,
	}

	token, err := clientStrategy.Decode(t.Context(), tokenString, WithClient(decodeClientRSA))
	require.NoError(t, err)

	assert.NotNil(t, token)

	assert.NoError(t, token.Valid(ValidateAlgorithm(string(jose.RS256)), ValidateKeyAlgorithm(string(jose.RSA_OAEP_256)), ValidateContentEncryption(string(jose.A128GCM)), ValidateKeyID("test-rsa-sig"), ValidateEncryptionKeyID("test-rsa-enc")))
	assert.NoError(t, token.Claims.Valid(ValidateRequireExpiresAt(), ValidateRequireIssuedAt(), ValidateIssuer("example.com"), ValidateAudienceAny("test")))
	assert.EqualError(t, token.Claims.Valid(ValidateAudienceAny("nope")), "Token has invalid audience")

	encodeClientECDSA := &testClient{
		id:     "test",
		kid:    "test-ecdsa-sig",
		alg:    string(jose.ES256),
		encKID: "test-ecdsa-enc",
		encAlg: string(jose.ECDH_ES_A128KW),
		enc:    string(jose.A128GCM),
		jwks: &jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				testKeyPublicEncRSA,
				testKeyPublicEncECDSA,
			},
		},
	}

	tokenString, sig, err = providerStrategy.Encode(t.Context(), claims, WithClient(encodeClientECDSA))
	require.NoError(t, err)
	assert.NotEmpty(t, sig)
	assert.NotEmpty(t, tokenString)

	clientStrategy = &DefaultStrategy{
		Config: &testConfig{},
		Issuer: NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				testKeyEncRSA,
				testKeyEncECDSA,
			},
		}),
	}

	decodeClientECDSA := &testClient{
		id:     "test",
		kid:    "test-ecdsa-sig",
		alg:    string(jose.RS256),
		encKID: "test-ecdsa-enc",
		encAlg: string(jose.RSA_OAEP_256),
		enc:    string(jose.A128GCM),
		jwks: &jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				testKeyPublicSigRSA,
				testKeyPublicSigECDSA,
			},
		},
		csigned: true,
	}

	token, err = clientStrategy.Decode(t.Context(), tokenString, WithClient(decodeClientECDSA))
	require.NoError(t, err)

	assert.NotNil(t, token)

	assert.NoError(t, token.Valid(ValidateAlgorithm(string(jose.ES256)), ValidateKeyAlgorithm(string(jose.ECDH_ES_A128KW)), ValidateContentEncryption(string(jose.A128GCM)), ValidateKeyID("test-ecdsa-sig"), ValidateEncryptionKeyID("test-ecdsa-enc")))
	assert.NoError(t, token.Claims.Valid(ValidateRequireExpiresAt(), ValidateRequireIssuedAt(), ValidateIssuer("example.com"), ValidateAudienceAny("test")))
	assert.EqualError(t, token.Claims.Valid(ValidateAudienceAny("nope")), "Token has invalid audience")

	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	decodeClientECDSA = &testClient{
		id:     "test",
		kid:    "test-ecdsa-sig",
		alg:    string(jose.RS256),
		encKID: "test-ecdsa-enc",
		encAlg: string(jose.RSA_OAEP_256),
		enc:    string(jose.A128GCM),
		jwks: &jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				testKeyPublicSigRSA,
				{
					Key:       k,
					KeyID:     "test-ecdsa-sig",
					Use:       "sig",
					Algorithm: string(jose.ES256),
				},
			},
		},
		csigned: true,
	}

	token, err = clientStrategy.Decode(t.Context(), tokenString, WithClient(decodeClientECDSA))

	assert.EqualError(t, err, "go-jose/go-jose: error in cryptographic primitive")
	require.NotNil(t, token)
	assert.False(t, token.IsSignatureValid())

	clientStrategy = &DefaultStrategy{
		Config: &testConfig{},
		Issuer: NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				testKeyEncRSA,
			},
		}),
	}

	token, err = clientStrategy.Decode(t.Context(), tokenString, WithClient(decodeClientECDSA))

	assert.Nil(t, token)
	assert.EqualError(t, err, "Error occurred retrieving the JSON Web Key. The JSON Web Token uses signing key with kid 'test-ecdsa-enc' which was not found")

	clientStrategy = &DefaultStrategy{
		Config: &testConfig{},
		Issuer: NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				testKeyEncRSA,
				{
					Key:       k,
					KeyID:     "test-ecdsa-enc",
					Algorithm: string(jose.ECDH_ES_A128KW),
					Use:       "enc",
				},
			},
		}),
	}

	token, err = clientStrategy.Decode(t.Context(), tokenString, WithClient(decodeClientECDSA))

	assert.Nil(t, token)
	assert.EqualError(t, err, "go-jose/go-jose: error in cryptographic primitive")
}

func TestDefaultStrategy_DecodeEncryptedTokens(t *testing.T) {
	testCases := []struct {
		name string
		have string
	}{
		{
			name: "ShouldDecodeRS256",
			have: testCompactSerializedNestedJWEWithRSA,
		},
		{
			name: "ShouldDecodeES256",
			have: testCompactSerializedNestedJWEWithECDSA,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			strategy := &DefaultStrategy{
				Config: &testConfig{},
				Issuer: NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						testKeyEncRSA,
						testKeyEncECDSA,
					},
				}),
			}

			client := &testClient{
				id: "test",
				jwks: &jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						testKeyPublicSigRSA,
						testKeyPublicSigECDSA,
					},
				},
				csigned: true,
			}

			token, err := strategy.Decode(context.Background(), tc.have, WithClient(client))
			require.NoError(t, err)
			require.NotNil(t, token)

			assert.NoError(t, token.Valid())
			assert.NoError(t, token.Claims.Valid(ValidateIssuer("example.com"), ValidateRequireIssuedAt(), ValidateRequireExpiresAt(), ValidateSubject("john")))
		})
	}
}

func TestDefaultStrategy_EncodeWithIssuerSigningAlg(t *testing.T) {
	rsaKey := gen.MustRSAKey()
	ecKey := gen.MustES256Key()

	rsaJWK := jose.JSONWebKey{Key: rsaKey, KeyID: "rs", Algorithm: string(jose.RS256), Use: JSONWebTokenUseSignature}
	ecJWK := jose.JSONWebKey{Key: ecKey, KeyID: "es", Algorithm: string(jose.ES256), Use: JSONWebTokenUseSignature}

	issuer, err := NewDefaultIssuer(rsaJWK, ecJWK)
	require.NoError(t, err)

	strategy := &DefaultStrategy{Config: &testConfig{}, Issuer: issuer}

	testCases := []struct {
		name string
		alg  string
		kid  string
	}{
		{"ShouldDefaultToRS256", "", rsaJWK.KeyID},
		{"ShouldSelectES256", string(jose.ES256), ecJWK.KeyID},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token, _, err := strategy.Encode(context.Background(), MapClaims{"sub": "a"}, WithIssuerSigningAlg(tc.alg))
			require.NoError(t, err)

			parsed, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256, jose.ES256})
			require.NoError(t, err)
			assert.Equal(t, tc.kid, parsed.Signatures[0].Header.KeyID)
		})
	}
}

func TestDefaultStrategy_Validate(t *testing.T) {
	rsaKey := mustRSAKey(t, 2048)

	issuerJWKS := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       rsaKey,
				KeyID:     "validate-kid",
				Use:       JSONWebTokenUseSignature,
				Algorithm: string(jose.RS256),
			},
		},
	}

	strategy := &DefaultStrategy{
		Config: &testConfig{},
		Issuer: NewDefaultIssuerUnverifiedFromJWKS(issuerJWKS),
	}

	t.Run("ShouldErrorOnNilToken", func(t *testing.T) {
		err := strategy.Validate(t.Context(), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token is nil")
	})

	t.Run("ShouldReturnNilWhenAlreadyValid", func(t *testing.T) {
		token := &Token{valid: true}
		assert.NoError(t, strategy.Validate(t.Context(), token))
	})

	t.Run("ShouldErrorWhenParsedTokenNil", func(t *testing.T) {
		token := &Token{valid: false}
		err := strategy.Validate(t.Context(), token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token is in an inconsistent state")
	})

	t.Run("ShouldErrorWhenOptionErrors", func(t *testing.T) {
		token := &Token{valid: true}
		failingOpt := func(opts *StrategyOpts) error { return fmt.Errorf("opt error") }
		err := strategy.Validate(t.Context(), token, failingOpt)
		assert.NoError(t, err, "valid token should short-circuit before applying opts")

		token = &Token{}
		err = strategy.Validate(t.Context(), token, failingOpt)
		require.Error(t, err, "should error when applying options to a non-valid token")
	})

	t.Run("ShouldValidateSignedTokenWithAllowUnverifiedDeferred", func(t *testing.T) {
		ctx := t.Context()
		claims := MapClaims{"foo": "bar"}
		headers := &Headers{Extra: map[string]any{JSONWebTokenHeaderType: JSONWebTokenTypeJWT}}

		tokenString, _, err := strategy.Encode(ctx, claims, WithHeaders(headers))
		require.NoError(t, err)
		require.NotEmpty(t, tokenString)

		token, err := strategy.Decode(ctx, tokenString, WithAllowUnverified())
		require.NoError(t, err)
		require.NotNil(t, token)
		require.False(t, token.valid, "Decode with WithAllowUnverified must defer validation")

		require.NoError(t, strategy.Validate(ctx, token))
		assert.True(t, token.valid)
	})
}

func TestDefaultStrategy_Errors(t *testing.T) {
	rsaKey := mustRSAKey(t, 2048)

	jwks := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       rsaKey,
				KeyID:     "default",
				Use:       JSONWebTokenUseSignature,
				Algorithm: string(jose.RS256),
			},
		},
	}

	strategy := &DefaultStrategy{
		Config: &testConfig{},
		Issuer: NewDefaultIssuerUnverifiedFromJWKS(jwks),
	}

	failingOpt := func(opts *StrategyOpts) error { return fmt.Errorf("opt failure") }

	t.Run("EncodeShouldErrorOnFailingOption", func(t *testing.T) {
		_, _, err := strategy.Encode(t.Context(), MapClaims{}, failingOpt)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "opt failure")
	})

	t.Run("EncodeShouldErrorOnMissingIssuerKey", func(t *testing.T) {
		emptyStrategy := &DefaultStrategy{
			Config: &testConfig{},
			Issuer: NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{}),
		}
		_, _, err := emptyStrategy.Encode(t.Context(), MapClaims{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error occurred retrieving issuer jwk")
	})

	t.Run("DecryptShouldErrorOnFailingOption", func(t *testing.T) {
		validJWE := "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4R0NNIn0.foo.iv.ct.tag"
		_, _, _, err := strategy.Decrypt(t.Context(), validJWE, failingOpt)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "opt failure")
	})

	t.Run("DecryptShouldReturnSignedJWTUnchanged", func(t *testing.T) {
		ctx := t.Context()
		claims := MapClaims{"foo": "bar"}
		headers := &Headers{Extra: map[string]any{JSONWebTokenHeaderType: JSONWebTokenTypeJWT}}

		signed, _, err := strategy.Encode(ctx, claims, WithHeaders(headers))
		require.NoError(t, err)

		out, sig, jwe, err := strategy.Decrypt(ctx, signed)
		require.NoError(t, err)
		assert.Equal(t, signed, out)
		assert.Empty(t, sig)
		assert.Nil(t, jwe)
	})

	t.Run("DecryptShouldErrorOnMalformedToken", func(t *testing.T) {
		_, _, _, err := strategy.Decrypt(t.Context(), "not-a-jwt")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Provided value does not appear to be a JWE or JWS compact serialized JWT")
	})

	t.Run("DecryptShouldErrorOnMalformedJWE", func(t *testing.T) {
		_, _, _, err := strategy.Decrypt(t.Context(), "garbage.garbage.garbage.garbage.garbage")
		require.Error(t, err)
	})

	t.Run("DecodeShouldErrorOnFailingOption", func(t *testing.T) {
		_, err := strategy.Decode(t.Context(), "garbage.garbage.garbage", failingOpt)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "opt failure")
	})

	t.Run("DecodeShouldErrorOnMalformedToken", func(t *testing.T) {
		_, err := strategy.Decode(t.Context(), "not-a-jwt")
		require.Error(t, err)
	})
}

func TestEncodeNestedCompactEncrypted(t *testing.T) {
	claims := MapClaims{
		"iss": "example.com",
		"sub": "john",
		"iat": time.Now().UTC().Unix(),
		"exp": time.Now().Add(time.Hour * 24 * 365 * 40).UTC().Unix(),
	}

	out, _, err := EncodeNestedCompactEncrypted(t.Context(), claims, &Headers{}, &Headers{}, &testKeySigECDSA, &testKeyPublicEncECDSA, jose.A128GCM)

	require.NoError(t, err)
	require.NotEmpty(t, out)

	t.Run("ShouldSetContentTypeJWT", func(t *testing.T) {
		headers := &Headers{Extra: map[string]any{JSONWebTokenHeaderType: JSONWebTokenTypeAccessToken}}

		out, _, err := EncodeNestedCompactEncrypted(t.Context(), claims, headers, &Headers{}, &testKeySigECDSA, &testKeyPublicEncECDSA, jose.A128GCM)
		require.NoError(t, err)

		jwe, err := jose.ParseEncryptedCompact(out, []jose.KeyAlgorithm{jose.ECDH_ES_A128KW}, []jose.ContentEncryption{jose.A128GCM})
		require.NoError(t, err)
		assert.Equal(t, JSONWebTokenTypeJWT, jwe.Header.ExtraHeaders[JSONWebTokenHeaderContentType])
	})

	t.Run("ShouldUseCallerContentType", func(t *testing.T) {
		headersJWE := &Headers{Extra: map[string]any{JSONWebTokenHeaderContentType: JSONWebTokenTypeAccessToken}}

		out, _, err := EncodeNestedCompactEncrypted(t.Context(), claims, &Headers{}, headersJWE, &testKeySigECDSA, &testKeyPublicEncECDSA, jose.A128GCM)
		require.NoError(t, err)

		jwe, err := jose.ParseEncryptedCompact(out, []jose.KeyAlgorithm{jose.ECDH_ES_A128KW}, []jose.ContentEncryption{jose.A128GCM})
		require.NoError(t, err)
		assert.Equal(t, JSONWebTokenTypeAccessToken, jwe.Header.ExtraHeaders[JSONWebTokenHeaderContentType])
	})
}

func TestEncodeHeaderKeyID(t *testing.T) {
	claims := MapClaims{"sub": "john"}
	stale := "stale"

	t.Run("ShouldUseSigningKeyID", func(t *testing.T) {
		headers := &Headers{Extra: map[string]any{JSONWebTokenHeaderKeyIdentifier: stale}}

		out, _, err := EncodeCompactSigned(t.Context(), claims, headers, &testKeySigECDSA)
		require.NoError(t, err)

		token, err := jwt.ParseSigned(out, []jose.SignatureAlgorithm{jose.ES256})
		require.NoError(t, err)
		require.Len(t, token.Headers, 1)
		assert.Equal(t, testKeySigECDSA.KeyID, token.Headers[0].KeyID)
	})

	t.Run("ShouldUseSigningAndEncryptionKeyIDs", func(t *testing.T) {
		headers := &Headers{Extra: map[string]any{JSONWebTokenHeaderKeyIdentifier: stale}}
		headersJWE := &Headers{Extra: map[string]any{JSONWebTokenHeaderKeyIdentifier: "stale-enc"}}

		out, _, err := EncodeNestedCompactEncrypted(t.Context(), claims, headers, headersJWE, &testKeySigECDSA, &testKeyPublicEncECDSA, jose.A128GCM)
		require.NoError(t, err)

		jwe, err := jose.ParseEncryptedCompact(out, []jose.KeyAlgorithm{jose.ECDH_ES_A128KW}, []jose.ContentEncryption{jose.A128GCM})
		require.NoError(t, err)
		assert.Equal(t, testKeyPublicEncECDSA.KeyID, jwe.Header.KeyID)

		raw, err := jwe.Decrypt(&testKeyEncECDSA)
		require.NoError(t, err)

		token, err := jwt.ParseSigned(string(raw), []jose.SignatureAlgorithm{jose.ES256})
		require.NoError(t, err)
		require.Len(t, token.Headers, 1)
		assert.Equal(t, testKeySigECDSA.KeyID, token.Headers[0].KeyID)
	})

	t.Run("ShouldNotModifyCallerHeaders", func(t *testing.T) {
		headers := &Headers{Extra: map[string]any{JSONWebTokenHeaderKeyIdentifier: stale}}

		_, _, err := EncodeCompactSigned(t.Context(), claims, headers, &testKeySigECDSA)
		require.NoError(t, err)
		assert.Equal(t, stale, headers.Get(JSONWebTokenHeaderKeyIdentifier))
	})
}

func TestDefaultStrategyDecodeAlgNone(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	strategy := &DefaultStrategy{
		Config: &testConfig{},
		Issuer: NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{KeyID: "rs256-sig", Key: key, Use: JSONWebTokenUseSignature, Algorithm: string(jose.RS256)},
			},
		}),
	}

	unsigned, err := NewWithClaims(SigningMethodNone, MapClaims{
		"iss": "client-id",
		"sub": "client-id",
		"aud": "https://auth.example.com",
		"jti": "test-jti",
		"exp": time.Now().Add(time.Hour).Unix(),
	}).CompactSignedString(UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	testCases := []struct {
		name     string
		client   Client
		expected bool
	}{
		{"ShouldNotVerifyWithoutAClient", nil, false},
		{"ShouldNotVerifyWhenSigningAlgIsUnregistered", &testClient{id: "client-id", csigned: true}, false},
		{"ShouldNotVerifyWhenSigningAlgIsRS256", &testClient{id: "client-id", csigned: true, alg: string(jose.RS256)}, false},
		{"ShouldVerifyWhenSigningAlgIsNone", &testClient{id: "client-id", csigned: true, alg: JSONWebTokenAlgNone}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := []StrategyOpt{WithSigAlgorithm(SignatureAlgorithmsNone...)}

			if tc.client != nil {
				opts = append(opts, WithClient(tc.client))
			}

			decoded, err := strategy.Decode(t.Context(), unsigned, opts...)
			require.NoError(t, err)
			require.NotNil(t, decoded)

			err = decoded.Valid()

			if tc.expected {
				assert.NoError(t, err)

				return
			}

			require.Error(t, err)

			var verr *ValidationError

			require.ErrorAs(t, err, &verr)
			assert.True(t, verr.Has(ValidationErrorSignatureInvalid), "expected the unsigned token to be reported as having an invalid signature, got: %v", err)
		})
	}
}

type testConfig struct{}

func (*testConfig) GetJWKSFetcherStrategy(ctx context.Context) (strategy JWKSFetcherStrategy) {
	return &testFetcher{client: http.DefaultClient}
}

type testFetcher struct {
	client *http.Client
}

func (f *testFetcher) Resolve(ctx context.Context, location string, _ bool) (jwks *jose.JSONWebKeySet, err error) {
	var req *http.Request

	if req, err = http.NewRequest(http.MethodGet, location, nil); err != nil {
		return nil, err
	}

	req = req.WithContext(ctx)

	var resp *http.Response

	if resp, err = f.client.Do(req); err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)

	jwks = &jose.JSONWebKeySet{}

	if err = decoder.Decode(jwks); err != nil {
		return nil, err
	}

	return jwks, nil
}

func init() {
	var (
		key any
		err error
	)

	if key, err = x509.ParsePKCS8PrivateKey(testKeyBytesSigRSA); err != nil {
		panic(err)
	}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		testKeySigRSA = jose.JSONWebKey{
			Key:       k,
			KeyID:     "test-rsa-sig",
			Use:       JSONWebTokenUseSignature,
			Algorithm: string(jose.RS256),
		}
		testKeyPublicSigRSA = jose.JSONWebKey{
			Key:       k.Public(),
			KeyID:     "test-rsa-sig",
			Use:       JSONWebTokenUseSignature,
			Algorithm: string(jose.RS256),
		}
	default:
		panic("unsupported private key")
	}

	if key, err = x509.ParsePKCS8PrivateKey(testKeyBytesEncRSA); err != nil {
		panic(err)
	}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		testKeyEncRSA = jose.JSONWebKey{
			Key:       k,
			KeyID:     "test-rsa-enc",
			Use:       JSONWebTokenUseEncryption,
			Algorithm: string(jose.RSA_OAEP_256),
		}
		testKeyPublicEncRSA = jose.JSONWebKey{
			Key:       k.Public(),
			KeyID:     "test-rsa-enc",
			Use:       JSONWebTokenUseEncryption,
			Algorithm: string(jose.RSA_OAEP_256),
		}
	default:
		panic("unsupported private key")
	}

	if key, err = x509.ParsePKCS8PrivateKey(testKeyBytesSigECDSA); err != nil {
		panic(err)
	}

	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		testKeySigECDSA = jose.JSONWebKey{
			Key:       k,
			KeyID:     "test-ecdsa-sig",
			Use:       JSONWebTokenUseSignature,
			Algorithm: string(jose.ES256),
		}
		testKeyPublicSigECDSA = jose.JSONWebKey{
			Key:       k.Public(),
			KeyID:     "test-ecdsa-sig",
			Use:       JSONWebTokenUseSignature,
			Algorithm: string(jose.ES256),
		}
	default:
		panic("unsupported private key")
	}

	if key, err = x509.ParsePKCS8PrivateKey(testKeyBytesEncECDSA); err != nil {
		panic(err)
	}

	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		testKeyEncECDSA = jose.JSONWebKey{
			Key:       k,
			KeyID:     "test-ecdsa-enc",
			Use:       JSONWebTokenUseEncryption,
			Algorithm: string(jose.ECDH_ES_A128KW),
		}
		testKeyPublicEncECDSA = jose.JSONWebKey{
			Key:       k.Public(),
			KeyID:     "test-ecdsa-enc",
			Use:       JSONWebTokenUseEncryption,
			Algorithm: string(jose.ECDH_ES_A128KW),
		}
	default:
		panic("unsupported private key")
	}
}
