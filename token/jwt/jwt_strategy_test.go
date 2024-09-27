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

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/internal/consts"
)

func TestDefaultStrategy(t *testing.T) {
	ctx := context.TODO()

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
				Use:       consts.JSONWebTokenUseSignature,
				Algorithm: string(jose.RS256),
			},
			{
				KeyID:     "es512-sig",
				Key:       issuerES512,
				Use:       consts.JSONWebTokenUseSignature,
				Algorithm: string(jose.ES512),
			},
			{
				KeyID:     "es512-enc",
				Key:       issuerES512enc,
				Use:       consts.JSONWebTokenUseEncryption,
				Algorithm: string(jose.ECDH_ES_A256KW),
			},
		},
	}

	issuerClientJWKS := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				KeyID:     "rs256-sig",
				Key:       &issuerRS256.PublicKey,
				Use:       consts.JSONWebTokenUseSignature,
				Algorithm: string(jose.RS256),
			},
			{
				KeyID:     "es512-sig",
				Key:       &issuerES512.PublicKey,
				Use:       consts.JSONWebTokenUseSignature,
				Algorithm: string(jose.ES512),
			},
			{
				KeyID:     "es512-enc",
				Key:       &issuerES512enc.PublicKey,
				Use:       consts.JSONWebTokenUseEncryption,
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
				Use:       consts.JSONWebTokenUseSignature,
				Algorithm: string(jose.ES512),
			},
			{
				KeyID:     "es512-enc",
				Key:       clientES512enc,
				Use:       consts.JSONWebTokenUseEncryption,
				Algorithm: string(jose.ECDH_ES_A256KW),
			},
		},
	}

	clientJWKS := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				KeyID:     "es512-sig",
				Key:       &clientES512.PublicKey,
				Use:       consts.JSONWebTokenUseSignature,
				Algorithm: string(jose.ES512),
			},
			{
				KeyID:     "es512-enc",
				Key:       &clientES512enc.PublicKey,
				Use:       consts.JSONWebTokenUseEncryption,
				Algorithm: string(jose.ECDH_ES_A256KW),
			},
		},
	}

	issuerJWKSenc := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				KeyID:     "es512-sig",
				Key:       &issuerES512.PublicKey,
				Use:       consts.JSONWebTokenUseSignature,
				Algorithm: string(jose.ES512),
			},
			{
				KeyID:     "es512-enc",
				Key:       &issuerES512enc.PublicKey,
				Use:       consts.JSONWebTokenUseEncryption,
				Algorithm: string(jose.ECDH_ES_A256KW),
			},
		},
	}

	clientJWKSenc := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				KeyID:     "es512-sig",
				Key:       &clientES512.PublicKey,
				Use:       consts.JSONWebTokenUseSignature,
				Algorithm: string(jose.ES512),
			},
			{
				KeyID:     "es512-enc",
				Key:       &clientES512enc.PublicKey,
				Use:       consts.JSONWebTokenUseEncryption,
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

	key128 := make([]byte, 32)

	_, err = rand.Read(key128)
	require.NoError(t, err)

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
			consts.JSONWebTokenHeaderType: consts.JSONWebTokenTypeAccessToken,
		},
	}

	var headersEnc *Headers

	var (
		token1, signature1 string
	)

	token1, signature1, err = strategy.Encode(ctx, WithClaims(claims), WithHeaders(headers1), WithClient(client))
	require.NoError(t, err)
	assert.NotEmpty(t, signature1)

	require.True(t, IsSignedJWT(token1))

	headersEnc = &Headers{}

	var (
		token2, signature2 string
	)

	headers2 := &Headers{
		Extra: map[string]any{
			consts.JSONWebTokenHeaderType: consts.JSONWebTokenTypeJWT,
		},
	}

	token2, signature2, err = strategy.Encode(ctx, WithClaims(claims), WithHeaders(headers2), WithHeadersJWE(headersEnc), WithClient(clientEnc))
	require.NoError(t, err)
	require.True(t, IsEncryptedJWT(token2))
	require.NotEmpty(t, signature2)

	var (
		token3, signature3 string
	)

	token3, signature3, err = strategy.Encode(ctx, WithClaims(claims), WithHeaders(headers1), WithHeadersJWE(headersEnc), WithClient(clientEncAsymmetric))
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
	require.NoError(t, err)

	tok, err := clientStrategy.Decode(ctx, token1, WithClient(issuerClient))
	require.NoError(t, err)
	require.NotNil(t, tok)

	tok, err = clientStrategy.Decode(ctx, token2, WithClient(issuerClient))
	require.NoError(t, err)

	tok, err = clientStrategy.Decode(ctx, token3, WithClient(clientEncAsymmetric))
	require.NoError(t, err)
	require.NotNil(t, tok)
}

func TestDefaultStrategy_Decode_RejectNonCompactSerializedJWT(t *testing.T) {
	testCases := []struct {
		name     string
		strategy Strategy
	}{
		{
			name:     "RS256",
			strategy: &DefaultStrategy{},
		},
		{
			name:     "ES256",
			strategy: &DefaultStrategy{},
		},
	}

	inputs := []struct {
		name  string
		value string
	}{
		{"Empty", ""},
		{"Space", " "},
		{"TwoParts", "foo.bar"},
		{"TwoPartsEmptySecond", "foo."},
		{"TwoPartsEmptyFirst", "foo."},
	}

	for _, tc := range testCases {
		for _, input := range inputs {
			t.Run(fmt.Sprintf("%s/%s", tc.name, input.name), func(t *testing.T) {
				_, err := tc.strategy.Decode(context.TODO(), input.value)

				assert.EqualError(t, err, "Provided value does not appear to be a JWE or JWS compact serialized JWT")
			})
		}
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

	tokenString, sig, err := providerStrategy.Encode(context.TODO(), WithClaims(claims), WithClient(encodeClientRSA))
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

	token, err := clientStrategy.Decode(context.TODO(), tokenString, WithClient(decodeClientRSA))
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

	tokenString, sig, err = providerStrategy.Encode(context.TODO(), WithClaims(claims), WithClient(encodeClientECDSA))
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

	token, err = clientStrategy.Decode(context.TODO(), tokenString, WithClient(decodeClientECDSA))
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

	token, err = clientStrategy.Decode(context.TODO(), tokenString, WithClient(decodeClientECDSA))
	assert.EqualError(t, err, "go-jose/go-jose: error in cryptographic primitive")

	clientStrategy = &DefaultStrategy{
		Config: &testConfig{},
		Issuer: NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				testKeyEncRSA,
			},
		}),
	}

	token, err = clientStrategy.Decode(context.TODO(), tokenString, WithClient(decodeClientECDSA))
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

	token, err = clientStrategy.Decode(context.TODO(), tokenString, WithClient(decodeClientECDSA))
	assert.EqualError(t, err, "go-jose/go-jose: error in cryptographic primitive")
}

func TestShouldDecodeEncrypedTokens(t *testing.T) {
	testCases := []struct {
		name string
		have string
	}{
		{
			"ShouldDecodeRS256",
			testCompactSerializedNestedJWEWithRSA,
		},
		{
			"ShouldDecodeES256",
			testCompactSerializedNestedJWEWithECDSA,
		},
	}

	for _, tc := range testCases {
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
		assert.NoError(t, err)
		assert.NotNil(t, token)

		assert.NoError(t, token.Valid())
		assert.NoError(t, token.Claims.Valid(ValidateIssuer("example.com"), ValidateRequireIssuedAt(), ValidateRequireExpiresAt(), ValidateSubject("john")))
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

	req.WithContext(ctx)

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

var (
	testKeyBytesSigRSA  = []byte{48, 130, 4, 189, 2, 1, 0, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 4, 130, 4, 167, 48, 130, 4, 163, 2, 1, 0, 2, 130, 1, 1, 0, 225, 139, 207, 167, 201, 162, 77, 23, 186, 56, 185, 177, 22, 31, 170, 37, 145, 252, 98, 102, 229, 160, 101, 31, 227, 76, 122, 70, 190, 1, 96, 53, 29, 58, 134, 211, 50, 166, 81, 143, 163, 141, 118, 165, 192, 238, 26, 250, 66, 42, 204, 164, 160, 205, 124, 175, 215, 202, 172, 74, 210, 134, 147, 10, 64, 58, 134, 46, 185, 15, 164, 126, 106, 106, 89, 206, 12, 95, 74, 229, 236, 132, 101, 98, 140, 40, 94, 177, 113, 24, 215, 184, 7, 210, 23, 98, 129, 207, 27, 221, 233, 168, 88, 68, 180, 157, 65, 141, 145, 53, 186, 230, 143, 128, 77, 47, 240, 181, 142, 236, 105, 119, 177, 231, 0, 123, 86, 215, 201, 165, 158, 234, 185, 236, 225, 72, 237, 28, 192, 193, 45, 212, 194, 19, 195, 9, 140, 141, 143, 3, 148, 118, 244, 25, 50, 18, 9, 37, 199, 202, 225, 142, 44, 138, 99, 84, 25, 162, 48, 243, 44, 31, 38, 88, 62, 244, 2, 64, 84, 53, 105, 92, 175, 156, 152, 32, 191, 26, 39, 153, 166, 188, 190, 33, 221, 116, 180, 174, 229, 191, 129, 198, 183, 23, 178, 20, 183, 250, 29, 42, 63, 63, 107, 170, 126, 121, 31, 90, 17, 180, 63, 137, 86, 255, 49, 163, 181, 91, 110, 160, 163, 147, 67, 149, 152, 218, 212, 23, 231, 76, 133, 208, 190, 161, 230, 4, 156, 186, 206, 145, 106, 7, 213, 50, 161, 159, 2, 3, 1, 0, 1, 2, 130, 1, 0, 106, 140, 145, 220, 193, 244, 90, 87, 11, 50, 33, 6, 247, 92, 158, 20, 129, 146, 169, 41, 210, 240, 162, 213, 29, 155, 211, 103, 247, 250, 206, 104, 73, 22, 140, 250, 216, 194, 153, 101, 49, 238, 114, 78, 123, 134, 0, 88, 153, 73, 126, 195, 134, 243, 140, 35, 197, 221, 136, 231, 15, 237, 99, 41, 68, 142, 97, 53, 81, 87, 130, 109, 245, 247, 167, 213, 31, 35, 37, 78, 217, 28, 242, 136, 75, 142, 6, 173, 236, 175, 191, 184, 192, 121, 15, 115, 9, 191, 189, 122, 104, 23, 143, 27, 101, 247, 164, 48, 44, 153, 37, 98, 38, 8, 134, 110, 79, 88, 117, 220, 89, 54, 162, 100, 110, 101, 213, 239, 215, 216, 210, 212, 103, 101, 141, 155, 163, 163, 92, 200, 89, 244, 21, 136, 197, 41, 119, 24, 87, 64, 179, 1, 128, 223, 166, 65, 16, 163, 99, 42, 251, 49, 59, 200, 176, 174, 9, 79, 90, 174, 171, 221, 68, 38, 200, 224, 123, 116, 79, 105, 97, 196, 164, 173, 200, 47, 199, 130, 84, 201, 111, 87, 76, 249, 117, 200, 83, 104, 195, 123, 171, 176, 39, 221, 101, 23, 152, 39, 148, 179, 79, 32, 135, 148, 86, 252, 85, 226, 50, 222, 84, 230, 174, 202, 149, 64, 87, 170, 2, 7, 20, 26, 118, 251, 7, 161, 55, 11, 127, 143, 78, 169, 209, 225, 94, 173, 164, 149, 37, 191, 21, 182, 38, 56, 168, 129, 2, 129, 129, 0, 238, 131, 86, 36, 159, 247, 119, 204, 99, 214, 255, 44, 244, 160, 224, 151, 30, 172, 198, 6, 76, 189, 52, 147, 11, 99, 164, 161, 245, 49, 224, 145, 118, 186, 229, 106, 207, 53, 208, 16, 74, 222, 118, 57, 230, 237, 5, 165, 224, 90, 194, 146, 162, 98, 85, 30, 162, 195, 214, 117, 130, 141, 43, 225, 169, 222, 247, 190, 77, 187, 244, 50, 2, 35, 153, 192, 253, 128, 34, 227, 128, 209, 145, 41, 192, 79, 185, 78, 169, 144, 71, 211, 58, 107, 50, 125, 152, 174, 177, 58, 121, 239, 95, 47, 248, 156, 53, 97, 126, 48, 112, 232, 206, 60, 139, 36, 111, 213, 98, 254, 233, 211, 168, 187, 115, 205, 142, 45, 2, 129, 129, 0, 242, 21, 25, 43, 57, 228, 145, 144, 61, 19, 122, 145, 201, 78, 122, 47, 209, 218, 227, 90, 209, 224, 174, 252, 191, 209, 172, 99, 217, 112, 127, 131, 200, 134, 90, 159, 37, 16, 46, 86, 118, 145, 140, 31, 83, 194, 111, 23, 83, 18, 151, 223, 126, 58, 186, 235, 33, 180, 24, 200, 101, 114, 148, 199, 203, 57, 190, 239, 21, 45, 194, 140, 182, 45, 222, 30, 162, 173, 189, 249, 203, 158, 162, 138, 246, 185, 164, 21, 216, 228, 146, 180, 162, 165, 48, 170, 215, 113, 204, 223, 200, 194, 140, 54, 191, 157, 251, 30, 218, 126, 228, 27, 228, 158, 30, 126, 131, 243, 169, 230, 172, 88, 183, 51, 70, 241, 218, 123, 2, 129, 129, 0, 156, 61, 214, 201, 73, 45, 0, 2, 25, 8, 246, 193, 201, 66, 53, 189, 104, 239, 191, 12, 211, 106, 66, 45, 109, 17, 138, 0, 58, 49, 193, 45, 40, 252, 199, 90, 79, 128, 173, 218, 110, 97, 10, 75, 101, 213, 176, 148, 119, 194, 156, 161, 23, 212, 152, 115, 232, 37, 167, 175, 244, 164, 107, 177, 120, 232, 193, 155, 157, 42, 89, 142, 4, 206, 179, 98, 179, 237, 35, 109, 170, 174, 29, 140, 159, 24, 218, 136, 8, 21, 166, 167, 93, 38, 105, 189, 210, 173, 229, 21, 44, 89, 61, 30, 156, 154, 31, 113, 205, 11, 8, 123, 200, 213, 234, 68, 37, 42, 64, 158, 66, 40, 79, 232, 243, 180, 28, 197, 2, 129, 128, 115, 240, 44, 212, 169, 238, 80, 212, 142, 155, 180, 152, 251, 155, 77, 35, 119, 210, 232, 14, 7, 244, 30, 122, 71, 247, 200, 35, 45, 241, 21, 240, 236, 105, 132, 31, 49, 229, 244, 251, 77, 223, 217, 6, 235, 219, 115, 206, 236, 231, 59, 187, 58, 190, 47, 229, 10, 136, 49, 82, 80, 91, 182, 235, 148, 229, 252, 14, 142, 203, 18, 160, 199, 99, 98, 60, 179, 214, 151, 228, 121, 99, 105, 31, 58, 152, 160, 0, 34, 151, 29, 183, 203, 41, 104, 12, 122, 16, 51, 121, 125, 177, 198, 235, 53, 140, 24, 199, 167, 7, 28, 130, 75, 84, 122, 240, 70, 139, 188, 244, 15, 216, 145, 44, 202, 174, 107, 223, 2, 129, 128, 106, 85, 157, 106, 91, 201, 27, 113, 197, 111, 239, 104, 141, 30, 73, 67, 30, 204, 18, 195, 1, 99, 13, 200, 69, 81, 13, 185, 250, 196, 26, 127, 67, 184, 226, 65, 176, 119, 163, 86, 176, 24, 120, 179, 50, 36, 76, 156, 108, 138, 164, 204, 65, 133, 112, 236, 122, 246, 227, 137, 244, 216, 112, 246, 212, 114, 24, 155, 88, 42, 17, 161, 70, 196, 67, 90, 209, 73, 58, 73, 82, 26, 116, 15, 229, 107, 35, 158, 89, 49, 241, 154, 7, 230, 219, 92, 234, 144, 136, 4, 221, 149, 130, 120, 64, 127, 225, 248, 241, 183, 6, 25, 225, 10, 236, 21, 141, 152, 122, 70, 111, 82, 177, 175, 205, 116, 72, 142}
	testKeyBytesEncRSA  = []byte{48, 130, 4, 191, 2, 1, 0, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 4, 130, 4, 169, 48, 130, 4, 165, 2, 1, 0, 2, 130, 1, 1, 0, 172, 196, 70, 138, 2, 105, 68, 113, 29, 120, 167, 117, 74, 253, 195, 218, 40, 62, 221, 198, 42, 216, 67, 65, 21, 181, 204, 211, 51, 45, 62, 127, 3, 219, 96, 95, 31, 191, 226, 255, 108, 87, 135, 133, 134, 197, 74, 188, 3, 244, 121, 123, 171, 192, 82, 213, 54, 61, 142, 226, 42, 71, 79, 59, 30, 197, 1, 67, 182, 236, 39, 62, 5, 234, 69, 4, 167, 72, 82, 76, 46, 146, 234, 117, 99, 90, 189, 205, 19, 75, 210, 105, 225, 110, 172, 236, 14, 158, 33, 176, 193, 58, 136, 147, 140, 151, 222, 181, 95, 11, 121, 56, 172, 215, 239, 222, 200, 76, 237, 183, 50, 104, 240, 1, 164, 197, 247, 180, 54, 216, 196, 34, 137, 211, 108, 74, 222, 188, 190, 84, 118, 244, 249, 97, 192, 147, 126, 67, 209, 24, 80, 37, 180, 88, 169, 112, 37, 242, 249, 49, 28, 152, 168, 182, 175, 21, 80, 88, 153, 23, 132, 136, 53, 25, 84, 128, 216, 88, 118, 173, 4, 241, 238, 122, 226, 190, 134, 116, 167, 94, 196, 131, 175, 156, 213, 115, 140, 105, 63, 15, 31, 237, 25, 243, 85, 156, 85, 37, 4, 238, 154, 36, 10, 235, 11, 213, 222, 238, 208, 69, 197, 201, 139, 76, 3, 137, 214, 175, 63, 112, 150, 41, 24, 122, 110, 250, 27, 14, 48, 7, 63, 158, 35, 107, 59, 185, 141, 200, 178, 123, 10, 97, 247, 100, 9, 85, 2, 3, 1, 0, 1, 2, 130, 1, 1, 0, 152, 106, 91, 244, 187, 37, 213, 60, 153, 140, 108, 231, 156, 109, 253, 207, 195, 123, 154, 185, 141, 232, 214, 132, 95, 187, 208, 100, 110, 156, 182, 170, 229, 99, 47, 69, 28, 68, 115, 229, 116, 214, 79, 119, 236, 42, 183, 192, 225, 24, 87, 232, 83, 224, 74, 243, 80, 115, 196, 79, 32, 143, 98, 133, 188, 162, 126, 120, 23, 179, 132, 247, 65, 206, 168, 110, 239, 137, 109, 25, 74, 105, 80, 48, 153, 163, 95, 24, 193, 178, 61, 130, 45, 96, 47, 107, 221, 133, 130, 33, 102, 134, 214, 32, 157, 131, 9, 246, 38, 80, 127, 244, 17, 0, 59, 220, 230, 6, 128, 29, 3, 122, 242, 105, 240, 204, 185, 182, 47, 40, 194, 94, 4, 152, 28, 251, 15, 21, 148, 149, 219, 180, 253, 154, 53, 60, 3, 82, 206, 27, 97, 137, 228, 105, 87, 0, 66, 43, 198, 230, 33, 30, 84, 92, 138, 116, 76, 202, 250, 90, 102, 81, 67, 19, 159, 126, 130, 200, 208, 208, 60, 228, 166, 103, 212, 19, 138, 196, 57, 183, 244, 13, 175, 147, 198, 124, 164, 40, 50, 3, 64, 158, 35, 238, 116, 55, 215, 168, 63, 173, 11, 78, 244, 200, 130, 120, 89, 164, 58, 35, 68, 254, 141, 69, 157, 97, 123, 97, 217, 112, 51, 2, 126, 109, 182, 243, 11, 147, 93, 125, 140, 86, 157, 156, 31, 197, 119, 225, 67, 65, 64, 190, 173, 0, 143, 1, 2, 129, 129, 0, 207, 234, 215, 66, 208, 61, 102, 219, 140, 108, 97, 58, 204, 132, 211, 206, 210, 223, 212, 210, 6, 208, 177, 231, 250, 31, 35, 164, 213, 46, 55, 179, 221, 134, 79, 253, 76, 75, 187, 250, 75, 70, 163, 150, 122, 190, 243, 196, 169, 187, 255, 91, 67, 42, 110, 35, 23, 169, 114, 47, 165, 89, 10, 97, 50, 61, 53, 45, 153, 81, 209, 82, 82, 20, 4, 15, 61, 204, 185, 24, 246, 63, 153, 3, 135, 170, 45, 112, 59, 36, 209, 49, 9, 224, 203, 226, 40, 178, 20, 19, 19, 73, 249, 21, 122, 188, 247, 161, 20, 226, 124, 14, 66, 4, 12, 37, 75, 35, 37, 36, 22, 216, 236, 189, 44, 179, 102, 193, 2, 129, 129, 0, 212, 184, 112, 164, 6, 140, 127, 190, 0, 170, 229, 42, 252, 99, 70, 29, 251, 176, 41, 87, 91, 226, 204, 173, 164, 208, 192, 70, 0, 238, 113, 97, 239, 147, 247, 156, 80, 98, 231, 47, 28, 186, 99, 25, 144, 18, 165, 68, 117, 99, 54, 99, 241, 109, 77, 82, 250, 105, 218, 148, 205, 139, 49, 181, 68, 110, 50, 146, 212, 149, 191, 97, 10, 83, 55, 240, 23, 114, 83, 116, 25, 118, 195, 85, 72, 74, 142, 57, 97, 31, 65, 4, 93, 46, 177, 32, 248, 146, 5, 0, 189, 181, 123, 116, 27, 197, 98, 195, 158, 196, 112, 60, 177, 31, 246, 237, 246, 126, 248, 63, 245, 185, 1, 224, 165, 186, 251, 149, 2, 129, 129, 0, 150, 10, 132, 249, 68, 73, 107, 54, 184, 169, 101, 169, 6, 250, 59, 215, 159, 57, 195, 221, 36, 233, 233, 216, 220, 25, 40, 161, 196, 237, 171, 104, 243, 77, 255, 223, 108, 245, 162, 91, 199, 130, 220, 126, 181, 105, 163, 132, 162, 112, 118, 160, 167, 97, 177, 69, 69, 200, 20, 12, 234, 39, 205, 99, 194, 219, 132, 202, 185, 63, 223, 236, 166, 42, 167, 155, 80, 31, 178, 219, 158, 168, 218, 133, 63, 155, 193, 90, 162, 115, 185, 58, 200, 68, 31, 29, 191, 252, 114, 156, 41, 105, 82, 132, 251, 163, 238, 151, 161, 248, 167, 73, 170, 190, 60, 253, 148, 177, 114, 22, 15, 30, 208, 8, 220, 127, 66, 129, 2, 129, 128, 60, 200, 195, 111, 43, 107, 228, 104, 191, 186, 21, 168, 21, 220, 172, 65, 143, 21, 4, 139, 48, 247, 122, 243, 55, 128, 107, 32, 213, 205, 76, 218, 230, 97, 202, 196, 128, 247, 242, 5, 181, 88, 209, 78, 145, 171, 178, 76, 0, 155, 44, 4, 157, 13, 85, 166, 27, 102, 58, 14, 129, 57, 128, 39, 194, 249, 22, 60, 124, 192, 153, 162, 58, 24, 19, 136, 232, 186, 67, 124, 142, 118, 48, 84, 227, 70, 98, 163, 164, 204, 16, 129, 21, 187, 108, 227, 246, 3, 139, 168, 109, 141, 57, 76, 177, 78, 210, 237, 1, 38, 50, 200, 52, 248, 228, 79, 149, 59, 44, 230, 225, 233, 78, 207, 9, 172, 135, 141, 2, 129, 129, 0, 159, 97, 92, 8, 76, 63, 113, 168, 5, 233, 58, 228, 155, 140, 19, 198, 225, 22, 110, 129, 71, 157, 118, 55, 94, 254, 112, 242, 244, 198, 217, 99, 175, 76, 225, 115, 14, 167, 243, 188, 219, 109, 122, 165, 15, 135, 5, 225, 235, 233, 121, 203, 211, 175, 135, 69, 205, 46, 93, 119, 95, 41, 226, 44, 233, 73, 97, 76, 15, 211, 139, 211, 206, 9, 176, 77, 30, 228, 93, 183, 93, 115, 237, 93, 140, 190, 8, 156, 58, 73, 145, 4, 224, 39, 159, 83, 234, 216, 224, 97, 165, 120, 123, 253, 159, 147, 119, 201, 144, 155, 171, 114, 129, 31, 44, 3, 58, 232, 180, 193, 155, 180, 143, 220, 132, 233, 153, 219}
	testKeySigRSA       jose.JSONWebKey
	testKeyPublicSigRSA jose.JSONWebKey
	testKeyEncRSA       jose.JSONWebKey
	testKeyPublicEncRSA jose.JSONWebKey

	testKeyBytesSigECDSA  = []byte{48, 129, 135, 2, 1, 0, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 4, 109, 48, 107, 2, 1, 1, 4, 32, 225, 45, 16, 217, 198, 48, 46, 37, 59, 165, 201, 242, 244, 143, 253, 127, 88, 84, 100, 25, 17, 39, 23, 128, 105, 241, 16, 227, 43, 47, 141, 187, 161, 68, 3, 66, 0, 4, 155, 65, 151, 191, 69, 30, 154, 72, 179, 179, 4, 5, 106, 97, 81, 20, 114, 8, 188, 137, 58, 81, 123, 3, 26, 111, 172, 26, 107, 212, 60, 52, 154, 177, 135, 254, 199, 8, 246, 198, 147, 23, 228, 46, 70, 145, 133, 222, 82, 222, 243, 113, 9, 10, 149, 59, 21, 144, 195, 215, 174, 175, 82, 51}
	testKeyBytesEncECDSA  = []byte{48, 129, 135, 2, 1, 0, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 4, 109, 48, 107, 2, 1, 1, 4, 32, 107, 125, 138, 26, 157, 158, 163, 251, 241, 207, 65, 183, 174, 68, 61, 135, 25, 188, 173, 245, 37, 8, 122, 233, 53, 113, 233, 221, 63, 91, 240, 100, 161, 68, 3, 66, 0, 4, 65, 254, 168, 68, 75, 55, 98, 71, 60, 193, 218, 125, 32, 224, 117, 19, 63, 145, 62, 117, 104, 107, 245, 157, 112, 192, 2, 44, 153, 73, 158, 193, 235, 150, 58, 174, 115, 25, 79, 68, 111, 142, 179, 168, 231, 172, 54, 214, 101, 18, 244, 173, 69, 22, 255, 235, 73, 227, 247, 206, 254, 183, 17, 177}
	testKeySigECDSA       jose.JSONWebKey
	testKeyPublicSigECDSA jose.JSONWebKey
	testKeyEncECDSA       jose.JSONWebKey
	testKeyPublicEncECDSA jose.JSONWebKey

	testCompactSerializedNestedJWEWithRSA   = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJjdHkiOiJKV1QiLCJlbmMiOiJBMTI4R0NNIiwia2lkIjoidGVzdC1yc2EtZW5jIiwidHlwIjoiSldUIn0.oWwJ7cVudU3U_EYu9vc4bXQqg7uH3xOvmjlRDKKFssc7oRDnM5IG3mvPpPnXm-jJhB0q4pGAHsVrCeRARUHTrkNWLgU4NtNhEhaeNVBoV38KxNyMXvfBdYoc91wPwN1TBQgSSBJ7FZPwDnUODAIIxh4NTyVJt6mEPlkDNrzViwv2zRhkfosdoiUJjbee2G5tQOV3Jj5o9gKrQOwZ9fJry-zKgOSeb0VR9s9vdfL8STKnwUnQ2HIYpsEG19IpXVut17Y8cIg43n65NrAHNxv2wRj-2vWij-bXM-YugSbNB7LH1n5H2wNW20nBKlYX7oLGWJHPuVxYftFIaPsm7m3sBA.6vLOfe12rdKCd0RW.-zYmgfbJNag4h0x3NQhzZCVAgczLDFYnW7fWKE51-ZyiUllRPiNuTQg-EQvwwNmFRNvwWpWFEpuhH9ceYYqfwrY0ZAqT7m3nDM24xvx46B2jZJvY3fCxB6XA72Afw4yxnRio_KMvS_vrTGsp4sLlHujolAAc3j-8y53uJ1y1mvfsKPT8i8YLyBtOT0wm1hVZAdyue-TA7iXjXRrbe2IdbW_FagXXyBW8JhOhFe9O5-T1Ts_SbPUQhwSYb5pIfUjfDLkVeEcOB9QNQw1Ai_bN2bgOh23sD4aS6G1alWEN0zHAzp0qgS7NXbyqBQefaUlcquSdM9JB9arLVGcy2IPFuC2zy7oppfcpCqmjPhXXJ0-WYA92FSAsREJCh6KsVu445KrfEQalyfmMd6qE2agDxqnDgdrIxlMzzxwCc4FvlwZ-3c3SDY5sZK_-auynoHx1adeguU1wPWY3Wy-2tEr5qsEK_P4M2h-AvcKRvMrqp6JLu3tQeSdhBGlLoEehABWp8fQqAASHlKEOLRe8znx2qSUMmdDfry8OzDYhYzcUf14YhneoEBv-HOLKykqaPWSlE-7Mkc6BY5gnoyHqznhP5cK6q-jCIUJVBRbKeTrWT2SiwZUcv89nDJL-YAMXG3GL_POPYr_TvTueRfyQL4xm1TRmZQ.fLEVOYxpohATkcNIolk1UA"
	testCompactSerializedNestedJWEWithECDSA = "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImN0eSI6IkpXVCIsImVuYyI6IkExMjhHQ00iLCJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJRcmdXc2wwN3lFclFjaXFMM1dKZE5FU015S01SR3d2bWRnYmlYNmRYSmpjIiwieSI6Ikl5MWRpellaZFVSTnpKS1FaVlZPVnkwSVVKWjhLaWVyN19LSllJS1hzaTAifSwia2lkIjoidGVzdC1lY2RzYS1lbmMiLCJ0eXAiOiJKV1QifQ.IDkNo5DGa6VQrL8ReJrBVixYN0S_VYYE.soDQKUuDrakfrQer.aaQWcWYoUF8ISUQ_EvkRCa75GeLFMsSK3imQjc3T0OalHsCIEXYCoV_vmjDPTd4svswMQtTiZxeajevnsBl_dtaEmykjqshxHww-07r36RhWKlix3gSTJTKUvGAhFDl24HcLnWUkZZjh0Vw0G9hLidax1OGoc43Rh08aHJ3swbj6yOA-KH-0SIBBmeK1Mfb0-1I4LRdAkCeyy4P6y8z2TvEqAtfCFDfAs5O8Zm9yVA6sxFAB5l6dK4WdotOh4F8lu-vE6MfD67Qi8xiW92ccYX7fBliNyypkDaN3B1k25N374qGXYl0_z0cX2T5ba_doVYgFNDFp.bmjYOk_ZXNTN2yZQjpFLjw"
)

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
			Use:       consts.JSONWebTokenUseSignature,
			Algorithm: string(jose.RS256),
		}
		testKeyPublicSigRSA = jose.JSONWebKey{
			Key:       k.Public(),
			KeyID:     "test-rsa-sig",
			Use:       consts.JSONWebTokenUseSignature,
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
			Use:       consts.JSONWebTokenUseEncryption,
			Algorithm: string(jose.RSA_OAEP_256),
		}
		testKeyPublicEncRSA = jose.JSONWebKey{
			Key:       k.Public(),
			KeyID:     "test-rsa-enc",
			Use:       consts.JSONWebTokenUseEncryption,
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
			Use:       consts.JSONWebTokenUseSignature,
			Algorithm: string(jose.ES256),
		}
		testKeyPublicSigECDSA = jose.JSONWebKey{
			Key:       k.Public(),
			KeyID:     "test-ecdsa-sig",
			Use:       consts.JSONWebTokenUseSignature,
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
			Use:       consts.JSONWebTokenUseEncryption,
			Algorithm: string(jose.ECDH_ES_A128KW),
		}
		testKeyPublicEncECDSA = jose.JSONWebKey{
			Key:       k.Public(),
			KeyID:     "test-ecdsa-enc",
			Use:       consts.JSONWebTokenUseEncryption,
			Algorithm: string(jose.ECDH_ES_A128KW),
		}
	default:
		panic("unsupported private key")
	}
}

func TestIniit(t *testing.T) {
	claims := MapClaims{
		"iss": "example.com",
		"sub": "john",
		"iat": time.Now().UTC().Unix(),
		"exp": time.Now().Add(time.Hour * 24 * 365 * 40).UTC().Unix(),
	}

	out, _, err := EncodeNestedCompactEncrypted(context.TODO(), claims, &Headers{}, &Headers{}, &testKeySigECDSA, &testKeyPublicEncECDSA, jose.A128GCM)

	fmt.Println(err)
	fmt.Println(out)
}
