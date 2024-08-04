package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/go-jose/go-jose/v4"
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

	require.True(t, IsSignedJWT(token1))

	fmt.Println("---------")
	fmt.Println("Token 1:")
	fmt.Println("\tValue:", token1)
	fmt.Println("\tSignature:", signature1)
	fmt.Println("---------")
	fmt.Println("")

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

	fmt.Println("---------")
	fmt.Println("Token 2:")
	fmt.Println("\tValue:", token2)
	fmt.Println("\tSignature:", signature2)
	fmt.Println("---------")
	fmt.Println("")

	var (
		token3, signature3 string
	)

	token3, signature3, err = strategy.Encode(ctx, WithClaims(claims), WithHeaders(headers1), WithHeadersJWE(headersEnc), WithClient(clientEncAsymmetric))
	require.NoError(t, err)

	fmt.Println("---------")
	fmt.Println("Token 3:")
	fmt.Println("\tValue:", token3)
	fmt.Println("\tSignature:", signature3)
	fmt.Println("---------")
	fmt.Println("")

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

	fmt.Println("---------")
	fmt.Println("Token 2 (Decrypted):")
	fmt.Println("\tValue:", tokenString)
	fmt.Println("\tSignature:", signature)
	fmt.Println("\tJWE:", jwe)
	fmt.Println("---------")
	fmt.Println("")

	tokenString, signature, jwe, err = clientStrategy.Decrypt(ctx, token3, WithClient(clientEncAsymmetric))
	require.NoError(t, err)

	fmt.Println("---------")
	fmt.Println("Token 3 (Decrypted):")
	fmt.Println("\tValue:", tokenString)
	fmt.Println("\tSignature:", signature)
	fmt.Println("\tJWE:", jwe)
	fmt.Println("---------")
	fmt.Println("")

	tok, err := clientStrategy.Decode(ctx, token1, WithClient(issuerClient))
	require.NoError(t, err)

	fmt.Printf("%v+\n", tok)

	tok, err = clientStrategy.Decode(ctx, token2, WithClient(issuerClient))
	require.NoError(t, err)

	fmt.Printf("%v+\n", tok)

	tok, err = clientStrategy.Decode(ctx, token3, WithClient(clientEncAsymmetric))
	require.NoError(t, err)

	fmt.Printf("%v+\n", tok)
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
