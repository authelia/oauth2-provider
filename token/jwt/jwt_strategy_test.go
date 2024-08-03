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

	strategy := &DefaultStrategy{
		Config: config,
		Issuer: issuer,
	}

	var (
		token, signature string
	)

	claims := MapClaims{
		"value": 1,
	}

	headers := &Headers{
		Extra: map[string]any{
			consts.JSONWebTokenHeaderType: consts.JSONWebTokenTypeAccessToken,
		},
	}

	var headersEnc *Headers

	token, signature, err = strategy.Encode(context.Background(), client, claims, headers, headersEnc)
	require.NoError(t, err)

	fmt.Println(token)
	fmt.Println(signature)

	headersEnc = &Headers{}

	token, signature, err = strategy.Encode(context.Background(), clientEnc, claims, headers, headersEnc)
	require.NoError(t, err)

	fmt.Println(token)
	fmt.Println(signature)

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
		csigned: false,
		jwks:    issuerClientJWKS,
		jwksURI: "",
	}

	tok, err := clientStrategy.Decode(context.Background(), token, issuerClient)
	require.NoError(t, err)

	fmt.Println(tok)
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
