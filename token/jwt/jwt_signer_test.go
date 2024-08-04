// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwt

/*

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/internal/gen"
)


var header = &Headers{
	Extra: map[string]any{
		"foo": "bar",
	},
}

func TestEncrypt(t *testing.T) {
	i, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	c, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	issuer := jose.JSONWebKey{
		Key:       i,
		KeyID:     "iss-abc123-es512",
		Algorithm: string(jose.ES512),
		Use:       "sig",
	}

	clientP := jose.JSONWebKey{
		Key:       c,
		KeyID:     "client-abc123-es512",
		Algorithm: string(jose.ECDH_ES_A256KW),
		Use:       "enc",
	}

	client := jose.JSONWebKey{
		Key:       &c.PublicKey,
		KeyID:     "client-abc123-es512",
		Algorithm: string(jose.ECDH_ES_A256KW),
		Use:       "enc",
	}

	issuerPublic := jose.JSONWebKey{
		Key:       &i.PublicKey,
		KeyID:     "iss-abc123-es512",
		Algorithm: string(jose.ES512),
		Use:       "sig",
	}

	key := make([]byte, 64)

	_, err = rand.Read(key)
	require.NoError(t, err)

	issuerDirect := jose.JSONWebKey{
		Key:       key,
		KeyID:     "iss-abc123-es512",
		Algorithm: string(jose.DIRECT),
		Use:       "enc",
	}

	data, err := json.Marshal(issuer)
	require.NoError(t, err)
	fmt.Println(string(data))

	data, err = json.Marshal(issuer.Public())
	require.NoError(t, err)
	fmt.Println(string(data))

	data, err = json.Marshal(issuerPublic)
	require.NoError(t, err)
	fmt.Println(string(data))

	data, err = json.Marshal(issuerPublic.Public())
	require.NoError(t, err)
	fmt.Println(string(data))

	data, err = json.Marshal(client)
	require.NoError(t, err)
	fmt.Println(string(data))

	data, err = json.Marshal(clientP)
	require.NoError(t, err)
	fmt.Println(string(data))

	data, err = json.Marshal(issuerDirect)
	require.NoError(t, err)
	fmt.Println(string(data))

	jwk2 := New()
	jwk := New()

	claims := MapClaims{
		"name": "example",
	}

	jwsHeaders := &Headers{}
	jweHeaders := &Headers{}

	jwk.SetJWS(jwsHeaders, claims, jose.SignatureAlgorithm(issuer.Algorithm))
	jwk2.SetJWS(jwsHeaders, claims, jose.ES256)
	jwk.SetJWE(jweHeaders, jose.KeyAlgorithm(client.Algorithm), jose.A256GCM, jose.NONE)

	token, signature, err := jwk.CompactEncrypted(&issuer, &client)
	require.NoError(t, err)

	fmt.Println(token)
	fmt.Println(signature)

	token, signature, err = jwk2.CompactSigned(&issuer)
	require.NoError(t, err)

	fmt.Println(token)
	fmt.Println(signature)
}

func TestHash(t *testing.T) {
	for k, tc := range []struct {
		d        string
		strategy Signer
	}{
		{
			d: "RS256",
			strategy: &DefaultSigner{GetPrivateKey: func(_ context.Context) (any, error) {
				return gen.MustRSAKey(), nil
			}},
		},
		{
			d: "ES256",
			strategy: &DefaultSigner{GetPrivateKey: func(_ context.Context) (any, error) {
				return gen.MustES256Key(), nil
			}},
		},
	} {
		t.Run(fmt.Sprintf("case=%d/strategy=%s", k, tc.d), func(t *testing.T) {
			in := []byte("foo")
			out, err := tc.strategy.Hash(context.TODO(), in)
			assert.NoError(t, err)
			assert.NotEqual(t, in, out)
		})
	}
}

func TestAssign(t *testing.T) {
	for k, c := range [][]map[string]any{
		{
			{"foo": "bar"},
			{"baz": "bar"},
			{"foo": "bar", "baz": "bar"},
		},
		{
			{"foo": "bar"},
			{"foo": "baz"},
			{"foo": "bar"},
		},
		{
			{},
			{"foo": "baz"},
			{"foo": "baz"},
		},
		{
			{"foo": "bar"},
			{"foo": "baz", "bar": "baz"},
			{"foo": "bar", "bar": "baz"},
		},
	} {
		assert.EqualValues(t, c[2], assign(c[0], c[1]), "Case %d", k)
	}
}

func TestGenerateJWT(t *testing.T) {
	testCases := []struct {
		name string
		key  func() any
	}{
		{
			name: "DefaultSigner",
			key: func() any {
				return gen.MustRSAKey()
			},
		},
		{
			name: "ES256JWTStrategy",
			key: func() any {
				return gen.MustES256Key()
			},
		},
		{
			name: "ES256JWTStrategyWithJSONWebKey",
			key: func() any {
				return &jose.JSONWebKey{
					Key:       gen.MustES521Key(),
					Algorithm: "ES512",
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			key := tc.key()

			strategy := &DefaultSigner{
				GetPrivateKey: func(_ context.Context) (any, error) {
					return key, nil
				},
			}

			claims := &JWTClaims{
				ExpiresAt: time.Now().UTC().Add(time.Hour),
			}

			token, sig, err := strategy.Generate(ctx, claims.ToMapClaims(), header)
			require.NoError(t, err)
			require.NotNil(t, token)
			assert.NotEmpty(t, sig)

			sig, err = strategy.Validate(ctx, token)
			require.NoError(t, err)
			assert.NotEmpty(t, sig)

			sig, err = strategy.Validate(ctx, token+"."+"0123456789")
			require.Error(t, err)
			assert.Empty(t, sig)

			partToken := strings.Split(token, ".")[2]

			sig, err = strategy.Validate(ctx, partToken)
			require.Error(t, err)
			assert.Empty(t, sig)

			key = tc.key()

			claims = &JWTClaims{
				ExpiresAt: time.Now().UTC().Add(-time.Hour),
			}

			token, sig, err = strategy.Generate(ctx, claims.ToMapClaims(), header)
			require.NoError(t, err)
			require.NotNil(t, token)
			assert.NotEmpty(t, sig)

			sig, err = strategy.Validate(ctx, token)
			require.Error(t, err)
			require.Empty(t, sig)

			claims = &JWTClaims{
				NotBefore: time.Now().UTC().Add(time.Hour),
			}

			token, sig, err = strategy.Generate(ctx, claims.ToMapClaims(), header)
			require.NoError(t, err)
			require.NotNil(t, token)
			assert.NotEmpty(t, sig)

			sig, err = strategy.Validate(ctx, token)
			require.Error(t, err)
			require.Empty(t, sig, "%s", err)
		})
	}
}

func TestValidateSignatureRejectsJWT(t *testing.T) {
	for k, tc := range []struct {
		d        string
		strategy Signer
	}{
		{
			d: "RS256",
			strategy: &DefaultSigner{GetPrivateKey: func(_ context.Context) (any, error) {
				return gen.MustRSAKey(), nil
			},
			},
		},
		{
			d: "ES256",
			strategy: &DefaultSigner{
				GetPrivateKey: func(_ context.Context) (any, error) {
					return gen.MustES256Key(), nil
				},
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d/strategy=%s", k, tc.d), func(t *testing.T) {
			for k, c := range []string{
				"",
				" ",
				"foo.bar",
				"foo.",
				".foo",
			} {
				_, err := tc.strategy.Validate(context.TODO(), c)
				assert.Error(t, err)
				t.Logf("Passed test case %d", k)
			}
		})
	}
}

*/
