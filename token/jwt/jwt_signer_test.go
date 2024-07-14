// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"context"
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
	var key any = gen.MustRSAKey()
	for k, tc := range []struct {
		d        string
		strategy Signer
		resetKey func(strategy Signer)
	}{
		{
			d: "DefaultSigner",
			strategy: &DefaultSigner{
				GetPrivateKey: func(_ context.Context) (any, error) {
					return key, nil
				},
			},
			resetKey: func(strategy Signer) {
				key = gen.MustRSAKey()
			},
		},
		{
			d: "ES256JWTStrategy",
			strategy: &DefaultSigner{
				GetPrivateKey: func(_ context.Context) (any, error) {
					return key, nil
				},
			},
			resetKey: func(strategy Signer) {
				key = &jose.JSONWebKey{
					Key:       gen.MustES521Key(),
					Algorithm: "ES512",
				}
			},
		},
		{
			d: "ES256JWTStrategy",
			strategy: &DefaultSigner{
				GetPrivateKey: func(_ context.Context) (any, error) {
					return key, nil
				},
			},
			resetKey: func(strategy Signer) {
				key = gen.MustES256Key()
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d/strategy=%s", k, tc.d), func(t *testing.T) {
			claims := &JWTClaims{
				ExpiresAt: time.Now().UTC().Add(time.Hour),
			}

			token, sig, err := tc.strategy.Generate(context.TODO(), claims.ToMapClaims(), header)
			require.NoError(t, err)
			require.NotNil(t, token)
			assert.NotEmpty(t, sig)

			sig, err = tc.strategy.Validate(context.TODO(), token)
			require.NoError(t, err)
			assert.NotEmpty(t, sig)

			sig, err = tc.strategy.Validate(context.TODO(), token+"."+"0123456789")
			require.Error(t, err)
			assert.Empty(t, sig)

			partToken := strings.Split(token, ".")[2]

			sig, err = tc.strategy.Validate(context.TODO(), partToken)
			require.Error(t, err)
			assert.Empty(t, sig)

			tc.resetKey(tc.strategy)

			claims = &JWTClaims{
				ExpiresAt: time.Now().UTC().Add(-time.Hour),
			}

			token, sig, err = tc.strategy.Generate(context.TODO(), claims.ToMapClaims(), header)
			require.NoError(t, err)
			require.NotNil(t, token)
			assert.NotEmpty(t, sig)

			sig, err = tc.strategy.Validate(context.TODO(), token)
			require.Error(t, err)
			require.Empty(t, sig)

			claims = &JWTClaims{
				NotBefore: time.Now().UTC().Add(time.Hour),
			}

			token, sig, err = tc.strategy.Generate(context.TODO(), claims.ToMapClaims(), header)
			require.NoError(t, err)
			require.NotNil(t, token)
			assert.NotEmpty(t, sig)

			sig, err = tc.strategy.Validate(context.TODO(), token)
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
