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
