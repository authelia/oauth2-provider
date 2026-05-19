// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"context"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithAllowUnverified(t *testing.T) {
	opts := &StrategyOpts{}
	require.NoError(t, WithAllowUnverified()(opts))
	assert.True(t, opts.allowUnverified)
}

func TestWithHeaders(t *testing.T) {
	headers := &Headers{Extra: map[string]any{"typ": "JWT"}}
	opts := &StrategyOpts{}
	require.NoError(t, WithHeaders(headers)(opts))
	assert.Same(t, headers, opts.headers)
}

func TestWithHeadersJWE(t *testing.T) {
	headers := &Headers{Extra: map[string]any{"typ": "JWT"}}
	opts := &StrategyOpts{}
	require.NoError(t, WithHeadersJWE(headers)(opts))
	assert.Same(t, headers, opts.headersJWE)
}

func TestWithClient(t *testing.T) {
	c := &testClient{id: "abc"}
	opts := &StrategyOpts{}
	require.NoError(t, WithClient(c)(opts))
	assert.Same(t, c, opts.client)
}

func TestWithIDTokenClient(t *testing.T) {
	t.Run("ShouldDecorateValidClient", func(t *testing.T) {
		c := &stubIDTokenClient{stubBase: stubBase{id: "abc"}, sigKID: "sig"}
		opts := &StrategyOpts{}
		require.NoError(t, WithIDTokenClient(c)(opts))
		require.NotNil(t, opts.client)
		assert.Equal(t, "sig", opts.client.GetSigningKeyID())
	})

	t.Run("ShouldNotSetClientForUnsupportedType", func(t *testing.T) {
		opts := &StrategyOpts{}
		require.NoError(t, WithIDTokenClient(struct{}{})(opts))
		assert.Nil(t, opts.client)
	})
}

func TestWithUserInfoClient(t *testing.T) {
	t.Run("ShouldDecorateValidClient", func(t *testing.T) {
		c := &stubUserInfoClient{stubBase: stubBase{id: "abc"}, sigKID: "sig"}
		opts := &StrategyOpts{}
		require.NoError(t, WithUserInfoClient(c)(opts))
		require.NotNil(t, opts.client)
		assert.Equal(t, "sig", opts.client.GetSigningKeyID())
	})

	t.Run("ShouldNotSetClientForUnsupportedType", func(t *testing.T) {
		opts := &StrategyOpts{}
		require.NoError(t, WithUserInfoClient(struct{}{})(opts))
		assert.Nil(t, opts.client)
	})
}

func TestWithIntrospectionClient(t *testing.T) {
	t.Run("ShouldDecorateValidClient", func(t *testing.T) {
		c := &stubIntrospectionClient{stubBase: stubBase{id: "abc"}, sigKID: "sig"}
		opts := &StrategyOpts{}
		require.NoError(t, WithIntrospectionClient(c)(opts))
		require.NotNil(t, opts.client)
		assert.Equal(t, "sig", opts.client.GetSigningKeyID())
	})

	t.Run("ShouldNotSetClientForUnsupportedType", func(t *testing.T) {
		opts := &StrategyOpts{}
		require.NoError(t, WithIntrospectionClient(struct{}{})(opts))
		assert.Nil(t, opts.client)
	})
}

func TestWithJARMClient(t *testing.T) {
	t.Run("ShouldDecorateValidClient", func(t *testing.T) {
		c := &stubJARMClient{stubBase: stubBase{id: "abc"}, sigKID: "sig"}
		opts := &StrategyOpts{}
		require.NoError(t, WithJARMClient(c)(opts))
		require.NotNil(t, opts.client)
		assert.Equal(t, "sig", opts.client.GetSigningKeyID())
	})

	t.Run("ShouldNotSetClientForUnsupportedType", func(t *testing.T) {
		opts := &StrategyOpts{}
		require.NoError(t, WithJARMClient(struct{}{})(opts))
		assert.Nil(t, opts.client)
	})
}

func TestWithJARClient(t *testing.T) {
	t.Run("ShouldDecorateValidClient", func(t *testing.T) {
		c := &stubJARClient{stubBase: stubBase{id: "abc"}, sigKID: "sig"}
		opts := &StrategyOpts{}
		require.NoError(t, WithJARClient(c)(opts))
		require.NotNil(t, opts.client)
		assert.Equal(t, "sig", opts.client.GetSigningKeyID())
		assert.True(t, opts.client.IsClientSigned())
	})

	t.Run("ShouldNotSetClientForUnsupportedType", func(t *testing.T) {
		opts := &StrategyOpts{}
		require.NoError(t, WithJARClient(struct{}{})(opts))
		assert.Nil(t, opts.client)
	})
}

func TestWithJWTProfileAccessTokenClient(t *testing.T) {
	t.Run("ShouldDecorateValidClient", func(t *testing.T) {
		c := &stubJWTProfileAccessTokenClient{stubBase: stubBase{id: "abc"}, sigKID: "sig"}
		opts := &StrategyOpts{}
		require.NoError(t, WithJWTProfileAccessTokenClient(c)(opts))
		require.NotNil(t, opts.client)
		assert.Equal(t, "sig", opts.client.GetSigningKeyID())
	})

	t.Run("ShouldNotSetClientForUnsupportedType", func(t *testing.T) {
		opts := &StrategyOpts{}
		require.NoError(t, WithJWTProfileAccessTokenClient(struct{}{})(opts))
		assert.Nil(t, opts.client)
	})
}

func TestWithStatelessJWTProfileIntrospectionClient(t *testing.T) {
	t.Run("ShouldPreferIntrospectionClient", func(t *testing.T) {
		c := &stubIntrospectionClient{stubBase: stubBase{id: "ix"}, sigKID: "ix-sig"}
		opts := &StrategyOpts{}
		require.NoError(t, WithStatelessJWTProfileIntrospectionClient(c)(opts))
		require.NotNil(t, opts.client)
		assert.Equal(t, "ix-sig", opts.client.GetSigningKeyID())
	})

	t.Run("ShouldFallbackToJWTProfileAccessTokenClient", func(t *testing.T) {
		c := &stubJWTProfileAccessTokenClient{stubBase: stubBase{id: "at"}, sigKID: "at-sig"}
		opts := &StrategyOpts{}
		require.NoError(t, WithStatelessJWTProfileIntrospectionClient(c)(opts))
		require.NotNil(t, opts.client)
		assert.Equal(t, "at-sig", opts.client.GetSigningKeyID())
	})

	t.Run("ShouldNotSetClientForUnsupportedType", func(t *testing.T) {
		opts := &StrategyOpts{}
		require.NoError(t, WithStatelessJWTProfileIntrospectionClient(struct{}{})(opts))
		assert.Nil(t, opts.client)
	})
}

func TestWithSigAlgorithm(t *testing.T) {
	opts := &StrategyOpts{}
	algs := []jose.SignatureAlgorithm{jose.RS256, jose.ES256}
	require.NoError(t, WithSigAlgorithm(algs...)(opts))
	assert.Equal(t, algs, opts.sigAlgorithm)
}

func TestWithKeyAlgorithm(t *testing.T) {
	opts := &StrategyOpts{}
	algs := []jose.KeyAlgorithm{jose.RSA_OAEP_256, jose.ECDH_ES_A128KW}
	require.NoError(t, WithKeyAlgorithm(algs...)(opts))
	assert.Equal(t, algs, opts.keyAlgorithm)
}

func TestWithContentEncryption(t *testing.T) {
	opts := &StrategyOpts{}
	encs := []jose.ContentEncryption{jose.A128GCM, jose.A256GCM}
	require.NoError(t, WithContentEncryption(encs...)(opts))
	assert.Equal(t, encs, opts.contentEncryption)
}

func TestWithKeyFunc(t *testing.T) {
	called := false
	f := func(ctx context.Context, token *jwt.JSONWebToken, claims MapClaims) (*jose.JSONWebKey, error) {
		called = true

		return nil, nil
	}

	opts := &StrategyOpts{}
	require.NoError(t, WithKeyFunc(f)(opts))
	require.NotNil(t, opts.jwsKeyFunc)

	_, _ = opts.jwsKeyFunc(t.Context(), nil, nil)
	assert.True(t, called, "key func should be invoked")
}

func TestWithKeyFuncJWE(t *testing.T) {
	called := false
	f := func(ctx context.Context, jwe *jose.JSONWebEncryption, kid, alg string) (*jose.JSONWebKey, error) {
		called = true

		return nil, nil
	}

	opts := &StrategyOpts{}
	require.NoError(t, WithKeyFuncJWE(f)(opts))
	require.NotNil(t, opts.jweKeyFunc)

	_, _ = opts.jweKeyFunc(t.Context(), nil, "", "")
	assert.True(t, called, "key func should be invoked")
}
