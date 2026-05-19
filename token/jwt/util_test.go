// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWKLookupError_GetDescription(t *testing.T) {
	err := &JWKLookupError{Description: "missing kid"}
	assert.Equal(t, "missing kid", err.GetDescription())
}

func TestJWKLookupError_Error(t *testing.T) {
	err := &JWKLookupError{Description: "missing kid"}
	assert.Equal(t, "Error occurred retrieving the JSON Web Key. missing kid", err.Error())
}

func TestSearchJWKS(t *testing.T) {
	rsaKey := mustRSAKey(t, 2048)

	keyA := jose.JSONWebKey{
		Key:       rsaKey,
		KeyID:     "kid-a",
		Use:       JSONWebTokenUseSignature,
		Algorithm: string(jose.RS256),
	}
	keyB := jose.JSONWebKey{
		Key:       rsaKey,
		KeyID:     "kid-b",
		Use:       JSONWebTokenUseSignature,
		Algorithm: string(jose.RS256),
	}
	keyEnc := jose.JSONWebKey{
		Key:       rsaKey,
		KeyID:     "kid-c",
		Use:       JSONWebTokenUseEncryption,
		Algorithm: string(jose.RSA_OAEP_256),
	}

	t.Run("ShouldErrorEmptyJWKS", func(t *testing.T) {
		_, err := SearchJWKS(&jose.JSONWebKeySet{}, "kid-a", string(jose.RS256), JSONWebTokenUseSignature, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not contain any key")
	})

	t.Run("ShouldFindByKid", func(t *testing.T) {
		key, err := SearchJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{keyA, keyB, keyEnc}}, "kid-b", string(jose.RS256), JSONWebTokenUseSignature, false)
		require.NoError(t, err)
		assert.Equal(t, "kid-b", key.KeyID)
	})

	t.Run("ShouldFindWithEmptyKidByAlgAndUse", func(t *testing.T) {
		key, err := SearchJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{keyEnc, keyA}}, "", string(jose.RS256), JSONWebTokenUseSignature, false)
		require.NoError(t, err)
		assert.Equal(t, "kid-a", key.KeyID)
	})

	t.Run("ShouldErrorKidNotFound", func(t *testing.T) {
		_, err := SearchJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{keyA}}, "missing", string(jose.RS256), JSONWebTokenUseSignature, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "which was not found")
	})

	t.Run("ShouldErrorWhenNoneMatchAlgOrUse", func(t *testing.T) {
		_, err := SearchJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{keyA}}, "kid-a", string(jose.RS384), JSONWebTokenUseSignature, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Unable to find JSON web key")
	})

	t.Run("ShouldReturnFirstWhenMultipleMatch", func(t *testing.T) {
		jwks := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{keyA, keyA}}
		key, err := SearchJWKS(jwks, "kid-a", string(jose.RS256), JSONWebTokenUseSignature, false)
		require.NoError(t, err)
		require.NotNil(t, key)
	})

	t.Run("ShouldErrorWhenMultipleMatchAndStrict", func(t *testing.T) {
		jwks := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{keyA, keyA}}
		_, err := SearchJWKS(jwks, "kid-a", string(jose.RS256), JSONWebTokenUseSignature, true)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Unable to find JSON web key")
	})
}

type stubFetcher struct {
	jwks      *jose.JSONWebKeySet
	jwksForce *jose.JSONWebKeySet
	calls     int
	err       error
}

func (f *stubFetcher) Resolve(ctx context.Context, location string, ignoreCache bool) (*jose.JSONWebKeySet, error) {
	f.calls++

	if f.err != nil {
		return nil, f.err
	}

	if ignoreCache && f.jwksForce != nil {
		return f.jwksForce, nil
	}

	return f.jwks, nil
}

func TestFindClientPublicJWK(t *testing.T) {
	rsaKey := mustRSAKey(t, 2048)

	sigKey := jose.JSONWebKey{
		Key:       rsaKey,
		KeyID:     "kid",
		Use:       JSONWebTokenUseSignature,
		Algorithm: string(jose.RS256),
	}

	t.Run("ShouldReturnFromInlineJWKS", func(t *testing.T) {
		client := &testClient{jwks: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{sigKey}}}
		key, err := FindClientPublicJWK(t.Context(), client, nil, "kid", string(jose.RS256), JSONWebTokenUseSignature, true)
		require.NoError(t, err)
		assert.Equal(t, "kid", key.KeyID)
	})

	t.Run("ShouldErrorWhenNoJWKSOrURI", func(t *testing.T) {
		client := &testClient{}
		_, err := FindClientPublicJWK(t.Context(), client, nil, "kid", string(jose.RS256), JSONWebTokenUseSignature, true)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "No JWKs have been registered for the client")
	})

	t.Run("ShouldFetchFromURIWhenAbsent", func(t *testing.T) {
		client := &testClient{jwksURI: "https://example.com/jwks.json"}
		fetcher := &stubFetcher{
			jwks: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{sigKey}},
		}
		key, err := FindClientPublicJWK(t.Context(), client, fetcher, "kid", string(jose.RS256), JSONWebTokenUseSignature, true)
		require.NoError(t, err)
		assert.Equal(t, "kid", key.KeyID)
		assert.Equal(t, 1, fetcher.calls, "fetcher should be called once when first lookup succeeds")
	})

	t.Run("ShouldRefetchWhenFirstLookupFails", func(t *testing.T) {
		client := &testClient{jwksURI: "https://example.com/jwks.json"}
		fetcher := &stubFetcher{
			jwks:      &jose.JSONWebKeySet{},
			jwksForce: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{sigKey}},
		}
		key, err := FindClientPublicJWK(t.Context(), client, fetcher, "kid", string(jose.RS256), JSONWebTokenUseSignature, true)
		require.NoError(t, err)
		assert.Equal(t, "kid", key.KeyID)
		assert.Equal(t, 2, fetcher.calls, "fetcher should be called twice when first lookup fails")
	})

	t.Run("ShouldPropagateFetcherError", func(t *testing.T) {
		client := &testClient{jwksURI: "https://example.com/jwks.json"}
		fetcher := &stubFetcher{err: fmt.Errorf("fetch failed")}
		_, err := FindClientPublicJWK(t.Context(), client, fetcher, "kid", string(jose.RS256), JSONWebTokenUseSignature, true)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "fetch failed")
	})
}

func TestNewClientSecretJWKFromClient(t *testing.T) {
	t.Run("ShouldErrorWhenClientReturnsError", func(t *testing.T) {
		client := &testClient{}
		_, err := NewClientSecretJWKFromClient(t.Context(), client, "kid", string(jose.HS256), "", JSONWebTokenUseSignature)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "The client returned an error")
	})

	t.Run("ShouldErrorWhenClientHasNoSecret", func(t *testing.T) {
		client := &testClient{secretNotDefined: true}
		_, err := NewClientSecretJWKFromClient(t.Context(), client, "kid", string(jose.HS256), "", JSONWebTokenUseSignature)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "The client is not configured with a client secret")
	})

	t.Run("ShouldReturnJWKWhenSecretAvailable", func(t *testing.T) {
		client := &testClient{secret: []byte("super-secret-value")}
		key, err := NewClientSecretJWKFromClient(t.Context(), client, "kid", string(jose.HS256), "", JSONWebTokenUseSignature)
		require.NoError(t, err)
		require.NotNil(t, key)
		assert.Equal(t, "kid", key.KeyID)
		assert.Equal(t, string(jose.HS256), key.Algorithm)
	})
}

func TestNewClientSecretJWK(t *testing.T) {
	secret := []byte("super-secret-value-of-some-length")

	testCases := []struct {
		name    string
		alg     string
		enc     string
		use     string
		wantErr string
		keyLen  int
	}{
		{
			name:   "ShouldDeriveHS256SignatureKey",
			alg:    string(jose.HS256),
			use:    JSONWebTokenUseSignature,
			keyLen: 32,
		},
		{
			name:   "ShouldDeriveHS384SignatureKey",
			alg:    string(jose.HS384),
			use:    JSONWebTokenUseSignature,
			keyLen: 48,
		},
		{
			name:   "ShouldDeriveHS512SignatureKey",
			alg:    string(jose.HS512),
			use:    JSONWebTokenUseSignature,
			keyLen: 64,
		},
		{
			name:    "ShouldErrorUnsupportedSignatureAlg",
			alg:     "unknown",
			use:     JSONWebTokenUseSignature,
			wantErr: "Unsupported algorithm 'unknown'",
		},
		{
			name:   "ShouldDeriveA128KWEncryptionKey",
			alg:    string(jose.A128KW),
			use:    JSONWebTokenUseEncryption,
			keyLen: 16,
		},
		{
			name:   "ShouldDeriveA192KWEncryptionKey",
			alg:    string(jose.A192KW),
			use:    JSONWebTokenUseEncryption,
			keyLen: 24,
		},
		{
			name:   "ShouldDeriveA256KWEncryptionKey",
			alg:    string(jose.A256KW),
			use:    JSONWebTokenUseEncryption,
			keyLen: 32,
		},
		{
			name:   "ShouldDerivePBES2HS256A128KWEncryptionKey",
			alg:    string(jose.PBES2_HS256_A128KW),
			use:    JSONWebTokenUseEncryption,
			keyLen: 16,
		},
		{
			name:   "ShouldDeriveDirectKeyA128CBCHS256",
			alg:    string(jose.DIRECT),
			enc:    string(jose.A128CBC_HS256),
			use:    JSONWebTokenUseEncryption,
			keyLen: 32,
		},
		{
			name:   "ShouldDeriveDirectKeyA192CBCHS384",
			alg:    string(jose.DIRECT),
			enc:    string(jose.A192CBC_HS384),
			use:    JSONWebTokenUseEncryption,
			keyLen: 48,
		},
		{
			name:   "ShouldDeriveDirectKeyA256CBCHS512",
			alg:    string(jose.DIRECT),
			enc:    string(jose.A256CBC_HS512),
			use:    JSONWebTokenUseEncryption,
			keyLen: 64,
		},
		{
			name:   "ShouldDeriveDirectKeyDefaultsToA128CBCHS256",
			alg:    string(jose.DIRECT),
			use:    JSONWebTokenUseEncryption,
			keyLen: 32,
		},
		{
			name:    "ShouldErrorUnsupportedDirectContentEncryption",
			alg:     string(jose.DIRECT),
			enc:     "unknown",
			use:     JSONWebTokenUseEncryption,
			wantErr: "Unsupported content encryption for the direct key algorthm 'unknown'",
		},
		{
			name:    "ShouldErrorUnsupportedEncryptionAlg",
			alg:     "unknown",
			use:     JSONWebTokenUseEncryption,
			wantErr: "Unsupported algorithm 'unknown'",
		},
		{
			name:   "ShouldReturnRawSecretForUnknownUse",
			alg:    string(jose.HS256),
			use:    "other",
			keyLen: len(secret),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := NewClientSecretJWK(t.Context(), secret, "kid", tc.alg, tc.enc, tc.use)

			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, key)
			assert.Equal(t, "kid", key.KeyID)
			assert.Equal(t, tc.alg, key.Algorithm)
			assert.Equal(t, tc.use, key.Use)

			if b, ok := key.Key.([]byte); ok {
				assert.Len(t, b, tc.keyLen)
			}
		})
	}

	t.Run("ShouldErrorOnEmptySecret", func(t *testing.T) {
		_, err := NewClientSecretJWK(t.Context(), nil, "kid", string(jose.HS256), "", JSONWebTokenUseSignature)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is not configured with a client secret")
	})
}

func TestGetJWTSignature(t *testing.T) {
	testCases := []struct {
		name     string
		token    string
		expected string
		wantErr  string
	}{
		{
			name:     "ShouldReturnSignatureForThreeSegments",
			token:    "header.payload.signature",
			expected: "signature",
		},
		{
			name:    "ShouldErrorForFiveSegments",
			token:   "a.b.c.d.e",
			wantErr: "the token is probably encrypted",
		},
		{
			name:    "ShouldErrorForUnknownFormat",
			token:   "single-segment",
			wantErr: "the format is unknown",
		},
		{
			name:    "ShouldErrorForTwoSegments",
			token:   "foo.bar",
			wantErr: "the format is unknown",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sig, err := getJWTSignature(tc.token)

			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, sig)
		})
	}
}

func TestAssign(t *testing.T) {
	a := map[string]any{"existing": 1}
	b := map[string]any{"existing": 99, "new": 2}

	assign(a, b)

	assert.Equal(t, 1, a["existing"], "existing keys must not be overwritten")
	assert.Equal(t, 2, a["new"], "missing keys must be copied over")
}

func TestGetPublicJWK(t *testing.T) {
	rsaKey := mustRSAKey(t, 2048)

	t.Run("ShouldReturnEmptyForNil", func(t *testing.T) {
		jwk := getPublicJWK(nil)
		assert.Equal(t, jose.JSONWebKey{}, jwk)
	})

	t.Run("ShouldReturnRawKeyForClientSecretHS256", func(t *testing.T) {
		secret := []byte("secret")
		input := &jose.JSONWebKey{Key: secret, Algorithm: string(jose.HS256), KeyID: "kid"}
		jwk := getPublicJWK(input)
		assert.Equal(t, secret, jwk.Key)
		assert.Equal(t, "kid", jwk.KeyID)
	})

	t.Run("ShouldReturnRSAPublicForRSAPrivate", func(t *testing.T) {
		input := &jose.JSONWebKey{Key: rsaKey, Algorithm: string(jose.RS256), KeyID: "kid"}
		jwk := getPublicJWK(input)
		_, ok := jwk.Key.(*rsa.PublicKey)
		assert.True(t, ok)
	})
}

func TestUnsafeParseSignedAny(t *testing.T) {
	t.Run("ShouldParseNoneToken", func(t *testing.T) {
		token := NewWithClaims(SigningMethodNone, MapClaims{"foo": "bar"})
		raw, err := token.CompactSignedString(UnsafeAllowNoneSignatureType)
		require.NoError(t, err)

		var dest struct {
			Foo string `json:"foo"`
		}

		parsed, err := UnsafeParseSignedAny(raw, &dest)
		require.NoError(t, err)
		require.NotNil(t, parsed)
		assert.Equal(t, "bar", dest.Foo)
	})

	t.Run("ShouldErrorOnInvalidToken", func(t *testing.T) {
		var dest struct{}

		_, err := UnsafeParseSignedAny("not-a-jwt", &dest)
		require.Error(t, err)
	})
}

func TestNewError(t *testing.T) {
	base := errors.New("base")
	extra := errors.New("extra")

	t.Run("ShouldWrapWithoutMessage", func(t *testing.T) {
		err := newError("", base)
		assert.True(t, errors.Is(err, base))
		assert.Equal(t, "base", err.Error())
	})

	t.Run("ShouldWrapWithMessage", func(t *testing.T) {
		err := newError("context", base)
		assert.True(t, errors.Is(err, base))
		assert.Equal(t, "base: context", err.Error())
	})

	t.Run("ShouldWrapMultipleErrors", func(t *testing.T) {
		err := newError("context", base, extra)
		assert.True(t, errors.Is(err, base))
		assert.True(t, errors.Is(err, extra))
		assert.Contains(t, err.Error(), "base")
		assert.Contains(t, err.Error(), "extra")
	})
}

func TestNewMapClaims(t *testing.T) {
	type nested struct {
		X int `json:"x"`
	}

	type sample struct {
		Sub      string `json:"sub"`
		Skip     string `json:"-"`
		Untagged string //nolint:unused
		Empty    string `json:"empty,omitempty"`
		Set      string `json:"set,omitempty"`
		Nested   nested `json:"nested"`
	}

	s := &sample{Sub: "peter", Set: "value", Nested: nested{X: 5}}
	mc := NewMapClaims(s)

	assert.Equal(t, "peter", mc["sub"])
	assert.Equal(t, "value", mc["set"])
	_, hasSkip := mc["-"]
	assert.False(t, hasSkip, "fields with json:\"-\" must be skipped")
	_, hasEmpty := mc["empty"]
	assert.False(t, hasEmpty, "omitempty fields with zero value must be skipped")
	require.NotNil(t, mc["nested"])
	nestedMap := mc["nested"].(map[string]any)
	assert.Equal(t, 5, nestedMap["x"])
}

func TestNewMapClaimsNil(t *testing.T) {
	mc := NewMapClaims(nil)
	assert.Empty(t, mc)
}

func TestParseTag(t *testing.T) {
	tag, opts := parseTag("sub,omitempty")
	assert.Equal(t, "sub", tag)
	assert.Equal(t, tagOptionsJSON("omitempty"), opts)

	tag, opts = parseTag("sub")
	assert.Equal(t, "sub", tag)
	assert.Equal(t, tagOptionsJSON(""), opts)
}

func TestTagOptions_Contains(t *testing.T) {
	o := tagOptionsJSON("omitempty,string")
	assert.True(t, o.Contains("omitempty"))
	assert.True(t, o.Contains("string"))
	assert.False(t, o.Contains("missing"))

	empty := tagOptionsJSON("")
	assert.False(t, empty.Contains("anything"))
}
