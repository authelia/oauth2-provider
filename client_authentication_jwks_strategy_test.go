// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/go-jose/go-jose/v4"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/internal/gen"
)

func initServerWithKey(t *testing.T) *httptest.Server {
	var set *jose.JSONWebKeySet
	var h http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewEncoder(w).Encode(set))
	}
	ts := httptest.NewServer(h)

	set = &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				KeyID: "bar",
				Use:   "sig",
				Key:   &gen.MustRSAKey().PublicKey,
			},
		},
	}

	t.Cleanup(ts.Close)
	return ts
}

var errRoundTrip = errors.New("roundtrip error")

type failingTripper struct{}

func (r *failingTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errRoundTrip
}

func TestDefaultJWKSFetcherStrategyFetching(t *testing.T) {
	ctx := context.Background()
	s := NewDefaultJWKSFetcherStrategy()

	var set *jose.JSONWebKeySet
	h := func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewEncoder(w).Encode(set))
	}
	ts := httptest.NewServer(http.HandlerFunc(h))
	defer ts.Close()

	testCases := []struct {
		name        string
		set         *jose.JSONWebKeySet
		ignoreCache bool
		expectKeyID string
		missingKey  string
	}{
		{
			name: "ShouldFetchAndReturnFooKey",
			set: &jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{
					{
						KeyID: "foo",
						Use:   "sig",
						Key:   &gen.MustRSAKey().PublicKey,
					},
				},
			},
			ignoreCache: false,
			expectKeyID: "foo",
		},
		{
			name: "ShouldReturnCachedFooKeyWhenRemoteChanges",
			set: &jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{
					{
						KeyID: "bar",
						Use:   "sig",
						Key:   &gen.MustRSAKey().PublicKey,
					},
				},
			},
			ignoreCache: false,
			expectKeyID: "foo",
			missingKey:  "bar",
		},
		{
			name: "ShouldBypassCacheWithIgnoreCache",
			set: &jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{
					{
						KeyID: "bar",
						Use:   "sig",
						Key:   &gen.MustRSAKey().PublicKey,
					},
				},
			},
			ignoreCache: true,
			expectKeyID: "bar",
			missingKey:  "foo",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			set = tc.set

			actual, err := s.Resolve(ctx, ts.URL, tc.ignoreCache)
			require.NoError(t, ErrorToDebugRFC6749Error(err))

			assert.Len(t, actual.Key(tc.expectKeyID), 1)
			if tc.missingKey != "" {
				assert.Len(t, actual.Key(tc.missingKey), 0)
			}
		})
	}
}

func TestDefaultJWKSFetcherStrategyOptions(t *testing.T) {
	testCases := []struct {
		name  string
		check func(t *testing.T)
	}{
		{
			name: "ShouldUseProvidedCache",
			check: func(t *testing.T) {
				ts := initServerWithKey(t)

				cache, _ := ristretto.NewCache(&ristretto.Config{NumCounters: 10 * 1000, MaxCost: 1000, BufferItems: 64})
				expected := &jose.JSONWebKeySet{}
				require.True(t, cache.Set(defaultJWKSFetcherStrategyCachePrefix+ts.URL, expected, 1))
				cache.Wait()

				s := NewDefaultJWKSFetcherStrategy(JWKSFetcherWithCache(cache))

				actual, err := s.Resolve(context.Background(), ts.URL, false)
				require.NoError(t, ErrorToDebugRFC6749Error(err))
				assert.Equal(t, expected, actual)
			},
		},
		{
			name: "ShouldExpireCacheUsingProvidedTTL",
			check: func(t *testing.T) {
				ts := initServerWithKey(t)

				s := NewDefaultJWKSFetcherStrategy(JKWKSFetcherWithDefaultTTL(time.Nanosecond))

				_, err := s.Resolve(context.Background(), ts.URL, false)
				require.NoError(t, ErrorToDebugRFC6749Error(err))

				s.(*DefaultJWKSFetcherStrategy).cache.Wait()

				_, ok := s.(*DefaultJWKSFetcherStrategy).cache.Get(defaultJWKSFetcherStrategyCachePrefix + ts.URL)
				assert.False(t, ok, "expected cache to be empty")
			},
		},
		{
			name: "ShouldUseProvidedHTTPClient",
			check: func(t *testing.T) {
				rt := retryablehttp.NewClient()
				rt.RetryMax = 0
				rt.HTTPClient = &http.Client{Transport: new(failingTripper)}

				s := NewDefaultJWKSFetcherStrategy(JWKSFetcherWithHTTPClient(rt))

				_, err := s.Resolve(context.Background(), "https://google.com", false)
				require.ErrorIs(t, err, errRoundTrip)
			},
		},
		{
			name: "ShouldPreferHTTPClientSourceOverHTTPClient",
			check: func(t *testing.T) {
				rt := retryablehttp.NewClient()
				rt.RetryMax = 0
				rt.HTTPClient = &http.Client{Transport: new(failingTripper)}

				s := NewDefaultJWKSFetcherStrategy(
					JWKSFetcherWithHTTPClient(retryablehttp.NewClient()),
					JWKSFetcherWithHTTPClientSource(func(ctx context.Context) *retryablehttp.Client {
						return rt
					}),
				)

				_, err := s.Resolve(context.Background(), "https://www.google.com", false)
				require.ErrorIs(t, err, errRoundTrip)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, tc.check)
	}
}

func TestDefaultJWKSFetcherStrategyResolveErrors(t *testing.T) {
	testCases := []struct {
		name     string
		setup    func(t *testing.T) (location string)
		expected string
	}{
		{
			name: "ShouldFailWhenServerReturnsNon2xxStatus",
			setup: func(t *testing.T) string {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusBadRequest)
				}))
				t.Cleanup(ts.Close)
				return ts.URL
			},
			expected: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
		},
		{
			name: "ShouldFailWhenLocationIsInvalidURL",
			setup: func(t *testing.T) string {
				return "$%/19"
			},
			expected: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
		},
		{
			name: "ShouldFailWhenResponseBodyIsNotValidJWKS",
			setup: func(t *testing.T) string {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = w.Write([]byte("[]"))
				}))
				t.Cleanup(ts.Close)
				return ts.URL
			},
			expected: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewDefaultJWKSFetcherStrategy()
			location := tc.setup(t)

			actual, err := s.Resolve(context.Background(), location, true)
			require.Error(t, err)
			assert.Nil(t, actual)
			assert.Contains(t, ErrorToDebugRFC6749Error(err).Error(), tc.expected)
		})
	}
}

func TestDefaultJWKSFetcherStrategyWaitForCache(t *testing.T) {
	testCases := []struct {
		name string
	}{
		{
			name: "ShouldReturnAfterCacheDrains",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewDefaultJWKSFetcherStrategy().(*DefaultJWKSFetcherStrategy)
			assert.NotPanics(t, func() {
				s.WaitForCache()
			})
		})
	}
}
