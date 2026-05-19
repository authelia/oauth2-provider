// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/go-jose/go-jose/v4"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/token/jwt"
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
	fooKeySet := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{
			KeyID: "foo",
			Use:   "sig",
			Key:   &gen.MustRSAKey().PublicKey,
		}},
	}
	barKeySet := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{
			KeyID: "bar",
			Use:   "sig",
			Key:   &gen.MustRSAKey().PublicKey,
		}},
	}

	testCases := []struct {
		name  string
		check func(t *testing.T, s jwt.JWKSFetcherStrategy, ts *httptest.Server, served *atomic.Pointer[jose.JSONWebKeySet])
	}{
		{
			name: "ShouldFetchAndReturnFooKey",
			check: func(t *testing.T, s jwt.JWKSFetcherStrategy, ts *httptest.Server, served *atomic.Pointer[jose.JSONWebKeySet]) {
				served.Store(fooKeySet)

				actual, err := s.Resolve(context.Background(), ts.URL, false)
				require.NoError(t, ErrorToDebugRFC6749Error(err))

				assert.Len(t, actual.Key("foo"), 1)
			},
		},
		{
			name: "ShouldReturnCachedKeySetWhenRemoteChanges",
			check: func(t *testing.T, s jwt.JWKSFetcherStrategy, ts *httptest.Server, served *atomic.Pointer[jose.JSONWebKeySet]) {
				// Seed the cache with the foo key set.
				served.Store(fooKeySet)
				_, err := s.Resolve(context.Background(), ts.URL, false)
				require.NoError(t, ErrorToDebugRFC6749Error(err))
				s.(*DefaultJWKSFetcherStrategy).WaitForCache()

				// Change the remote, then re-resolve without forcing a refresh.
				served.Store(barKeySet)
				actual, err := s.Resolve(context.Background(), ts.URL, false)
				require.NoError(t, ErrorToDebugRFC6749Error(err))

				assert.Len(t, actual.Key("foo"), 1)
				assert.Len(t, actual.Key("bar"), 0)
			},
		},
		{
			name: "ShouldBypassCacheWithIgnoreCache",
			check: func(t *testing.T, s jwt.JWKSFetcherStrategy, ts *httptest.Server, served *atomic.Pointer[jose.JSONWebKeySet]) {
				// Seed the cache with the foo key set.
				served.Store(fooKeySet)
				_, err := s.Resolve(context.Background(), ts.URL, false)
				require.NoError(t, ErrorToDebugRFC6749Error(err))

				// Change the remote and force a refresh.
				served.Store(barKeySet)
				actual, err := s.Resolve(context.Background(), ts.URL, true)
				require.NoError(t, ErrorToDebugRFC6749Error(err))

				assert.Len(t, actual.Key("bar"), 1)
				assert.Len(t, actual.Key("foo"), 0)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			served := &atomic.Pointer[jose.JSONWebKeySet]{}
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.NoError(t, json.NewEncoder(w).Encode(served.Load()))
			}))
			t.Cleanup(ts.Close)

			s := NewDefaultJWKSFetcherStrategy()
			tc.check(t, s, ts, served)
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
