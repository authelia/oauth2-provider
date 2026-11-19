// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/token/jwt"
)

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
				served.Store(fooKeySet)

				_, err := s.Resolve(context.Background(), ts.URL, false)
				require.NoError(t, ErrorToDebugRFC6749Error(err))
				s.(*DefaultJWKSFetcherStrategy).WaitForCache()

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
				served.Store(fooKeySet)

				_, err := s.Resolve(context.Background(), ts.URL, false)
				require.NoError(t, ErrorToDebugRFC6749Error(err))

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

func TestDefaultJWKSFetcherStrategyRefreshInterval(t *testing.T) {
	testCases := []struct {
		name     string
		opts     []func(*DefaultJWKSFetcherStrategy)
		wait     time.Duration
		expected int64
	}{
		{
			name:     "ShouldRefreshOnceWithinTheInterval",
			expected: 2,
		},
		{
			name:     "ShouldRefreshAgainAfterTheInterval",
			opts:     []func(*DefaultJWKSFetcherStrategy){JWKSFetcherWithRefreshInterval(50 * time.Millisecond)},
			wait:     100 * time.Millisecond,
			expected: 3,
		},
		{
			name:     "ShouldRefreshEveryTimeWithoutAnInterval",
			opts:     []func(*DefaultJWKSFetcherStrategy){JWKSFetcherWithRefreshInterval(0)},
			expected: 3,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var fetches atomic.Int64

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fetches.Add(1)

				require.NoError(t, json.NewEncoder(w).Encode(&jose.JSONWebKeySet{}))
			}))
			t.Cleanup(ts.Close)

			s := NewDefaultJWKSFetcherStrategy(tc.opts...)

			_, err := s.Resolve(context.Background(), ts.URL, false)
			require.NoError(t, ErrorToDebugRFC6749Error(err))
			s.(*DefaultJWKSFetcherStrategy).WaitForCache()

			_, err = s.Resolve(context.Background(), ts.URL, true)
			require.NoError(t, ErrorToDebugRFC6749Error(err))
			s.(*DefaultJWKSFetcherStrategy).WaitForCache()

			time.Sleep(tc.wait)

			_, err = s.Resolve(context.Background(), ts.URL, true)
			require.NoError(t, ErrorToDebugRFC6749Error(err))

			assert.Equal(t, tc.expected, fetches.Load())
		})
	}
}

func TestDefaultJWKSFetcherStrategyCoalescing(t *testing.T) {
	setA := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{KeyID: "a", Key: &gen.MustES256Key().PublicKey}}}
	setB := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{KeyID: "b", Key: &gen.MustES256Key().PublicKey}}}

	type server struct {
		*httptest.Server

		fetches  atomic.Int64
		received chan struct{}
		release  chan struct{}
		set      atomic.Pointer[jose.JSONWebKeySet]
		status   atomic.Int64
	}

	newServer := func(t *testing.T) *server {
		srv := &server{received: make(chan struct{}, 16), release: make(chan struct{})}

		srv.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			srv.fetches.Add(1)

			srv.received <- struct{}{}

			<-srv.release

			if status := srv.status.Load(); status != 0 {
				w.WriteHeader(int(status))

				return
			}

			assert.NoError(t, json.NewEncoder(w).Encode(srv.set.Load()))
		}))

		t.Cleanup(srv.Close)

		return srv
	}

	resolve := func(s jwt.JWKSFetcherStrategy, ctx context.Context, location string, force bool) <-chan any {
		result := make(chan any, 1)

		go func() {
			set, err := s.Resolve(ctx, location, force)
			if err != nil {
				result <- err
			} else {
				result <- set
			}
		}()

		return result
	}

	kid := func(result any) string {
		if set, ok := result.(*jose.JSONWebKeySet); ok && len(set.Keys) == 1 {
			return set.Keys[0].KeyID
		}

		return fmt.Sprint(result)
	}

	t.Run("ShouldFetchOnceForConcurrentMisses", func(t *testing.T) {
		srv := newServer(t)
		srv.set.Store(setA)

		s := NewDefaultJWKSFetcherStrategy()

		first := resolve(s, context.Background(), srv.URL, false)

		<-srv.received

		results := make([]<-chan any, 0, 5)
		results = append(results, first)

		for range 4 {
			results = append(results, resolve(s, context.Background(), srv.URL, false))
		}

		time.Sleep(50 * time.Millisecond)
		close(srv.release)

		for _, result := range results {
			assert.Equal(t, "a", kid(<-result))
		}

		assert.Equal(t, int64(1), srv.fetches.Load())
	})

	t.Run("ShouldWaitForTheRefreshInFlight", func(t *testing.T) {
		srv := newServer(t)
		srv.set.Store(setA)

		s := NewDefaultJWKSFetcherStrategy()

		prime := resolve(s, context.Background(), srv.URL, false)

		<-srv.received

		srv.release <- struct{}{}

		assert.Equal(t, "a", kid(<-prime))

		srv.set.Store(setB)

		// The second forced refresh is inside the refresh interval, and waits for the first in place of the cache.
		first := resolve(s, context.Background(), srv.URL, true)

		<-srv.received

		second := resolve(s, context.Background(), srv.URL, true)

		time.Sleep(50 * time.Millisecond)
		close(srv.release)

		assert.Equal(t, "b", kid(<-first))
		assert.Equal(t, "b", kid(<-second))
		assert.Equal(t, int64(2), srv.fetches.Load())
	})

	t.Run("ShouldReportTheRefreshInFlightAsFetched", func(t *testing.T) {
		srv := newServer(t)
		srv.set.Store(setA)

		s := NewDefaultJWKSFetcherStrategy().(*DefaultJWKSFetcherStrategy)

		prime := resolve(s, context.Background(), srv.URL, false)

		<-srv.received

		srv.release <- struct{}{}

		assert.Equal(t, "a", kid(<-prime))

		srv.set.Store(setB)

		first := resolve(s, context.Background(), srv.URL, true)

		<-srv.received

		type refreshed struct {
			set     *jose.JSONWebKeySet
			fetched bool
		}

		second := make(chan refreshed, 1)

		go func() {
			set, fetched, _ := s.Refresh(context.Background(), srv.URL)

			second <- refreshed{set, fetched}
		}()

		time.Sleep(50 * time.Millisecond)
		close(srv.release)

		assert.Equal(t, "b", kid(<-first))

		result := <-second

		assert.Equal(t, "b", kid(result.set))
		assert.True(t, result.fetched)
	})

	t.Run("ShouldReturnTheFailureOfTheRefreshInFlight", func(t *testing.T) {
		srv := newServer(t)
		srv.set.Store(setA)

		s := NewDefaultJWKSFetcherStrategy()

		prime := resolve(s, context.Background(), srv.URL, false)

		<-srv.received

		srv.release <- struct{}{}

		assert.Equal(t, "a", kid(<-prime))

		srv.status.Store(http.StatusNotFound)

		first := resolve(s, context.Background(), srv.URL, true)

		<-srv.received

		second := resolve(s, context.Background(), srv.URL, true)

		time.Sleep(50 * time.Millisecond)
		close(srv.release)

		for _, result := range []any{<-first, <-second} {
			err, _ := result.(error)

			assert.ErrorIs(t, err, ErrServerError)
		}

		// The cached set is kept, and the refresh interval still applies.
		set, err := s.Resolve(context.Background(), srv.URL, true)
		require.NoError(t, ErrorToDebugRFC6749Error(err))
		assert.Equal(t, "a", kid(set))
		assert.Equal(t, int64(2), srv.fetches.Load())
	})

	t.Run("ShouldFetchAgainWhenTheFetchEndedAtTheDeadlineOfAnotherLookup", func(t *testing.T) {
		srv := newServer(t)
		srv.set.Store(setA)

		s := NewDefaultJWKSFetcherStrategy()

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		first := resolve(s, ctx, srv.URL, false)

		<-srv.received

		second := resolve(s, context.Background(), srv.URL, false)

		err, _ := (<-first).(error)

		assert.ErrorIs(t, err, context.DeadlineExceeded)

		// The fetch of the first lookup ends at its deadline, and the second fetches again with its own.
		close(srv.release)

		assert.Equal(t, "a", kid(<-second))
		assert.Equal(t, int64(2), srv.fetches.Load())
	})

	t.Run("ShouldReturnAPanicOfTheFetch", func(t *testing.T) {
		s := NewDefaultJWKSFetcherStrategy(JWKSFetcherWithHTTPClientSource(func(context.Context) *retryablehttp.Client { return nil }))

		for range 2 {
			_, err := s.Resolve(context.Background(), "https://keys.example.com/jwks.json", false)

			assert.ErrorIs(t, err, ErrServerError)
		}
	})

	t.Run("ShouldNotEndTheFetchWithTheContextOfTheFirstLookup", func(t *testing.T) {
		srv := newServer(t)
		srv.set.Store(setA)

		s := NewDefaultJWKSFetcherStrategy()

		ctx, cancel := context.WithCancel(context.Background())

		first := resolve(s, ctx, srv.URL, false)

		<-srv.received

		second := resolve(s, context.Background(), srv.URL, false)

		cancel()

		err, _ := (<-first).(error)

		assert.ErrorIs(t, err, context.Canceled)

		close(srv.release)

		assert.Equal(t, "a", kid(<-second))
		assert.Equal(t, int64(1), srv.fetches.Load())
	})
}

func TestDefaultJWKSFetcherStrategyRefresh(t *testing.T) {
	var fetches atomic.Int64

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)

		assert.NoError(t, json.NewEncoder(w).Encode(&jose.JSONWebKeySet{}))
	}))
	t.Cleanup(ts.Close)

	strategy := NewDefaultJWKSFetcherStrategy().(*DefaultJWKSFetcherStrategy)

	testCases := []struct {
		name     string
		strategy jwt.JWKSRefreshStrategy
	}{
		{"ShouldReportTheFetch", strategy},
		{"ShouldReportTheFetchOfAGuardedLookup", &guardedJWKSFetcherStrategy{strategy: strategy, allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			before := fetches.Load()

			set, fetched, err := tc.strategy.Refresh(context.Background(), ts.URL)
			require.NoError(t, ErrorToDebugRFC6749Error(err))
			assert.NotNil(t, set)
			assert.True(t, fetched)

			strategy.WaitForCache()

			// The location was refreshed within the refresh interval, so the cached set is returned.
			set, fetched, err = tc.strategy.Refresh(context.Background(), ts.URL)
			require.NoError(t, ErrorToDebugRFC6749Error(err))
			assert.NotNil(t, set)
			assert.False(t, fetched)

			assert.Equal(t, before+1, fetches.Load())
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

				cache, _ := ristretto.NewCache(&ristretto.Config[string, *jose.JSONWebKeySet]{NumCounters: 10 * 1000, MaxCost: 1000, BufferItems: 64})
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

func TestDefaultJWKSFetcherStrategyHardening(t *testing.T) {
	t.Run("ShouldNotFollowRedirects", func(t *testing.T) {
		var reached atomic.Bool

		internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached.Store(true)

			require.NoError(t, json.NewEncoder(w).Encode(&jose.JSONWebKeySet{}))
		}))
		t.Cleanup(internal.Close)

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, internal.URL, http.StatusFound)
		}))
		t.Cleanup(ts.Close)

		_, err := NewDefaultJWKSFetcherStrategy().Resolve(context.Background(), ts.URL, true)

		require.Error(t, err)
		assert.False(t, reached.Load())
	})

	t.Run("ShouldBoundTheResponseBody", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			var b strings.Builder

			b.WriteString(`{"keys":[`)

			for i := 0; b.Len() < (2 << 20); i++ {
				if i != 0 {
					b.WriteString(",")
				}

				b.WriteString(`{"kty":"oct","k":"` + strings.Repeat("A", 4096) + `"}`)
			}

			b.WriteString(`]}`)

			_, _ = w.Write([]byte(b.String()))
		}))
		t.Cleanup(ts.Close)

		_, err := NewDefaultJWKSFetcherStrategy().Resolve(context.Background(), ts.URL, true)

		require.Error(t, err)
	})

	t.Run("ShouldNotDiscloseTheOriginStatusCode", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		}))
		t.Cleanup(ts.Close)

		_, err := NewDefaultJWKSFetcherStrategy().Resolve(context.Background(), ts.URL, true)

		require.Error(t, err)

		var rfc *RFC6749Error

		require.ErrorAs(t, err, &rfc)
		assert.NotContains(t, rfc.HintField, "418", "the origin's status code must not reach the caller through the hint")
	})
}

func initServerWithKey(t *testing.T) *httptest.Server {
	var (
		set *jose.JSONWebKeySet
		h   http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
			require.NoError(t, json.NewEncoder(w).Encode(set))
		}
	)

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

type failingTripper struct{}

func (r *failingTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errRoundTrip
}

var errRoundTrip = errors.New("roundtrip error")
