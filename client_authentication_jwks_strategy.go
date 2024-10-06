// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/go-jose/go-jose/v4"
	"github.com/hashicorp/go-retryablehttp"

	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

const defaultJWKSFetcherStrategyCachePrefix = "authelia.com/provider/oauth2.DefaultJWKSFetcherStrategy:"

// DefaultJWKSFetcherStrategy is a default implementation of the jwt.JWKSFetcherStrategy interface.
type DefaultJWKSFetcherStrategy struct {
	client           *retryablehttp.Client
	cache            *ristretto.Cache
	ttl              time.Duration
	clientSourceFunc func(ctx context.Context) *retryablehttp.Client
}

// NewDefaultJWKSFetcherStrategy returns a new instance of the DefaultJWKSFetcherStrategy.
func NewDefaultJWKSFetcherStrategy(opts ...func(*DefaultJWKSFetcherStrategy)) jwt.JWKSFetcherStrategy {
	dc, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 10000 * 10,
		MaxCost:     10000,
		BufferItems: 64,
		Metrics:     false,
		Cost: func(value any) int64 {
			return 1
		},
	})
	if err != nil {
		panic(err)
	}

	s := &DefaultJWKSFetcherStrategy{
		cache:  dc,
		client: retryablehttp.NewClient(),
		ttl:    time.Hour,
	}

	for _, o := range opts {
		o(s)
	}

	return s
}

// JKWKSFetcherWithDefaultTTL sets the default TTL for the cache.
func JKWKSFetcherWithDefaultTTL(ttl time.Duration) func(*DefaultJWKSFetcherStrategy) {
	return func(s *DefaultJWKSFetcherStrategy) {
		s.ttl = ttl
	}
}

// JWKSFetcherWithCache sets the cache to use.
func JWKSFetcherWithCache(cache *ristretto.Cache) func(*DefaultJWKSFetcherStrategy) {
	return func(s *DefaultJWKSFetcherStrategy) {
		s.cache = cache
	}
}

// JWKSFetcherWithHTTPClient sets the HTTP client to use.
func JWKSFetcherWithHTTPClient(client *retryablehttp.Client) func(*DefaultJWKSFetcherStrategy) {
	return func(s *DefaultJWKSFetcherStrategy) {
		s.client = client
	}
}

// JWKSFetcherWithHTTPClientSource sets the HTTP client source function to use.
func JWKSFetcherWithHTTPClientSource(clientSourceFunc func(ctx context.Context) *retryablehttp.Client) func(*DefaultJWKSFetcherStrategy) {
	return func(s *DefaultJWKSFetcherStrategy) {
		s.clientSourceFunc = clientSourceFunc
	}
}

// Resolve returns the JSON Web Key Set, or an error if something went wrong. The forceRefresh, if true, forces
// the strategy to fetch the key from the remote. If forceRefresh is false, the strategy may use a caching strategy
// to fetch the key.
func (s *DefaultJWKSFetcherStrategy) Resolve(ctx context.Context, location string, ignoreCache bool) (*jose.JSONWebKeySet, error) {
	cacheKey := defaultJWKSFetcherStrategyCachePrefix + location
	key, ok := s.cache.Get(cacheKey)
	if !ok || ignoreCache {
		req, err := retryablehttp.NewRequest(http.MethodGet, location, nil)
		if err != nil {
			return nil, errorsx.WithStack(ErrServerError.WithHintf("Unable to create HTTP 'GET' request to fetch JSON Web Keys from location '%s'.", location).WithWrap(err).WithDebugError(err))
		}

		hc := s.client
		if s.clientSourceFunc != nil {
			hc = s.clientSourceFunc(ctx)
		}

		response, err := hc.Do(req.WithContext(ctx))
		if err != nil {
			return nil, errorsx.WithStack(ErrServerError.WithHintf("Unable to fetch JSON Web Keys from location '%s'. Check for typos or other network issues.", location).WithWrap(err).WithDebugError(err))
		}
		defer response.Body.Close()

		if response.StatusCode < 200 || response.StatusCode >= 400 {
			return nil, errorsx.WithStack(ErrServerError.WithHintf("Expected successful status code in range of 200 - 399 from location '%s' but received code %d.", location, response.StatusCode))
		}

		var set jose.JSONWebKeySet

		if err = json.NewDecoder(response.Body).Decode(&set); err != nil {
			return nil, errorsx.WithStack(ErrServerError.WithHintf("Unable to decode JSON Web Keys from location '%s'. Please check for typos and if the URL returns valid JSON.", location).WithWrap(err).WithDebugError(err))
		}

		_ = s.cache.SetWithTTL(cacheKey, &set, 1, s.ttl)
		return &set, nil
	}

	return key.(*jose.JSONWebKeySet), nil
}

func (s *DefaultJWKSFetcherStrategy) WaitForCache() {
	s.cache.Wait()
}
