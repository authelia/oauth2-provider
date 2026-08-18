// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/hashicorp/go-retryablehttp"

	"authelia.com/provider/oauth2/token/jose"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

const (
	defaultJWKSFetcherStrategyCachePrefix       = "authelia.com/provider/oauth2.DefaultJWKSFetcherStrategy:"
	maxRemoteDocumentBytes                int64 = 1 << 20
)

// httpClientWithoutRedirects returns a shallow copy of client that refuses to follow redirects, leaving the redirect
// response itself to be surfaced and rejected by the caller's status check.
//
// A URI a client registered is validated for scheme and shape at registration time, but that check binds only the
// first hop: a registrant-controlled host behind a conformant 'https' URI can answer with a 302 to a loopback,
// link-local, or otherwise internal address, and the authorization server would follow it. Refusing redirects keeps
// the fetch pointed at the location the deployment actually validated.
//
// The copy is deliberate. The client belongs to the integrator and is shared with every other consumer of
// GetHTTPClient, so mutating its CheckRedirect in place would silently change their behaviour too.
func httpClientWithoutRedirects(client *retryablehttp.Client) (scoped *retryablehttp.Client) {
	refuseRedirect := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	inner := &http.Client{CheckRedirect: refuseRedirect}

	if client.HTTPClient != nil {
		innerCopy := *client.HTTPClient
		innerCopy.CheckRedirect = refuseRedirect
		inner = &innerCopy
	}

	scoped = &retryablehttp.Client{
		HTTPClient:      inner,
		RetryWaitMin:    client.RetryWaitMin,
		RetryWaitMax:    client.RetryWaitMax,
		RetryMax:        client.RetryMax,
		CheckRetry:      client.CheckRetry,
		Backoff:         client.Backoff,
		ErrorHandler:    client.ErrorHandler,
		RequestLogHook:  client.RequestLogHook,
		ResponseLogHook: client.ResponseLogHook,
	}

	// retryablehttp.Client.Do dereferences CheckRetry and Backoff without a nil guard, and only lazily initialises
	// HTTPClient, so a client assembled as a struct literal rather than by retryablehttp.NewClient would panic here.
	if scoped.CheckRetry == nil {
		scoped.CheckRetry = retryablehttp.DefaultRetryPolicy
	}

	if scoped.Backoff == nil {
		scoped.Backoff = retryablehttp.DefaultBackoff
	}

	return scoped
}

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

		response, err := httpClientWithoutRedirects(hc).Do(req.WithContext(ctx))
		if err != nil {
			return nil, errorsx.WithStack(ErrServerError.WithHintf("Unable to fetch JSON Web Keys from location '%s'. Check for typos or other network issues.", location).WithWrap(err).WithDebugError(err))
		}
		defer response.Body.Close()

		if response.StatusCode < 200 || response.StatusCode >= 400 {
			return nil, errorsx.WithStack(ErrServerError.WithHintf("Expected successful status code in range of 200 - 399 from location '%s' but received code %d.", location, response.StatusCode))
		}

		var set jose.JSONWebKeySet

		if err = json.NewDecoder(io.LimitReader(response.Body, maxRemoteDocumentBytes)).Decode(&set); err != nil {
			return nil, errorsx.WithStack(ErrServerError.WithHintf("Unable to decode JSON Web Keys from location '%s'. Please check for typos and if the URL returns valid JSON.", location).WithWrap(err).WithDebugError(err))
		}

		_ = s.cache.SetWithTTL(cacheKey, &set, 1, s.ttl)
		return &set, nil
	}

	return key.(*jose.JSONWebKeySet), nil
}

// WaitForCache blocks until the in-flight JWKS fetch (if any) has completed and the cache is consistent. It is intended
// for use in tests that need deterministic cache state before asserting behavior.
func (s *DefaultJWKSFetcherStrategy) WaitForCache() {
	s.cache.Wait()
}
