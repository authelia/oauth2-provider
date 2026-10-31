// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

const outboundLocation = "https://registrant.example.com/location"

func TestOutboundFetches(t *testing.T) {
	testCases := []struct {
		name  string
		fetch func(ctx context.Context, t *testing.T, client *retryablehttp.Client)
	}{
		{
			name: "ShouldBoundAJWKSFetch",
			fetch: func(ctx context.Context, _ *testing.T, client *retryablehttp.Client) {
				_, _ = NewDefaultJWKSFetcherStrategy(JWKSFetcherWithHTTPClient(client)).Resolve(ctx, outboundLocation, false)
			},
		},
		{
			name: "ShouldBoundARequestURIFetch",
			fetch: func(ctx context.Context, _ *testing.T, client *retryablehttp.Client) {
				store := storage.NewMemoryStore()
				store.Clients["foo"] = &DefaultJARClient{
					DefaultClient:           &DefaultClient{ID: "foo", RedirectURIs: []string{"https://example.com/cb"}, ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow}, Scopes: []string{consts.ScopeOpenID}},
					RequestURIs:             []string{outboundLocation},
					JSONWebKeysURI:          outboundLocation,
					RequestObjectSigningAlg: "RS256",
				}

				form := url.Values{
					consts.FormParameterClientID:     {"foo"},
					consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow},
					consts.FormParameterScope:        {consts.ScopeOpenID},
					consts.FormParameterRedirectURI:  {"https://example.com/cb"},
					consts.FormParameterState:        {"0123456789abcdef"},
					consts.FormParameterRequestURI:   {outboundLocation},
				}

				r := httptest.NewRequest(http.MethodGet, "https://auth.example.com/authorize?"+form.Encode(), nil).WithContext(ctx)

				provider := &Fosite{Store: store, Config: &Config{HTTPClient: client}}

				_, _ = provider.NewAuthorizeRequest(ctx, r)
			},
		},
		{
			name: "ShouldBoundABackChannelLogoutDelivery",
			fetch: func(ctx context.Context, t *testing.T, client *retryablehttp.Client) {
				provider, _ := newBCLProvider(t)
				provider.Config.(*Config).HTTPClient = client

				_, _ = provider.SendBackChannelLogout(ctx, NewBackChannelLogoutRequest("alice", "", []Client{bclClient("rp", outboundLocation, false)}))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("ShouldApplyTheFetchTimeout", func(t *testing.T) {
				transport := &outboundTransport{status: http.StatusOK}

				tc.fetch(context.Background(), t, newOutboundClient(transport))

				require.NotEmpty(t, transport.remaining)

				for _, remaining := range transport.remaining {
					assert.Positive(t, remaining)
					assert.LessOrEqual(t, remaining, FetchTimeout)
				}
			})

			t.Run("ShouldKeepAShorterCallerDeadline", func(t *testing.T) {
				transport := &outboundTransport{status: http.StatusOK}

				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()

				tc.fetch(ctx, t, newOutboundClient(transport))

				require.NotEmpty(t, transport.remaining)
				assert.LessOrEqual(t, transport.remaining[0], time.Second)
			})

			t.Run("ShouldNotWaitForAnUnboundedRetryAfter", func(t *testing.T) {
				transport := &outboundTransport{status: http.StatusServiceUnavailable, retryAfter: "86400"}

				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()

				start := time.Now()

				tc.fetch(ctx, t, newOutboundClient(transport))

				assert.Less(t, time.Since(start), 2*time.Second)
				assert.Len(t, transport.remaining, 2)
			})
		})
	}
}

func newOutboundClient(transport http.RoundTripper) *retryablehttp.Client {
	client := retryablehttp.NewClient()
	client.Logger = nil
	client.RetryMax = 1
	client.RetryWaitMin = time.Millisecond
	client.RetryWaitMax = 10 * time.Millisecond
	client.HTTPClient = &http.Client{Transport: transport}

	return client
}

type outboundTransport struct {
	status     int
	retryAfter string

	mu        sync.Mutex
	remaining []time.Duration
}

func (o *outboundTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	deadline, ok := r.Context().Deadline()

	o.mu.Lock()
	defer o.mu.Unlock()

	if ok {
		o.remaining = append(o.remaining, time.Until(deadline))
	} else {
		o.remaining = append(o.remaining, 0)
	}

	header := http.Header{}

	if o.retryAfter != "" {
		header.Set("Retry-After", o.retryAfter)
	}

	return &http.Response{StatusCode: o.status, Header: header, Body: io.NopCloser(strings.NewReader("{}")), Request: r}, nil
}

func TestHTTPClientWithoutRedirectsCapsTheRetryWait(t *testing.T) {
	response := &http.Response{StatusCode: http.StatusServiceUnavailable, Header: http.Header{"Retry-After": {"86400"}}}

	backoff := HTTPClientWithoutRedirects(retryablehttp.NewClient()).Backoff

	testCases := []struct {
		name     string
		maximum  time.Duration
		expected time.Duration
	}{
		{name: "ShouldCapAtAPositiveMaximum", maximum: 10 * time.Millisecond, expected: 10 * time.Millisecond},
		{name: "ShouldCapAtAZeroMaximum"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, backoff(time.Millisecond, tc.maximum, 0, response))
		})
	}

	t.Run("ShouldNotRaiseAShorterWait", func(t *testing.T) {
		assert.Equal(t, time.Millisecond, backoff(time.Millisecond, time.Second, 0, nil))
	})
}

func TestConfigGetHTTPClientSharesTheDefaultClient(t *testing.T) {
	config := &Config{}

	assert.Same(t, config.GetHTTPClient(context.Background()), config.GetHTTPClient(context.Background()))
}
