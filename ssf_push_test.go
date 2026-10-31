// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/stretchr/testify/assert"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/storage"
)

const ssfPushSecret = "Bearer super-secret-value"

var ssfPushClient = &oauth2.DefaultClient{ID: "a"}

func TestPushSecurityEventToken(t *testing.T) {
	testCases := []struct {
		name        string
		handler     func(w http.ResponseWriter, r *http.Request)
		auth        string
		outcome     oauth2.SSFPushOutcome
		status      int
		code        string
		description string
		retryAfter  time.Duration
		err         bool
	}{
		{
			name:    "ShouldDeliverOn202",
			handler: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusAccepted) },
			outcome: oauth2.SSFPushDelivered,
			status:  http.StatusAccepted,
		},
		{
			name:    "ShouldDeliverOn202WithoutAuthorization",
			handler: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusAccepted) },
			outcome: oauth2.SSFPushDelivered,
			status:  http.StatusAccepted,
		},
		{
			name: "ShouldRejectOn400WithErrorCode",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"err":"invalid_key","description":"x"}`))
			},
			outcome:     oauth2.SSFPushRejected,
			status:      http.StatusBadRequest,
			code:        "invalid_key",
			description: "x",
			err:         true,
		},
		{
			name: "ShouldRejectOn400WithNonJSONBody",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`<html>bad</html>`))
			},
			outcome: oauth2.SSFPushRejected,
			status:  http.StatusBadRequest,
			err:     true,
		},
		{
			name: "ShouldNotFailOnOversizedBody",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusAccepted)
				_, _ = w.Write([]byte(strings.Repeat("a", 1<<20)))
			},
			outcome: oauth2.SSFPushDelivered,
			status:  http.StatusAccepted,
		},
		{
			name:    "ShouldRejectOtherSuccessStatus",
			handler: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) },
			outcome: oauth2.SSFPushRejected,
			status:  http.StatusOK,
			err:     true,
		},
		{
			name:    "ShouldRetryOn503",
			handler: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) },
			outcome: oauth2.SSFPushRetryable,
			status:  http.StatusServiceUnavailable,
			err:     true,
		},
		{
			name:    "ShouldRetryOn500",
			handler: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) },
			outcome: oauth2.SSFPushRetryable,
			status:  http.StatusInternalServerError,
			err:     true,
		},
		{
			name: "ShouldRetryOn429WithRetryAfter",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Retry-After", "30")
				w.WriteHeader(http.StatusTooManyRequests)
			},
			outcome:    oauth2.SSFPushRetryable,
			status:     http.StatusTooManyRequests,
			retryAfter: 30 * time.Second,
			err:        true,
		},
		{
			name: "ShouldCapRetryAfter",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Retry-After", "99999999")
				w.WriteHeader(http.StatusServiceUnavailable)
			},
			outcome:    oauth2.SSFPushRetryable,
			status:     http.StatusServiceUnavailable,
			retryAfter: 5 * time.Minute,
			err:        true,
		},
		{
			name: "ShouldIgnoreInvalidRetryAfter",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Retry-After", "soon")
				w.WriteHeader(http.StatusServiceUnavailable)
			},
			outcome: oauth2.SSFPushRetryable,
			status:  http.StatusServiceUnavailable,
			err:     true,
		},
		{
			name:    "ShouldRejectOn401",
			handler: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) },
			outcome: oauth2.SSFPushRejected,
			status:  http.StatusUnauthorized,
			err:     true,
		},
		{
			name:    "ShouldRejectOn403",
			handler: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) },
			outcome: oauth2.SSFPushRejected,
			status:  http.StatusForbidden,
			err:     true,
		},
		{
			name:    "ShouldRejectOn404",
			handler: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) },
			outcome: oauth2.SSFPushRejected,
			status:  http.StatusNotFound,
			err:     true,
		},
	}

	for _, tc := range testCases {
		// Every row runs with the secret unless it is the row without authorization.
		if tc.name != "ShouldDeliverOn202WithoutAuthorization" {
			tc.auth = ssfPushSecret
		}

		t.Run(tc.name, func(t *testing.T) {
			var hits int32

			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&hits, 1)

				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "application/secevent+jwt", r.Header.Get("Content-Type"))
				assert.Equal(t, "application/json", r.Header.Get("Accept"))

				if tc.auth == "" {
					_, present := r.Header["Authorization"]
					assert.False(t, present)
				} else {
					assert.Equal(t, tc.auth, r.Header.Get("Authorization"))
				}

				body, _ := io.ReadAll(r.Body)
				assert.Equal(t, "the.set.token", string(body))

				tc.handler(w, r)
			}))

			defer server.Close()

			provider := newSSFPushProvider(server)

			result := provider.PushSecurityEventToken(context.Background(), ssfPushClient, oauth2.SSFDelivery{Method: "urn:ietf:rfc:8935", EndpointURL: server.URL, AuthorizationHeader: tc.auth}, "the.set.token")

			assert.Equal(t, tc.outcome, result.Outcome)
			assert.Equal(t, tc.status, result.Status)
			assert.Equal(t, tc.code, result.ErrorCode)
			assert.Equal(t, tc.description, result.Description)
			assert.Equal(t, tc.retryAfter, result.RetryAfter)
			assert.Equal(t, int32(1), atomic.LoadInt32(&hits))

			if tc.err {
				assert.Error(t, result.Err)
			} else {
				assert.NoError(t, result.Err)
			}

			assert.NotContains(t, fmt.Sprintf("%+v %#v %v %s", result, result, result, result.Err), "super-secret-value")
		})
	}
}

func TestPushSecurityEventTokenShouldNotFollowRedirect(t *testing.T) {
	var targetHits int32

	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&targetHits, 1)
	}))

	defer target.Close()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))

	defer server.Close()

	result := newSSFPushProvider(server).PushSecurityEventToken(context.Background(), ssfPushClient, oauth2.SSFDelivery{EndpointURL: server.URL, AuthorizationHeader: ssfPushSecret}, "t")

	assert.Equal(t, oauth2.SSFPushRejected, result.Outcome)
	assert.Equal(t, http.StatusFound, result.Status)
	assert.Error(t, result.Err)
	assert.Zero(t, atomic.LoadInt32(&targetHits))
}

func TestPushSecurityEventTokenShouldRetryOnNetworkError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := server.URL
	provider := newSSFPushProvider(server)

	server.Close()

	result := provider.PushSecurityEventToken(context.Background(), ssfPushClient, oauth2.SSFDelivery{EndpointURL: url, AuthorizationHeader: ssfPushSecret}, "t")

	assert.Equal(t, oauth2.SSFPushRetryable, result.Outcome)
	assert.Zero(t, result.Status)
	assert.Error(t, result.Err)
	assert.NotContains(t, fmt.Sprintf("%+v", result), "super-secret-value")
	assert.NotContains(t, result.Err.Error(), "super-secret-value")
}

func TestPushSecurityEventTokenShouldMakeOneRequestWithRetriesConfigured(t *testing.T) {
	var hits int32

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)

		w.WriteHeader(http.StatusServiceUnavailable)
	}))

	defer server.Close()

	provider := newSSFPushProvider(server)

	client := provider.Config.GetHTTPClient(context.Background())
	client.RetryMax = 5
	client.RetryWaitMin = time.Millisecond
	client.RetryWaitMax = time.Millisecond
	client.CheckRetry = func(ctx context.Context, resp *http.Response, err error) (bool, error) { return true, nil }

	result := provider.PushSecurityEventToken(context.Background(), ssfPushClient, oauth2.SSFDelivery{EndpointURL: server.URL}, "t")

	assert.Equal(t, oauth2.SSFPushRetryable, result.Outcome)
	assert.Equal(t, int32(1), atomic.LoadInt32(&hits))
	assert.Equal(t, 5, client.RetryMax)
}

func TestPushSecurityEventTokenShouldRefuseInvalidDelivery(t *testing.T) {
	var hits int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))

	defer server.Close()

	provider := newSSFPushProvider(nil)

	testCases := []struct {
		name     string
		delivery oauth2.SSFDelivery
	}{
		{"ShouldRefuseHTTP", oauth2.SSFDelivery{EndpointURL: server.URL, AuthorizationHeader: ssfPushSecret}},
		{"ShouldRefuseEmptyURL", oauth2.SSFDelivery{}},
		{"ShouldRefuseUnparseableURL", oauth2.SSFDelivery{EndpointURL: "https://[::1"}},
		{"ShouldRefuseNoHost", oauth2.SSFDelivery{EndpointURL: "https:///path"}},
		{"ShouldRefusePollMethod", oauth2.SSFDelivery{Method: "urn:ietf:rfc:8936", EndpointURL: "https://example.com/push"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := provider.PushSecurityEventToken(context.Background(), ssfPushClient, tc.delivery, "t")

			assert.Equal(t, oauth2.SSFPushRejected, result.Outcome)
			assert.Zero(t, result.Status)
			assert.Error(t, result.Err)
			assert.NotContains(t, result.Err.Error(), "super-secret-value")
		})
	}

	assert.Zero(t, atomic.LoadInt32(&hits))
}

func TestPushSecurityEventTokenShouldEnforceEndpointValidator(t *testing.T) {
	testCases := []struct {
		name   string
		client oauth2.Client
		mutate func(config *oauth2.Config)
	}{
		{"ShouldRefuseValidatorError", ssfPushClient, func(config *oauth2.Config) {
			config.SSF.EndpointValidator = ssfHandlerValidator{err: errors.New("private address")}
		}},
		{"ShouldRefuseMissingValidator", ssfPushClient, func(config *oauth2.Config) { config.SSF.EndpointValidator = nil }},
		{"ShouldRefuseMissingConfig", ssfPushClient, func(config *oauth2.Config) { config.SSF = nil }},
		{"ShouldRefuseMissingClient", nil, func(config *oauth2.Config) {}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var hits int32

			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&hits, 1)
				w.WriteHeader(http.StatusAccepted)
			}))
			defer server.Close()

			provider := newSSFPushProvider(server)

			tc.mutate(provider.Config.(*oauth2.Config))

			result := provider.PushSecurityEventToken(context.Background(), tc.client, oauth2.SSFDelivery{EndpointURL: server.URL, AuthorizationHeader: ssfPushSecret}, "t")

			assert.Equal(t, oauth2.SSFPushRejected, result.Outcome)
			assert.Error(t, result.Err)
			assert.Zero(t, atomic.LoadInt32(&hits))
		})
	}
}

func TestPushSecurityEventTokenShouldNotCallLogHooks(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusAccepted) }))
	defer server.Close()

	var requests, responses int32

	provider := newSSFPushProvider(server)
	base := provider.Config.(*oauth2.Config).HTTPClient

	base.RequestLogHook = func(retryablehttp.Logger, *http.Request, int) { atomic.AddInt32(&requests, 1) }
	base.ResponseLogHook = func(retryablehttp.Logger, *http.Response) { atomic.AddInt32(&responses, 1) }

	result := provider.PushSecurityEventToken(context.Background(), ssfPushClient, oauth2.SSFDelivery{EndpointURL: server.URL, AuthorizationHeader: ssfPushSecret}, "t")

	assert.Equal(t, oauth2.SSFPushDelivered, result.Outcome)
	assert.Zero(t, atomic.LoadInt32(&requests))
	assert.Zero(t, atomic.LoadInt32(&responses))
	assert.NotNil(t, base.RequestLogHook, "the configured client must not be modified")
}

func TestPushSecurityEventTokenShouldIgnoreConfiguredCheckRetry(t *testing.T) {
	testCases := []struct {
		name    string
		check   retryablehttp.CheckRetry
		status  int
		outcome oauth2.SSFPushOutcome
		hits    int32
	}{
		{
			name:    "ShouldKeepStatusWhenCheckRetryErrors",
			check:   func(context.Context, *http.Response, error) (bool, error) { return false, errors.New("check failed") },
			status:  http.StatusServiceUnavailable,
			outcome: oauth2.SSFPushRetryable,
			hits:    1,
		},
		{
			name:    "ShouldClassifyRejectionWhenCheckRetryErrors",
			check:   func(context.Context, *http.Response, error) (bool, error) { return false, errors.New("check failed") },
			status:  http.StatusBadRequest,
			outcome: oauth2.SSFPushRejected,
			hits:    1,
		},
		{
			name:    "ShouldNotRetryWhenCheckRetryAsks",
			check:   func(context.Context, *http.Response, error) (bool, error) { return true, nil },
			status:  http.StatusServiceUnavailable,
			outcome: oauth2.SSFPushRetryable,
			hits:    1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var hits int32

			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&hits, 1)
				w.WriteHeader(tc.status)
			}))
			defer server.Close()

			provider := newSSFPushProvider(server)

			provider.Config.(*oauth2.Config).HTTPClient.CheckRetry = tc.check
			provider.Config.(*oauth2.Config).HTTPClient.RetryMax = 3

			result := provider.PushSecurityEventToken(context.Background(), ssfPushClient, oauth2.SSFDelivery{EndpointURL: server.URL}, "t")

			assert.Equal(t, tc.status, result.Status)
			assert.Equal(t, tc.outcome, result.Outcome)
			assert.Error(t, result.Err)
			assert.NotContains(t, result.Err.Error(), "check failed")
			assert.Equal(t, tc.hits, atomic.LoadInt32(&hits))
		})
	}
}

func TestSSFDeliveryShouldRedactAuthorizationHeader(t *testing.T) {
	delivery := oauth2.SSFDelivery{Method: "urn:ietf:rfc:8935", EndpointURL: "https://example.com/push", AuthorizationHeader: ssfPushSecret}

	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		assert.NotContains(t, fmt.Sprintf(format, delivery), "super-secret-value", format)
		assert.NotContains(t, fmt.Sprintf(format, &delivery), "super-secret-value", format)
	}

	assert.Contains(t, fmt.Sprintf("%+v", delivery), "https://example.com/push")
}

func newSSFPushProvider(server *httptest.Server) *oauth2.Fosite {
	config := &oauth2.Config{SSF: &oauth2.SSFConfig{Issuer: "https://ssf.example.com", EndpointValidator: ssfHandlerValidator{}}}

	client := retryablehttp.NewClient()
	client.Logger = nil
	client.RetryWaitMin = time.Millisecond
	client.RetryWaitMax = time.Millisecond

	if server != nil {
		client.HTTPClient = server.Client()
	}

	config.HTTPClient = client

	return &oauth2.Fosite{Store: storage.NewMemoryStore(), Config: config}
}
