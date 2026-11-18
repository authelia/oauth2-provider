// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
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

const (
	ssfPushSecret = "Bearer super-secret-value"
	ssfPushToken  = "the.set.token"
)

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
			name: "ShouldKeepErrorCodeWhenDescriptionIsNotAString",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"err":"invalid_key","description":5}`))
			},
			outcome: oauth2.SSFPushRejected,
			status:  http.StatusBadRequest,
			code:    "invalid_key",
			err:     true,
		},
		{
			name: "ShouldKeepDescriptionWhenErrorCodeIsNotAString",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"err":["invalid_key"],"description":"x"}`))
			},
			outcome:     oauth2.SSFPushRejected,
			status:      http.StatusBadRequest,
			description: "x",
			err:         true,
		},
		{
			name: "ShouldRejectOn400WithNonObjectBody",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`["invalid_key"]`))
			},
			outcome: oauth2.SSFPushRejected,
			status:  http.StatusBadRequest,
			err:     true,
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
			name: "ShouldCapRetryAfterBeyondInt64",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Retry-After", "9223372036854775808")
				w.WriteHeader(http.StatusServiceUnavailable)
			},
			outcome:    oauth2.SSFPushRetryable,
			status:     http.StatusServiceUnavailable,
			retryAfter: 5 * time.Minute,
			err:        true,
		},
		{
			name: "ShouldIgnoreNegativeRetryAfter",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Retry-After", "-9223372036854775809")
				w.WriteHeader(http.StatusServiceUnavailable)
			},
			outcome: oauth2.SSFPushRetryable,
			status:  http.StatusServiceUnavailable,
			err:     true,
		},
		{
			name: "ShouldIgnoreSignedRetryAfter",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Retry-After", "+30")
				w.WriteHeader(http.StatusServiceUnavailable)
			},
			outcome: oauth2.SSFPushRetryable,
			status:  http.StatusServiceUnavailable,
			err:     true,
		},
		{
			name: "ShouldIgnoreSignedRetryAfterBeyondInt64",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Retry-After", "+9223372036854775808")
				w.WriteHeader(http.StatusServiceUnavailable)
			},
			outcome: oauth2.SSFPushRetryable,
			status:  http.StatusServiceUnavailable,
			err:     true,
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
		{
			name: "ShouldRetryOn408WithRetryAfter",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Retry-After", "7")
				w.WriteHeader(http.StatusRequestTimeout)
			},
			outcome:    oauth2.SSFPushRetryable,
			status:     http.StatusRequestTimeout,
			retryAfter: 7 * time.Second,
			err:        true,
		},
		{
			name:    "ShouldRetryOn425",
			handler: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTooEarly) },
			outcome: oauth2.SSFPushRetryable,
			status:  http.StatusTooEarly,
			err:     true,
		},
		{
			name:    "ShouldRetryOn502",
			handler: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadGateway) },
			outcome: oauth2.SSFPushRetryable,
			status:  http.StatusBadGateway,
			err:     true,
		},
		{
			name:    "ShouldRetryOn504",
			handler: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusGatewayTimeout) },
			outcome: oauth2.SSFPushRetryable,
			status:  http.StatusGatewayTimeout,
			err:     true,
		},
		{
			name: "ShouldRejectOn501",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Retry-After", "30")
				w.WriteHeader(http.StatusNotImplemented)
			},
			outcome: oauth2.SSFPushRejected,
			status:  http.StatusNotImplemented,
			err:     true,
		},
		{
			name:    "ShouldRejectOn505",
			handler: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusHTTPVersionNotSupported) },
			outcome: oauth2.SSFPushRejected,
			status:  http.StatusHTTPVersionNotSupported,
			err:     true,
		},
		{
			name:    "ShouldRejectOn511",
			handler: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNetworkAuthenticationRequired) },
			outcome: oauth2.SSFPushRejected,
			status:  http.StatusNetworkAuthenticationRequired,
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
				assert.Equal(t, ssfPushToken, string(body))

				tc.handler(w, r)
			}))

			defer server.Close()

			provider := newSSFPushProvider(server)

			result := provider.PushSecurityEventToken(context.Background(), ssfPushClient, oauth2.SSFDelivery{Method: "urn:ietf:rfc:8935", EndpointURL: server.URL, AuthorizationHeader: tc.auth}, ssfPushToken)

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

	result := newSSFPushProvider(server).PushSecurityEventToken(context.Background(), ssfPushClient, oauth2.SSFDelivery{EndpointURL: server.URL, AuthorizationHeader: ssfPushSecret}, ssfPushToken)

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

	result := provider.PushSecurityEventToken(context.Background(), ssfPushClient, oauth2.SSFDelivery{EndpointURL: url, AuthorizationHeader: ssfPushSecret}, ssfPushToken)

	assert.Equal(t, oauth2.SSFPushRetryable, result.Outcome)
	assert.Zero(t, result.Status)
	assert.Error(t, result.Err)
	assert.NotContains(t, fmt.Sprintf("%+v", result), "super-secret-value")
	assert.NotContains(t, result.Err.Error(), "super-secret-value")
}

func TestPushSecurityEventTokenShouldRejectUnrecoverableTransportFailure(t *testing.T) {
	testCases := []struct {
		name     string
		auth     string
		mutate   func(config *oauth2.Config, server *httptest.Server)
		expected error
	}{
		{
			name: "ShouldRejectUntrustedCertificate",
			auth: ssfPushSecret,
			mutate: func(config *oauth2.Config, server *httptest.Server) {
				config.HTTPClient.HTTPClient = &http.Client{Transport: &http.Transport{}}
			},
		},
		{
			name: "ShouldRejectCertificateForAnotherHost",
			auth: ssfPushSecret,
			mutate: func(config *oauth2.Config, server *httptest.Server) {
				transport := server.Client().Transport.(*http.Transport).Clone()
				transport.TLSClientConfig.ServerName = "receiver.invalid"

				config.HTTPClient.HTTPClient = &http.Client{Transport: transport}
			},
		},
		{
			name:   "ShouldRejectAuthorizationHeaderWithLineBreak",
			auth:   "Bearer a\r\nX-Injected: b",
			mutate: func(config *oauth2.Config, server *httptest.Server) {},
		},
		{
			name: "ShouldRejectSpecialUseAddressAtDial",
			auth: ssfPushSecret,
			mutate: func(config *oauth2.Config, server *httptest.Server) {
				config.DisableSpecialUseAddressGuard = false
			},
			expected: oauth2.ErrSpecialUseAddress,
		},
		{
			name: "ShouldRejectClientThatCannotBeGuarded",
			auth: ssfPushSecret,
			mutate: func(config *oauth2.Config, server *httptest.Server) {
				config.DisableSpecialUseAddressGuard = false
				config.HTTPClient.HTTPClient = &http.Client{Transport: ssfPushRoundTripper{}}
			},
			expected: oauth2.ErrSpecialUseAddress,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var hits int32

			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&hits, 1)
				w.WriteHeader(http.StatusAccepted)
			}))

			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.StartTLS()

			defer server.Close()

			provider := newSSFPushProvider(server)

			tc.mutate(provider.Config.(*oauth2.Config), server)

			result := provider.PushSecurityEventToken(context.Background(), ssfPushClient, oauth2.SSFDelivery{EndpointURL: server.URL, AuthorizationHeader: tc.auth}, ssfPushToken)

			assert.Equal(t, oauth2.SSFPushRejected, result.Outcome)
			assert.Zero(t, result.Status)
			assert.Zero(t, result.RetryAfter)
			assert.Error(t, result.Err)
			assert.Zero(t, atomic.LoadInt32(&hits))

			if tc.expected != nil {
				assert.ErrorIs(t, result.Err, tc.expected)
			}

			assert.NotContains(t, fmt.Sprintf("%+v %#v %v %s", result, result, result, result.Err), "super-secret-value")
			assert.NotContains(t, fmt.Sprintf("%+v %s", result, result.Err), "X-Injected")
		})
	}
}

func TestPushSecurityEventTokenShouldRetryOnTimeout(t *testing.T) {
	release := make(chan struct{})

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer server.Close()
	defer close(release)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	result := newSSFPushProvider(server).PushSecurityEventToken(ctx, ssfPushClient, oauth2.SSFDelivery{EndpointURL: server.URL, AuthorizationHeader: ssfPushSecret}, ssfPushToken)

	assert.Equal(t, oauth2.SSFPushRetryable, result.Outcome)
	assert.Zero(t, result.Status)
	assert.ErrorIs(t, result.Err, context.DeadlineExceeded)
}

func TestPushSecurityEventTokenShouldKeepIdleConnections(t *testing.T) {
	testCases := []struct {
		name    string
		status  int
		closed  bool
		outcome oauth2.SSFPushOutcome
	}{
		{"ShouldKeepAfterDelivery", http.StatusAccepted, false, oauth2.SSFPushDelivered},
		{"ShouldKeepAfterRejection", http.StatusBadRequest, false, oauth2.SSFPushRejected},
		{"ShouldKeepAfterRetryableStatus", http.StatusServiceUnavailable, false, oauth2.SSFPushRetryable},
		{"ShouldKeepAfterNetworkError", 0, true, oauth2.SSFPushRetryable},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status) }))
			defer server.Close()

			transport := &ssfPushIdleTransport{RoundTripper: server.Client().Transport}

			provider := newSSFPushProvider(server)
			provider.Config.(*oauth2.Config).HTTPClient.HTTPClient = &http.Client{Transport: transport}

			if tc.closed {
				server.Close()
			}

			result := provider.PushSecurityEventToken(context.Background(), ssfPushClient, oauth2.SSFDelivery{EndpointURL: server.URL, AuthorizationHeader: ssfPushSecret}, ssfPushToken)

			assert.Equal(t, tc.outcome, result.Outcome)
			assert.Equal(t, tc.status, result.Status)
			assert.Equal(t, int32(1), atomic.LoadInt32(&transport.trips))
			assert.Zero(t, atomic.LoadInt32(&transport.closed))
		})
	}
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

	result := provider.PushSecurityEventToken(context.Background(), ssfPushClient, oauth2.SSFDelivery{EndpointURL: server.URL}, ssfPushToken)

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
		{"ShouldRefuseUnparsableURL", oauth2.SSFDelivery{EndpointURL: "https://[::1"}},
		{"ShouldRefuseNoHost", oauth2.SSFDelivery{EndpointURL: "https:///path"}},
		{"ShouldRefusePollMethod", oauth2.SSFDelivery{Method: "urn:ietf:rfc:8936", EndpointURL: "https://example.com/push"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := provider.PushSecurityEventToken(context.Background(), ssfPushClient, tc.delivery, ssfPushToken)

			assert.Equal(t, oauth2.SSFPushRejected, result.Outcome)
			assert.Zero(t, result.Status)
			assert.Error(t, result.Err)
			assert.NotContains(t, result.Err.Error(), "super-secret-value")
		})
	}

	assert.Zero(t, atomic.LoadInt32(&hits))
}

func TestPushSecurityEventTokenShouldRefuseTokenThatIsNotCompact(t *testing.T) {
	testCases := []struct {
		name  string
		token string
	}{
		{"ShouldRefuseEmpty", ""},
		{"ShouldRefuseOneSegment", "token"},
		{"ShouldRefuseTwoSegments", "the.token"},
		{"ShouldRefuseFourSegments", "the.set.token.x"},
		{"ShouldRefuseSixSegments", "a.b.c.d.e.f"},
		{"ShouldRefuseEmptyPayload", "the..token"},
		{"ShouldRefuseEmptyHeader", ".set.token"},
		{"ShouldRefuseEmptyHeaderOfJWE", ".b.c.d.e"},
		{"ShouldRefuseOnlySeparators", ".."},
		{"ShouldRefuseEmptyCiphertext", "a.b.c..e"},
		{"ShouldRefuseJSON", `{"iss":"https://example.com"}`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var hits int32

			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&hits, 1)
				w.WriteHeader(http.StatusAccepted)
			}))
			defer server.Close()

			result := newSSFPushProvider(server).PushSecurityEventToken(context.Background(), ssfPushClient, oauth2.SSFDelivery{EndpointURL: server.URL, AuthorizationHeader: ssfPushSecret}, tc.token)

			assert.Equal(t, oauth2.SSFPushRejected, result.Outcome)
			assert.Zero(t, result.Status)
			assert.Error(t, result.Err)
			assert.Zero(t, atomic.LoadInt32(&hits))
		})
	}
}

func TestPushSecurityEventTokenShouldSendCompactToken(t *testing.T) {
	testCases := []struct {
		name  string
		token string
	}{
		{"ShouldSendJWS", "the.set.token"},
		{"ShouldSendJWE", "a.b.c.d.e"},
		{"ShouldSendJWEWithEmptyEncryptedKey", "a..c.d.e"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var hits int32

			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&hits, 1)
				w.WriteHeader(http.StatusAccepted)
			}))
			defer server.Close()

			result := newSSFPushProvider(server).PushSecurityEventToken(context.Background(), ssfPushClient, oauth2.SSFDelivery{EndpointURL: server.URL, AuthorizationHeader: ssfPushSecret}, tc.token)

			assert.Equal(t, oauth2.SSFPushDelivered, result.Outcome)
			assert.NoError(t, result.Err)
			assert.Equal(t, int32(1), atomic.LoadInt32(&hits))
		})
	}
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

			result := provider.PushSecurityEventToken(context.Background(), tc.client, oauth2.SSFDelivery{EndpointURL: server.URL, AuthorizationHeader: ssfPushSecret}, ssfPushToken)

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

	result := provider.PushSecurityEventToken(context.Background(), ssfPushClient, oauth2.SSFDelivery{EndpointURL: server.URL, AuthorizationHeader: ssfPushSecret}, ssfPushToken)

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

			result := provider.PushSecurityEventToken(context.Background(), ssfPushClient, oauth2.SSFDelivery{EndpointURL: server.URL}, ssfPushToken)

			assert.Equal(t, tc.status, result.Status)
			assert.Equal(t, tc.outcome, result.Outcome)
			assert.Error(t, result.Err)
			assert.NotContains(t, result.Err.Error(), "check failed")
			assert.Equal(t, tc.hits, atomic.LoadInt32(&hits))
		})
	}
}

func TestPushSecurityEventTokenShouldRetryTransientValidatorError(t *testing.T) {
	var hits int32

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	provider := newSSFPushProvider(server)
	provider.Config.(*oauth2.Config).SSF.EndpointValidator = ssfHandlerValidator{err: oauth2.ErrTemporarilyUnavailable.WithHint("The allow list is unavailable.")}

	result := provider.PushSecurityEventToken(context.Background(), ssfPushClient, oauth2.SSFDelivery{EndpointURL: server.URL, AuthorizationHeader: ssfPushSecret}, ssfPushToken)

	assert.Equal(t, oauth2.SSFPushRetryable, result.Outcome)
	assert.ErrorIs(t, result.Err, oauth2.ErrTemporarilyUnavailable)
	assert.Zero(t, atomic.LoadInt32(&hits))
}

func TestPushSecurityEventTokenShouldUseSSFHTTPClient(t *testing.T) {
	t.Run("ShouldPreferSSFHTTPClient", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusAccepted) }))
		defer server.Close()

		provider := newSSFPushProvider(nil)
		provider.Config.(*oauth2.Config).SSF.HTTPClient = newSSFPushProvider(server).Config.(*oauth2.Config).HTTPClient

		result := provider.PushSecurityEventToken(context.Background(), ssfPushClient, oauth2.SSFDelivery{EndpointURL: server.URL}, ssfPushToken)

		assert.Equal(t, oauth2.SSFPushDelivered, result.Outcome)
		assert.NoError(t, result.Err)
	})

	t.Run("ShouldRefuseSpecialUseAddressWhenGuarded", func(t *testing.T) {
		var hits int32

		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&hits, 1)
			w.WriteHeader(http.StatusAccepted)
		}))
		defer server.Close()

		provider := newSSFPushProvider(server)
		provider.Config.(*oauth2.Config).SSF.HTTPClient = oauth2.NewSpecialUseAddressGuardedHTTPClient()

		result := provider.PushSecurityEventToken(context.Background(), ssfPushClient, oauth2.SSFDelivery{EndpointURL: server.URL}, ssfPushToken)

		assert.Equal(t, oauth2.SSFPushRejected, result.Outcome)
		assert.ErrorIs(t, result.Err, oauth2.ErrSpecialUseAddress)
		assert.Zero(t, atomic.LoadInt32(&hits))
	})
}

func TestPushSecurityEventTokenShouldApplySpecialUseAddressGuard(t *testing.T) {
	testCases := []struct {
		name    string
		disable bool
		ssf     bool
		outcome oauth2.SSFPushOutcome
	}{
		{name: "ShouldDeliverWhenDisabled", disable: true, outcome: oauth2.SSFPushDelivered},
		{name: "ShouldDeliverWithSSFHTTPClientWhenDisabled", disable: true, ssf: true, outcome: oauth2.SSFPushDelivered},
		{name: "ShouldRefuseByDefault", outcome: oauth2.SSFPushRejected},
		{name: "ShouldRefuseWithSSFHTTPClientByDefault", ssf: true, outcome: oauth2.SSFPushRejected},
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
			config := provider.Config.(*oauth2.Config)
			config.DisableSpecialUseAddressGuard = tc.disable

			if tc.ssf {
				config.SSF.HTTPClient = config.HTTPClient
				config.HTTPClient = nil
			}

			result := provider.PushSecurityEventToken(context.Background(), ssfPushClient, oauth2.SSFDelivery{EndpointURL: server.URL}, ssfPushToken)

			assert.Equal(t, tc.outcome, result.Outcome)

			if !tc.disable {
				assert.ErrorIs(t, result.Err, oauth2.ErrSpecialUseAddress)
				assert.Zero(t, atomic.LoadInt32(&hits))
			} else {
				assert.NoError(t, result.Err)
				assert.Equal(t, int32(1), atomic.LoadInt32(&hits))
			}
		})
	}
}

func TestPushSecurityEventTokenToStream(t *testing.T) {
	const (
		streamUpdated = "https://schemas.openid.net/secevent/ssf/event-type/stream-updated"
		verification  = "https://schemas.openid.net/secevent/ssf/event-type/verification"
	)

	other := &oauth2.DefaultClient{ID: "b"}

	testCases := []struct {
		name      string
		status    string
		method    string
		client    oauth2.Client
		streamID  string
		eventType string
		mutate    func(provider *oauth2.Fosite)
		outcome   oauth2.SSFPushOutcome
		expected  error
		hits      int32
	}{
		{name: "ShouldDeliverOnEnabledStream", status: oauth2.SSFStreamStatusEnabled, eventType: ssfEventSessionRev, outcome: oauth2.SSFPushDelivered, hits: 1},
		{name: "ShouldDeliverVerificationOnEnabledStream", status: oauth2.SSFStreamStatusEnabled, eventType: verification, outcome: oauth2.SSFPushDelivered, hits: 1},
		{name: "ShouldHoldOnPausedStream", status: oauth2.SSFStreamStatusPaused, eventType: ssfEventSessionRev, outcome: oauth2.SSFPushRetryable, expected: oauth2.ErrSSFStreamPaused},
		{name: "ShouldHoldVerificationOnPausedStream", status: oauth2.SSFStreamStatusPaused, eventType: verification, outcome: oauth2.SSFPushRetryable, expected: oauth2.ErrSSFStreamPaused},
		{name: "ShouldHoldUnnamedEventOnPausedStream", status: oauth2.SSFStreamStatusPaused, outcome: oauth2.SSFPushRetryable, expected: oauth2.ErrSSFStreamPaused},
		{name: "ShouldRejectOnDisabledStream", status: oauth2.SSFStreamStatusDisabled, eventType: ssfEventSessionRev, outcome: oauth2.SSFPushRejected, expected: oauth2.ErrSSFStreamDisabled},
		{name: "ShouldRejectVerificationOnDisabledStream", status: oauth2.SSFStreamStatusDisabled, eventType: verification, outcome: oauth2.SSFPushRejected, expected: oauth2.ErrSSFStreamDisabled},
		{name: "ShouldRejectOnUnknownStatus", status: "stopped", eventType: ssfEventSessionRev, outcome: oauth2.SSFPushRejected},
		{name: "ShouldRejectOnEmptyStatus", eventType: ssfEventSessionRev, outcome: oauth2.SSFPushRejected},
		{name: "ShouldDeliverStreamUpdatedOnPausedStream", status: oauth2.SSFStreamStatusPaused, eventType: streamUpdated, outcome: oauth2.SSFPushDelivered, hits: 1},
		{name: "ShouldDeliverStreamUpdatedOnDisabledStream", status: oauth2.SSFStreamStatusDisabled, eventType: streamUpdated, outcome: oauth2.SSFPushDelivered, hits: 1},
		{name: "ShouldRejectUnknownStream", status: oauth2.SSFStreamStatusEnabled, streamID: "unknown", eventType: ssfEventSessionRev, outcome: oauth2.SSFPushRejected, expected: oauth2.ErrNotFound},
		{name: "ShouldRejectStreamOfAnotherClient", status: oauth2.SSFStreamStatusEnabled, client: other, eventType: ssfEventSessionRev, outcome: oauth2.SSFPushRejected, expected: oauth2.ErrNotFound},
		{name: "ShouldRejectStreamUpdatedOnStreamOfAnotherClient", status: oauth2.SSFStreamStatusEnabled, client: other, eventType: streamUpdated, outcome: oauth2.SSFPushRejected, expected: oauth2.ErrNotFound},
		{name: "ShouldRejectPollStream", status: oauth2.SSFStreamStatusEnabled, method: oauth2.SSFDeliveryMethodPoll, eventType: ssfEventSessionRev, outcome: oauth2.SSFPushRejected},
		{name: "ShouldRejectPausedPollStream", status: oauth2.SSFStreamStatusPaused, method: oauth2.SSFDeliveryMethodPoll, eventType: ssfEventSessionRev, outcome: oauth2.SSFPushRejected},
		{name: "ShouldRejectDisabledPollStream", status: oauth2.SSFStreamStatusDisabled, method: oauth2.SSFDeliveryMethodPoll, eventType: ssfEventSessionRev, outcome: oauth2.SSFPushRejected},
		{name: "ShouldRejectStreamUpdatedOnPausedPollStream", status: oauth2.SSFStreamStatusPaused, method: oauth2.SSFDeliveryMethodPoll, eventType: streamUpdated, outcome: oauth2.SSFPushRejected},
		{
			name: "ShouldRetryOnStorageFailure", status: oauth2.SSFStreamStatusEnabled, eventType: ssfEventSessionRev,
			mutate: func(provider *oauth2.Fosite) {
				provider.Store = &ssfPushFailingStore{MemoryStore: provider.Store.(*storage.MemoryStore)}
			},
			outcome: oauth2.SSFPushRetryable,
		},
		{
			name: "ShouldRejectStorageWithoutStreams", status: oauth2.SSFStreamStatusEnabled, eventType: ssfEventSessionRev,
			mutate:  func(provider *oauth2.Fosite) { provider.Store = nil },
			outcome: oauth2.SSFPushRejected,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var hits int32

			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&hits, 1)

				assert.Equal(t, ssfPushSecret, r.Header.Get("Authorization"))

				w.WriteHeader(http.StatusAccepted)
			}))
			defer server.Close()

			provider := newSSFPushProvider(server)

			stream := &oauth2.SSFStream{
				StreamID: "stream-a",
				ClientID: ssfPushClient.ID,
				Status:   tc.status,
				Delivery: oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPush, EndpointURL: server.URL, AuthorizationHeader: ssfPushSecret},
			}

			if tc.method != "" {
				stream.Delivery.Method = tc.method
			}

			assert.NoError(t, provider.Store.(*storage.MemoryStore).CreateSSFStream(context.Background(), stream))

			if tc.mutate != nil {
				tc.mutate(provider)
			}

			var client oauth2.Client = ssfPushClient

			if tc.client != nil {
				client = tc.client
			}

			streamID := stream.StreamID

			if tc.streamID != "" {
				streamID = tc.streamID
			}

			result := provider.PushSecurityEventTokenToStream(context.Background(), client, streamID, tc.eventType, ssfPushToken)

			assert.Equal(t, tc.outcome, result.Outcome)
			assert.Equal(t, tc.hits, atomic.LoadInt32(&hits))

			if tc.outcome == oauth2.SSFPushDelivered {
				assert.NoError(t, result.Err)
			} else {
				assert.Error(t, result.Err)
				assert.Zero(t, result.Status)
			}

			if tc.expected != nil {
				assert.ErrorIs(t, result.Err, tc.expected)
			}

			assert.NotContains(t, fmt.Sprintf("%+v %#v %v %s", result, result, result, result.Err), "super-secret-value")
		})
	}
}

func TestPushSecurityEventTokenToStreamShouldReadTheStatusOnEveryAttempt(t *testing.T) {
	var hits int32

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	ctx := context.Background()

	provider := newSSFPushProvider(server)
	store := provider.Store.(*storage.MemoryStore)

	assert.NoError(t, store.CreateSSFStream(ctx, &oauth2.SSFStream{
		StreamID: "stream-a",
		ClientID: ssfPushClient.ID,
		Status:   oauth2.SSFStreamStatusEnabled,
		Delivery: oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPush, EndpointURL: server.URL},
	}))

	steps := []struct {
		status  string
		outcome oauth2.SSFPushOutcome
		hits    int32
	}{
		{oauth2.SSFStreamStatusEnabled, oauth2.SSFPushDelivered, 1},
		{oauth2.SSFStreamStatusPaused, oauth2.SSFPushRetryable, 1},
		{oauth2.SSFStreamStatusEnabled, oauth2.SSFPushDelivered, 2},
		{oauth2.SSFStreamStatusDisabled, oauth2.SSFPushRejected, 2},
	}

	for _, step := range steps {
		assert.NoError(t, store.UpdateSSFStreamStatus(ctx, ssfPushClient.ID, "stream-a", step.status, ""))

		result := provider.PushSecurityEventTokenToStream(ctx, ssfPushClient, "stream-a", ssfEventSessionRev, ssfPushToken)

		assert.Equal(t, step.outcome, result.Outcome, step.status)
		assert.Equal(t, step.hits, atomic.LoadInt32(&hits), step.status)
	}
}

func TestPushSecurityEventTokenToStreamShouldRefuseMissingClient(t *testing.T) {
	result := newSSFPushProvider(nil).PushSecurityEventTokenToStream(context.Background(), nil, "stream-a", ssfEventSessionRev, ssfPushToken)

	assert.Equal(t, oauth2.SSFPushRejected, result.Outcome)
	assert.Error(t, result.Err)
}

func TestSSFPushOutcome(t *testing.T) {
	testCases := []struct {
		name     string
		have     oauth2.SSFPushOutcome
		expected string
	}{
		{"ShouldNameZeroValueUnknown", oauth2.SSFPushResult{}.Outcome, "unknown"},
		{"ShouldNameUnknown", oauth2.SSFPushUnknown, "unknown"},
		{"ShouldNameDelivered", oauth2.SSFPushDelivered, "delivered"},
		{"ShouldNameRejected", oauth2.SSFPushRejected, "rejected"},
		{"ShouldNameRetryable", oauth2.SSFPushRetryable, "retryable"},
		{"ShouldNameOutOfRangeUnknown", oauth2.SSFPushOutcome(99), "unknown"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.have.String())
		})
	}

	assert.NotEqual(t, oauth2.SSFPushDelivered, oauth2.SSFPushResult{}.Outcome)
	assert.Equal(t, oauth2.SSFPushUnknown, oauth2.SSFPushResult{}.Outcome)
}

func TestSSFDeliveryShouldRedactAuthorizationHeader(t *testing.T) {
	delivery := oauth2.SSFDelivery{Method: "urn:ietf:rfc:8935", EndpointURL: "https://example.com/push", AuthorizationHeader: ssfPushSecret}

	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		assert.NotContains(t, fmt.Sprintf(format, delivery), "super-secret-value", format)
		assert.NotContains(t, fmt.Sprintf(format, &delivery), "super-secret-value", format)
	}

	assert.Contains(t, fmt.Sprintf("%+v", delivery), "https://example.com/push")
}

type ssfPushIdleTransport struct {
	http.RoundTripper

	trips, closed int32
}

func (t *ssfPushIdleTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	atomic.AddInt32(&t.trips, 1)

	return t.RoundTripper.RoundTrip(r)
}

func (t *ssfPushIdleTransport) CloseIdleConnections() {
	atomic.AddInt32(&t.closed, 1)
}

type ssfPushFailingStore struct {
	*storage.MemoryStore
}

func (s *ssfPushFailingStore) GetSSFStream(context.Context, string, string) (*oauth2.SSFStream, error) {
	return nil, errors.New("the storage is unavailable")
}

type ssfPushRoundTripper struct{}

func (ssfPushRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("not reached")
}

func newSSFPushProvider(server *httptest.Server) *oauth2.Fosite {
	config := &oauth2.Config{Issuer: ssfHandlerIssuer, SSF: &oauth2.SSFConfig{EndpointValidator: ssfHandlerValidator{}}, DisableSpecialUseAddressGuard: true}

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
