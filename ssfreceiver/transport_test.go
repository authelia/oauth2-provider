// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/ssfjson"
)

const (
	testTransmitterToken = "c2VjcmV0LWFjY2Vzcy10b2tlbg"
	testTransmitterPath  = "/streams"
)

// testAuthorizer is an Authorizer which records what it was asked for.
type testAuthorizer struct {
	issuers []string
	scopes  []string
	err     error
}

func (a *testAuthorizer) AuthorizeRequest(_ context.Context, issuer, scope string, r *http.Request) (err error) {
	a.issuers = append(a.issuers, issuer)
	a.scopes = append(a.scopes, scope)

	if a.err != nil {
		return a.err
	}

	r.Header.Set("Authorization", "Bearer "+testTransmitterToken)

	return nil
}

// testTokenSource issues a new token after each invalidation.
type testTokenSource struct {
	generation  int
	invalidated []string
	requested   []string
}

func (s *testTokenSource) token(_ context.Context, issuer, scope string) (token string, err error) {
	s.requested = append(s.requested, issuer+" "+scope)

	return testTransmitterToken + strconv.Itoa(s.generation), nil
}

func (s *testTokenSource) invalidate(_ context.Context, issuer, scope string) {
	s.invalidated = append(s.invalidated, issuer+" "+scope)
	s.generation++
}

type testTransmitterRequest struct {
	method        string
	path          string
	query         string
	authorization string
	accept        string
	contentType   string
	language      string
	body          string
}

// testManagementServer is a TLS server which records the requests it receives.
type testManagementServer struct {
	*httptest.Server

	mu       sync.Mutex
	requests []testTransmitterRequest
}

func (s *testManagementServer) received() []testTransmitterRequest {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]testTransmitterRequest(nil), s.requests...)
}

func newTestManagementServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request, n int)) *testManagementServer {
	t.Helper()

	s := &testManagementServer{}

	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		s.mu.Lock()
		s.requests = append(s.requests, testTransmitterRequest{
			method:        r.Method,
			path:          r.URL.Path,
			query:         r.URL.RawQuery,
			authorization: r.Header.Get("Authorization"),
			accept:        r.Header.Get("Accept"),
			contentType:   r.Header.Get("Content-Type"),
			language:      r.Header.Get("Content-Language"),
			body:          string(body),
		})
		n := len(s.requests)
		s.mu.Unlock()

		handler(w, r, n)
	}))

	t.Cleanup(s.Close)

	return s
}

// testRetryingHTTPClient is a client which sends a request again up to three times.
func testRetryingHTTPClient(server *httptest.Server) *retryablehttp.Client {
	return &retryablehttp.Client{
		HTTPClient:   server.Client(),
		RetryWaitMin: time.Millisecond,
		RetryWaitMax: 2 * time.Millisecond,
		RetryMax:     3,
		CheckRetry:   retryablehttp.DefaultRetryPolicy,
		Backoff:      retryablehttp.DefaultBackoff,
	}
}

func testTransmitterReceiver(server *testManagementServer, authorizer Authorizer) *Receiver {
	receiver := testReceiver(server.Server)

	receiver.Config.Authorizer = authorizer

	return receiver
}

func TestReceiverTransmit(t *testing.T) {
	t.Run("ShouldSendBearerToken", func(t *testing.T) {
		server := newTestManagementServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
			writeTestJSON(w, []byte(`{"stream_id":"abc","unknown":true}`))
		})

		source := &testTokenSource{}
		receiver := testTransmitterReceiver(server, &BearerAuthorizer{Token: source.token})

		response, err := receiver.transmit(t.Context(), server.URL, transmitterRequest{
			method:   http.MethodPost,
			endpoint: server.URL + testTransmitterPath + "?tenant=a",
			scope:    oauth2.ScopeSSFManage,
			query:    map[string][]string{"stream_id": {"abc"}},
			header:   http.Header{"Content-Language": {"en"}},
			body:     map[string]any{"description": "example"},
			success:  []int{http.StatusOK, http.StatusCreated},
		})
		require.NoError(t, err)

		require.Len(t, server.received(), 1)

		request := server.received()[0]

		assert.Equal(t, http.MethodPost, request.method)
		assert.Equal(t, testTransmitterPath, request.path)
		assert.Equal(t, "tenant=a&stream_id=abc", request.query)
		assert.Equal(t, "Bearer "+testTransmitterToken+"0", request.authorization)
		assert.Equal(t, "application/json", request.accept)
		assert.Equal(t, "application/json", request.contentType)
		assert.Equal(t, "en", request.language)
		assert.JSONEq(t, `{"description":"example"}`, request.body)
		assert.Equal(t, []string{server.URL + " " + oauth2.ScopeSSFManage}, source.requested)

		assert.Equal(t, http.StatusOK, response.status)

		members, err := response.object()
		require.NoError(t, err)

		value, ok := ssfjson.ParseString(members["stream_id"])
		assert.True(t, ok)
		assert.Equal(t, "abc", value)
	})

	t.Run("ShouldRefuseAnEndpointWhichHasTheQueryParameter", func(t *testing.T) {
		server := newTestManagementServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
			w.WriteHeader(http.StatusNoContent)
		})

		receiver := testTransmitterReceiver(server, &testAuthorizer{})

		_, err := receiver.transmit(t.Context(), server.URL, transmitterRequest{
			method:   http.MethodDelete,
			endpoint: server.URL + testTransmitterPath + "?tenant=a&stream_id=other",
			scope:    oauth2.ScopeSSFManage,
			query:    map[string][]string{"stream_id": {"abc"}},
		})

		require.EqualError(t, err, "ssfreceiver: the endpoint already has the query parameter 'stream_id'")
		assert.Empty(t, server.received())
	})

	t.Run("ShouldRefuseAnEndpointWhoseQueryCanNotBeParsed", func(t *testing.T) {
		server := newTestManagementServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
			w.WriteHeader(http.StatusNoContent)
		})

		receiver := testTransmitterReceiver(server, &testAuthorizer{})

		_, err := receiver.transmit(t.Context(), server.URL, transmitterRequest{
			method:   http.MethodDelete,
			endpoint: server.URL + testTransmitterPath + "?tenant=a&stream_id=other%ZZ",
			scope:    oauth2.ScopeSSFManage,
			query:    map[string][]string{"stream_id": {"abc"}},
		})

		require.EqualError(t, err, "ssfreceiver: the query of the endpoint is not valid")
		assert.Empty(t, server.received())
	})

	t.Run("ShouldSendNoBodyOrContentTypeWithoutBody", func(t *testing.T) {
		server := newTestManagementServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
			w.WriteHeader(http.StatusNoContent)
		})

		receiver := testTransmitterReceiver(server, &testAuthorizer{})

		response, err := receiver.transmit(t.Context(), server.URL, transmitterRequest{
			method:   http.MethodDelete,
			endpoint: server.URL + testTransmitterPath,
			scope:    oauth2.ScopeSSFManage,
		})
		require.NoError(t, err)

		assert.Equal(t, http.StatusNoContent, response.status)
		assert.Empty(t, response.body)

		require.Len(t, server.received(), 1)
		assert.Empty(t, server.received()[0].contentType)
		assert.Empty(t, server.received()[0].body)
	})

	t.Run("ShouldAskForManageScopeOnWrites", func(t *testing.T) {
		server := newTestManagementServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
			w.WriteHeader(http.StatusNoContent)
		})

		authorizer := &testAuthorizer{}
		receiver := testTransmitterReceiver(server, authorizer)

		_, err := receiver.transmit(t.Context(), server.URL, transmitterRequest{
			method:   http.MethodPatch,
			endpoint: server.URL + testTransmitterPath,
			scope:    oauth2.ScopeSSFManage,
			body:     map[string]any{"stream_id": "abc"},
		})
		require.NoError(t, err)

		assert.Equal(t, []string{"ssf.manage"}, authorizer.scopes)
		assert.Equal(t, []string{server.URL}, authorizer.issuers)
	})

	t.Run("ShouldAskForReadScopeOnReads", func(t *testing.T) {
		server := newTestManagementServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
			writeTestJSON(w, []byte(`{}`))
		})

		authorizer := &testAuthorizer{}
		receiver := testTransmitterReceiver(server, authorizer)

		_, err := receiver.transmit(t.Context(), server.URL, transmitterRequest{
			method:   http.MethodGet,
			endpoint: server.URL + testTransmitterPath,
			scope:    oauth2.ScopeSSFRead,
			success:  []int{http.StatusOK},
		})
		require.NoError(t, err)

		assert.Equal(t, []string{"ssf.read"}, authorizer.scopes)
	})

	t.Run("ShouldRefuseUnknownScope", func(t *testing.T) {
		server := newTestManagementServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {})

		authorizer := &testAuthorizer{}
		receiver := testTransmitterReceiver(server, authorizer)

		_, err := receiver.transmit(t.Context(), server.URL, transmitterRequest{
			method:   http.MethodGet,
			endpoint: server.URL + testTransmitterPath,
			scope:    "openid",
		})
		require.Error(t, err)

		assert.Empty(t, authorizer.scopes)
		assert.Empty(t, server.received())
	})

	t.Run("ShouldRetryOnceAfter401WhenInvalidated", func(t *testing.T) {
		server := newTestManagementServer(t, func(w http.ResponseWriter, _ *http.Request, n int) {
			if n == 1 {
				w.WriteHeader(http.StatusUnauthorized)

				return
			}

			writeTestJSON(w, []byte(`{}`))
		})

		source := &testTokenSource{}
		receiver := testTransmitterReceiver(server, &BearerAuthorizer{Token: source.token, Invalidate: source.invalidate})

		_, err := receiver.transmit(t.Context(), server.URL, transmitterRequest{
			method:   http.MethodPost,
			endpoint: server.URL + testTransmitterPath,
			scope:    oauth2.ScopeSSFManage,
			body:     map[string]any{"a": 1},
			success:  []int{http.StatusOK},
		})
		require.NoError(t, err)

		requests := server.received()

		require.Len(t, requests, 2)
		assert.Equal(t, "Bearer "+testTransmitterToken+"0", requests[0].authorization)
		assert.Equal(t, "Bearer "+testTransmitterToken+"1", requests[1].authorization)
		assert.Equal(t, requests[0].body, requests[1].body)
		assert.Equal(t, []string{server.URL + " " + oauth2.ScopeSSFManage}, source.invalidated)
	})

	t.Run("ShouldNotRetryASecond401", func(t *testing.T) {
		server := newTestManagementServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
			w.WriteHeader(http.StatusUnauthorized)
		})

		source := &testTokenSource{}
		receiver := testTransmitterReceiver(server, &BearerAuthorizer{Token: source.token, Invalidate: source.invalidate})

		_, err := receiver.transmit(t.Context(), server.URL, transmitterRequest{
			method:   http.MethodGet,
			endpoint: server.URL + testTransmitterPath,
			scope:    oauth2.ScopeSSFRead,
		})
		require.ErrorIs(t, err, ErrTransmitterUnauthorized)

		assert.Len(t, server.received(), 2)
		assert.Len(t, source.invalidated, 2)
	})

	t.Run("ShouldNotRetryAfter401WithoutInvalidation", func(t *testing.T) {
		server := newTestManagementServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
			w.WriteHeader(http.StatusUnauthorized)
		})

		for name, authorizer := range map[string]Authorizer{
			"NoInvalidator":    &testAuthorizer{},
			"NoInvalidateFunc": &BearerAuthorizer{Token: (&testTokenSource{}).token},
		} {
			before := len(server.received())

			_, err := testTransmitterReceiver(server, authorizer).transmit(t.Context(), server.URL, transmitterRequest{
				method:   http.MethodGet,
				endpoint: server.URL + testTransmitterPath,
				scope:    oauth2.ScopeSSFRead,
			})
			require.ErrorIs(t, err, ErrTransmitterUnauthorized, name)

			assert.Len(t, server.received(), before+1, name)
		}
	})

	t.Run("ShouldNotFollowRedirect", func(t *testing.T) {
		server := newTestManagementServer(t, func(w http.ResponseWriter, r *http.Request, _ int) {
			if r.URL.Path == testTransmitterPath {
				http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)

				return
			}

			writeTestJSON(w, []byte(`{}`))
		})

		receiver := testTransmitterReceiver(server, &testAuthorizer{})

		_, err := receiver.transmit(t.Context(), server.URL, transmitterRequest{
			method:   http.MethodGet,
			endpoint: server.URL + testTransmitterPath,
			scope:    oauth2.ScopeSSFRead,
			success:  []int{http.StatusOK},
		})

		var e *TransmitterError

		require.ErrorAs(t, err, &e)
		assert.Equal(t, http.StatusTemporaryRedirect, e.Status)

		require.Len(t, server.received(), 1)
		assert.Equal(t, testTransmitterPath, server.received()[0].path)
	})

	t.Run("ShouldMapEachStatus", func(t *testing.T) {
		sentinels := []error{
			ErrTransmitterUnauthorized, ErrTransmitterForbidden, ErrStreamNotFound, ErrStreamConflict,
			ErrTransmitterThrottled, ErrStreamUpdatePending, ErrEndpointNotSupported,
		}

		testCases := []struct {
			name    string
			status  int
			pending bool
			success []int
			is      error
			ok      bool
		}{
			{name: "ShouldAccept200", status: http.StatusOK, success: []int{http.StatusOK}, ok: true},
			{name: "ShouldAcceptAny2xxWithoutSuccessList", status: http.StatusAccepted, ok: true},
			{name: "ShouldRefuse3xxWithoutSuccessList", status: http.StatusNotModified},
			{name: "ShouldRefuseUnexpectedSuccess", status: http.StatusNoContent, success: []int{http.StatusOK}},
			{name: "ShouldMap401", status: http.StatusUnauthorized, is: ErrTransmitterUnauthorized},
			{name: "ShouldMap403", status: http.StatusForbidden, is: ErrTransmitterForbidden},
			{name: "ShouldMap404", status: http.StatusNotFound, is: ErrStreamNotFound},
			{name: "ShouldMap409", status: http.StatusConflict, is: ErrStreamConflict},
			{name: "ShouldMap429", status: http.StatusTooManyRequests, is: ErrTransmitterThrottled},
			{name: "ShouldMap202WhenPending", status: http.StatusAccepted, pending: true, success: []int{http.StatusOK}, is: ErrStreamUpdatePending},
			{name: "ShouldMap202WhenPendingWithoutSuccessList", status: http.StatusAccepted, pending: true, is: ErrStreamUpdatePending},
			{name: "ShouldNotMap202WhenNotPending", status: http.StatusAccepted, success: []int{http.StatusOK}},
			{name: "ShouldMap400", status: http.StatusBadRequest},
			{name: "ShouldMap500", status: http.StatusInternalServerError},
			{name: "ShouldMap503", status: http.StatusServiceUnavailable},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				server := newTestManagementServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
					w.WriteHeader(tc.status)
				})

				receiver := testTransmitterReceiver(server, &testAuthorizer{})

				response, err := receiver.transmit(t.Context(), server.URL, transmitterRequest{
					method:   http.MethodPost,
					endpoint: server.URL + testTransmitterPath,
					scope:    oauth2.ScopeSSFManage,
					body:     map[string]any{},
					success:  tc.success,
					pending:  tc.pending,
				})

				// The request is sent once. ShouldNeverSendAResponseAgain covers a client which retries.
				assert.Len(t, server.received(), 1)

				if tc.ok {
					require.NoError(t, err)
					assert.Equal(t, tc.status, response.status)

					return
				}

				assert.Nil(t, response)

				var e *TransmitterError

				require.ErrorAs(t, err, &e)
				assert.Equal(t, tc.status, e.Status)
				assert.Contains(t, err.Error(), strconv.Itoa(tc.status))

				for _, sentinel := range sentinels {
					assert.Equal(t, sentinel == tc.is, errors.Is(err, sentinel), "%v", sentinel)
				}
			})
		}
	})

	t.Run("ShouldCapRetryAfter", func(t *testing.T) {
		testCases := []struct {
			name     string
			header   string
			expected time.Duration
		}{
			{name: "ShouldReturnSeconds", header: "30", expected: 30 * time.Second},
			{name: "ShouldCapSeconds", header: "86400", expected: ssfjson.MaxRetryAfter},
			{name: "ShouldCapDate", header: time.Now().Add(24 * time.Hour).UTC().Format(http.TimeFormat), expected: ssfjson.MaxRetryAfter},
			{name: "ShouldReturnZeroWithoutHeader", header: "", expected: 0},
			{name: "ShouldReturnZeroForInvalid", header: "soon", expected: 0},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				server := newTestManagementServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
					if tc.header != "" {
						w.Header().Set("Retry-After", tc.header)
					}

					w.WriteHeader(http.StatusTooManyRequests)
				})

				receiver := testTransmitterReceiver(server, &testAuthorizer{})

				_, err := receiver.transmit(t.Context(), server.URL, transmitterRequest{
					method:   http.MethodGet,
					endpoint: server.URL + testTransmitterPath,
					scope:    oauth2.ScopeSSFRead,
				})
				require.ErrorIs(t, err, ErrTransmitterThrottled)

				var e *TransmitterError

				require.ErrorAs(t, err, &e)
				assert.Equal(t, tc.expected, e.RetryAfter)
				assert.LessOrEqual(t, e.RetryAfter, ssfjson.MaxRetryAfter)
			})
		}
	})

	t.Run("ShouldRefuseHTTPEndpoint", func(t *testing.T) {
		hits := 0

		server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
		t.Cleanup(server.Close)

		testCases := []struct {
			name     string
			endpoint string
		}{
			{name: "ShouldRefuseHTTP", endpoint: server.URL + testTransmitterPath},
			{name: "ShouldRefuseNoScheme", endpoint: strings.TrimPrefix(server.URL, "http:") + testTransmitterPath},
			{name: "ShouldRefuseNoHost", endpoint: "https:///streams"},
			{name: "ShouldRefuseNoHostname", endpoint: "https://:443/streams"},
			{name: "ShouldRefuseUserInfo", endpoint: "https://user:pass@" + strings.TrimPrefix(server.URL, "http://") + testTransmitterPath},
			{name: "ShouldRefuseFragment", endpoint: "https://" + strings.TrimPrefix(server.URL, "http://") + testTransmitterPath + "#a"},
			{name: "ShouldRefuseUnparsable", endpoint: "https://exa mple.com/\x7f"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				authorizer := &testAuthorizer{}
				receiver := &Receiver{Config: Config{HTTPClient: testHTTPClient(server), SpecialUseAddressGuard: testLoopbackGuard(), Authorizer: authorizer}}

				_, err := receiver.transmit(t.Context(), server.URL, transmitterRequest{
					method:   http.MethodGet,
					endpoint: tc.endpoint,
					scope:    oauth2.ScopeSSFRead,
				})
				require.ErrorIs(t, err, ErrEndpointNotHTTPS)

				assert.Zero(t, hits)
				assert.Empty(t, authorizer.scopes)
			})
		}
	})

	t.Run("ShouldReturnNotSupportedWithoutEndpoint", func(t *testing.T) {
		authorizer := &testAuthorizer{}
		receiver := &Receiver{Config: Config{Authorizer: authorizer}}

		_, err := receiver.transmit(t.Context(), "https://transmitter.example.com", transmitterRequest{
			method: http.MethodPost,
			scope:  oauth2.ScopeSSFManage,
		})
		require.ErrorIs(t, err, ErrEndpointNotSupported)

		assert.Empty(t, authorizer.scopes)
	})

	t.Run("ShouldRefuseWithoutAuthorizer", func(t *testing.T) {
		server := newTestManagementServer(t, func(http.ResponseWriter, *http.Request, int) {})

		_, err := testTransmitterReceiver(server, nil).transmit(t.Context(), server.URL, transmitterRequest{
			method:   http.MethodGet,
			endpoint: server.URL + testTransmitterPath,
			scope:    oauth2.ScopeSSFRead,
		})
		require.Error(t, err)

		assert.Empty(t, server.received())
	})

	t.Run("ShouldReturnAuthorizerError", func(t *testing.T) {
		server := newTestManagementServer(t, func(http.ResponseWriter, *http.Request, int) {})

		expected := errors.New("no token")

		_, err := testTransmitterReceiver(server, &testAuthorizer{err: expected}).transmit(t.Context(), server.URL, transmitterRequest{
			method:   http.MethodGet,
			endpoint: server.URL + testTransmitterPath,
			scope:    oauth2.ScopeSSFRead,
		})
		require.ErrorIs(t, err, expected)

		assert.Empty(t, server.received())
	})

	t.Run("ShouldRefuseSpecialUseAddress", func(t *testing.T) {
		server := newTestManagementServer(t, func(http.ResponseWriter, *http.Request, int) {})

		receiver := testTransmitterReceiver(server, &testAuthorizer{})
		receiver.Config.SpecialUseAddressGuard = nil

		_, err := receiver.transmit(t.Context(), server.URL, transmitterRequest{
			method:   http.MethodGet,
			endpoint: server.URL + testTransmitterPath,
			scope:    oauth2.ScopeSSFRead,
		})
		require.ErrorIs(t, err, oauth2.ErrSpecialUseAddress)

		assert.Empty(t, server.received())
	})

	t.Run("ShouldCapResponseBody", func(t *testing.T) {
		server := newTestManagementServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
			writeTestJSON(w, []byte(`{"a":"`+strings.Repeat("a", 64)+`"}`))
		})

		receiver := testTransmitterReceiver(server, &testAuthorizer{})
		receiver.Config.MaxResponseBytes = 32

		response, err := receiver.transmit(t.Context(), server.URL, transmitterRequest{
			method:   http.MethodGet,
			endpoint: server.URL + testTransmitterPath,
			scope:    oauth2.ScopeSSFRead,
		})
		require.EqualError(t, err, "ssfreceiver: the transmitter response is not valid: the body is larger than 32 bytes")

		assert.Nil(t, response)
	})

	t.Run("ShouldUseTheRequestTimeout", func(t *testing.T) {
		release := make(chan struct{})

		server := newTestManagementServer(t, func(http.ResponseWriter, *http.Request, int) { <-release })
		t.Cleanup(func() { close(release) })

		receiver := testTransmitterReceiver(server, &testAuthorizer{})

		_, err := receiver.transmit(t.Context(), server.URL, transmitterRequest{
			method:   http.MethodGet,
			endpoint: server.URL + testTransmitterPath,
			scope:    oauth2.ScopeSSFRead,
			timeout:  50 * time.Millisecond,
		})
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})

	t.Run("ShouldNeverPutTheTokenInAnError", func(t *testing.T) {
		echo := func(status int) func(w http.ResponseWriter, r *http.Request, _ int) {
			return func(w http.ResponseWriter, r *http.Request, _ int) {
				w.Header().Set("WWW-Authenticate", r.Header.Get("Authorization"))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"error":"` + r.Header.Get("Authorization") + ` marker-in-body"}`))
			}
		}

		check := func(t *testing.T, err error) {
			t.Helper()

			require.Error(t, err)

			for e := err; e != nil; e = errors.Unwrap(e) {
				assert.NotContains(t, e.Error(), testTransmitterToken)
				assert.NotContains(t, e.Error(), "marker-in-body")
			}
		}

		for _, status := range []int{202, 204, 302, 400, 401, 403, 404, 409, 429, 500, 503} {
			t.Run("ShouldOmitOn"+strconv.Itoa(status), func(t *testing.T) {
				server := newTestManagementServer(t, echo(status))

				source := &testTokenSource{}
				receiver := testTransmitterReceiver(server, &BearerAuthorizer{Token: source.token, Invalidate: source.invalidate})

				_, err := receiver.transmit(t.Context(), server.URL, transmitterRequest{
					method:   http.MethodPut,
					endpoint: server.URL + testTransmitterPath,
					scope:    oauth2.ScopeSSFManage,
					body:     map[string]any{},
					success:  []int{http.StatusOK},
					pending:  true,
				})

				check(t, err)
			})
		}

		t.Run("ShouldOmitWhenTheBodyIsTooLarge", func(t *testing.T) {
			server := newTestManagementServer(t, echo(http.StatusOK))

			receiver := testTransmitterReceiver(server, &BearerAuthorizer{Token: (&testTokenSource{}).token})
			receiver.Config.MaxResponseBytes = 8

			_, err := receiver.transmit(t.Context(), server.URL, transmitterRequest{
				method:   http.MethodGet,
				endpoint: server.URL + testTransmitterPath,
				scope:    oauth2.ScopeSSFRead,
			})

			check(t, err)
		})

		t.Run("ShouldOmitWhenTheBodyIsNotAnObject", func(t *testing.T) {
			server := newTestManagementServer(t, func(w http.ResponseWriter, r *http.Request, _ int) {
				writeTestJSON(w, []byte(`[`+r.Header.Get("Authorization")+` marker-in-body`))
			})

			receiver := testTransmitterReceiver(server, &BearerAuthorizer{Token: (&testTokenSource{}).token})

			response, err := receiver.transmit(t.Context(), server.URL, transmitterRequest{
				method:   http.MethodGet,
				endpoint: server.URL + testTransmitterPath,
				scope:    oauth2.ScopeSSFRead,
			})
			require.NoError(t, err)

			_, err = response.object()

			check(t, err)
		})

		t.Run("ShouldOmitWhenTheConnectionFails", func(t *testing.T) {
			server := newTestManagementServer(t, echo(http.StatusOK))

			receiver := testTransmitterReceiver(server, &BearerAuthorizer{Token: (&testTokenSource{}).token})

			server.Close()

			_, err := receiver.transmit(t.Context(), server.URL, transmitterRequest{
				method:   http.MethodGet,
				endpoint: server.URL + testTransmitterPath,
				scope:    oauth2.ScopeSSFRead,
			})

			check(t, err)
		})

		t.Run("ShouldOmitWhenTheTokenIsNotAHeaderValue", func(t *testing.T) {
			server := newTestManagementServer(t, echo(http.StatusOK))

			for _, token := range []string{testTransmitterToken + "\r\nX-Injected: 1", testTransmitterToken + " b", ""} {
				receiver := testTransmitterReceiver(server, &BearerAuthorizer{Token: func(context.Context, string, string) (string, error) {
					return token, nil
				}})

				_, err := receiver.transmit(t.Context(), server.URL, transmitterRequest{
					method:   http.MethodGet,
					endpoint: server.URL + testTransmitterPath,
					scope:    oauth2.ScopeSSFRead,
				})

				check(t, err)
			}

			assert.Empty(t, server.received())
		})
	})
}

func TestReceiverTransmitHeld(t *testing.T) {
	const authorize = 100 * time.Millisecond

	server := newTestManagementServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.WriteHeader(http.StatusGatewayTimeout)
	})

	receiver := testTransmitterReceiver(server, &BearerAuthorizer{Token: func(context.Context, string, string) (token string, err error) {
		time.Sleep(authorize)

		return testTransmitterToken, nil
	}})

	start := time.Now()

	_, err := receiver.transmit(t.Context(), server.URL, transmitterRequest{method: http.MethodPost, endpoint: server.URL + testTransmitterPath, scope: oauth2.ScopeSSFManage})

	total := time.Since(start)

	var terr *TransmitterError

	require.ErrorAs(t, err, &terr)

	// The time a request is held starts after it is authorized, whatever the time of the exchange.
	assert.Positive(t, terr.held)
	assert.LessOrEqual(t, terr.held, total-authorize)
}

func TestReceiverTransmitRetry(t *testing.T) {
	t.Run("ShouldRetryOnlyIdempotentMethodsWhenTheConnectionFails", func(t *testing.T) {
		testCases := []struct {
			name   string
			method string
			once   bool
			retry  bool
		}{
			{name: "ShouldSendPOSTOnce", method: http.MethodPost},
			{name: "ShouldSendPATCHOnce", method: http.MethodPatch},
			{name: "ShouldSendPUTOnceWhenAsked", method: http.MethodPut, once: true},
			{name: "ShouldRetryGET", method: http.MethodGet, retry: true},
			{name: "ShouldRetryPUT", method: http.MethodPut, retry: true},
			{name: "ShouldRetryDELETE", method: http.MethodDelete, retry: true},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// The first connection is closed after the request is read and before any response.
				server := newTestManagementServer(t, func(w http.ResponseWriter, _ *http.Request, n int) {
					if n == 1 {
						conn, _, err := w.(http.Hijacker).Hijack()
						if err == nil {
							_ = conn.Close()
						}

						return
					}

					w.WriteHeader(http.StatusNoContent)
				})

				receiver := testTransmitterReceiver(server, &testAuthorizer{})
				receiver.Config.HTTPClient = testRetryingHTTPClient(server.Server)

				request := transmitterRequest{
					method:   tc.method,
					endpoint: server.URL + testTransmitterPath,
					scope:    oauth2.ScopeSSFManage,
					once:     tc.once,
				}

				if tc.method != http.MethodGet && tc.method != http.MethodDelete {
					request.body = map[string]any{"stream_id": "abc"}
				}

				response, err := receiver.transmit(t.Context(), server.URL, request)

				if tc.retry {
					require.NoError(t, err)
					assert.Equal(t, http.StatusNoContent, response.status)
					assert.Len(t, server.received(), 2)

					return
				}

				require.Error(t, err)
				assert.Nil(t, response)

				var e *TransmitterError

				assert.NotErrorAs(t, err, &e)
				assert.Len(t, server.received(), 1)
			})
		}
	})

	t.Run("ShouldNeverSendAResponseAgain", func(t *testing.T) {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete} {
			for _, status := range []int{http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusServiceUnavailable} {
				t.Run(method+strconv.Itoa(status), func(t *testing.T) {
					server := newTestManagementServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
						w.WriteHeader(status)
					})

					receiver := testTransmitterReceiver(server, &testAuthorizer{})
					receiver.Config.HTTPClient = testRetryingHTTPClient(server.Server)

					_, err := receiver.transmit(t.Context(), server.URL, transmitterRequest{
						method:   method,
						endpoint: server.URL + testTransmitterPath,
						scope:    oauth2.ScopeSSFManage,
					})

					var e *TransmitterError

					require.ErrorAs(t, err, &e)
					assert.Equal(t, status, e.Status)
					assert.Len(t, server.received(), 1)
				})
			}
		}
	})
}

func TestTransmitterResponseObject(t *testing.T) {
	testCases := []struct {
		name        string
		contentType string
		body        string
		err         string
		expected    []string
	}{
		{name: "ShouldReturnMembers", contentType: "application/json", body: `{"a":1,"b":"c"}`, expected: []string{"a", "b"}},
		{name: "ShouldAcceptContentTypeParameters", contentType: "Application/JSON; charset=utf-8", body: `{"a":1}`, expected: []string{"a"}},
		{name: "ShouldRejectOtherContentType", contentType: "text/html", body: `{"a":1}`, err: "content type"},
		{name: "ShouldRejectMissingContentType", body: `{"a":1}`, err: "content type"},
		{name: "ShouldRejectRepeatedMemberNames", contentType: "application/json", body: `{"a":1,"a":2}`, err: "not a JSON object"},
		{name: "ShouldRejectArray", contentType: "application/json", body: `[]`, err: "not a JSON object"},
		{name: "ShouldRejectEmptyBody", contentType: "application/json", err: "not a JSON object"},
		{name: "ShouldRejectTrailingData", contentType: "application/json", body: `{}{}`, err: "not a JSON object"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			response := &transmitterResponse{status: http.StatusOK, header: http.Header{}, body: []byte(tc.body)}

			if tc.contentType != "" {
				response.header.Set("Content-Type", tc.contentType)
			}

			members, err := response.object()

			if tc.err != "" {
				assert.ErrorContains(t, err, tc.err)
				assert.Nil(t, members)

				return
			}

			require.NoError(t, err)
			assert.Len(t, members, len(tc.expected))

			for _, name := range tc.expected {
				assert.Contains(t, members, name)
			}
		})
	}
}

func TestBearerAuthorizer(t *testing.T) {
	t.Run("ShouldReturnTokenError", func(t *testing.T) {
		expected := errors.New("token endpoint unavailable")

		authorizer := &BearerAuthorizer{Token: func(context.Context, string, string) (string, error) { return "", expected }}

		r := httptest.NewRequest(http.MethodGet, "https://transmitter.example.com/streams", nil)

		require.ErrorIs(t, authorizer.AuthorizeRequest(t.Context(), "https://transmitter.example.com", oauth2.ScopeSSFRead, r), expected)
		assert.Empty(t, r.Header.Get("Authorization"))
	})

	t.Run("ShouldRefuseWithoutTokenFunc", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "https://transmitter.example.com/streams", nil)

		require.Error(t, (&BearerAuthorizer{}).AuthorizeRequest(t.Context(), "https://transmitter.example.com", oauth2.ScopeSSFRead, r))
		assert.Empty(t, r.Header.Get("Authorization"))
	})

	t.Run("ShouldReportWhetherItInvalidated", func(t *testing.T) {
		source := &testTokenSource{}

		assert.False(t, (&BearerAuthorizer{Token: source.token}).InvalidateAuthorization(t.Context(), "a", "b"))
		assert.True(t, (&BearerAuthorizer{Token: source.token, Invalidate: source.invalidate}).InvalidateAuthorization(t.Context(), "a", "b"))
		assert.Equal(t, []string{"a b"}, source.invalidated)
	})
}

func TestUnconfirmedError(t *testing.T) {
	cause := errors.New("connection reset")

	testCases := []struct {
		name string
		err  error
	}{
		{name: "ShouldMatchWithoutAResponse", err: &unconfirmedError{err: cause}},
		{name: "ShouldMatchAnUnreadResponse", err: &unconfirmedError{err: cause, status: http.StatusOK}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := fmt.Errorf("ssfreceiver: the transmitter request could not be sent: %w", tc.err)

			require.ErrorIs(t, err, ErrTransmitterUnconfirmed)
			require.ErrorIs(t, err, cause)
			assert.NotContains(t, err.Error(), ErrTransmitterUnconfirmed.Error())
		})
	}

	t.Run("ShouldNotMatchAnotherError", func(t *testing.T) {
		assert.NotErrorIs(t, fmt.Errorf("ssfreceiver: the transmitter request could not be authorized: %w", cause), ErrTransmitterUnconfirmed)
		assert.NotErrorIs(t, &TransmitterError{Status: http.StatusBadGateway}, ErrTransmitterUnconfirmed)
	})
}
