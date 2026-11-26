// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
)

const (
	testPushSecret        = "Bearer cHVzaC1zZWNyZXQ"
	testPendingPushSecret = "Bearer cGVuZGluZy1zZWNyZXQ"
	testPushURL           = "https://rp.example.com/ssf/push/s1"
)

// testEventHandler is the EventHandler of a Receiver under test.
type testEventHandler struct {
	events []*ReceivedEvent
	err    error
}

func (h *testEventHandler) HandleSecurityEvent(_ context.Context, event *ReceivedEvent) (err error) {
	h.events = append(h.events, event)

	return h.err
}

// testPushAuthorizer is a PushAuthorizer which records the records it was asked about.
type testPushAuthorizer struct {
	records []*StreamRecord
	err     error
}

func (a *testPushAuthorizer) AuthorizePush(_ context.Context, record *StreamRecord, _ *http.Request) (err error) {
	a.records = append(a.records, record)

	return a.err
}

// testBody counts the reads of a request body.
type testBody struct {
	io.Reader

	reads int
}

func (b *testBody) Read(p []byte) (n int, err error) {
	b.reads++

	return b.Reader.Read(p)
}

type testPush struct {
	x       *testTransmitter
	store   *testTokenStore
	handler *testEventHandler
}

func newTestPush(t *testing.T) *testPush {
	p := &testPush{x: newTestTransmitter(t), handler: &testEventHandler{}}

	p.store = p.x.store()
	p.x.receiver.Config.Handler = p.handler
	p.x.record.Delivery = oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPush, EndpointURL: testPushURL, AuthorizationHeader: testPushSecret}

	return p
}

func (p *testPush) request(body io.Reader) *http.Request {
	r := httptest.NewRequest(http.MethodPost, testPushURL, body)

	r.Header.Set("Content-Type", "application/secevent+jwt")
	r.Header.Set("Authorization", testPushSecret)

	return r
}

func (p *testPush) token(t *testing.T) string {
	return p.x.set().sign(t, p.x.claims())
}

func (p *testPush) do(t *testing.T, r *http.Request) (rw *httptest.ResponseRecorder, err error) {
	rw = httptest.NewRecorder()

	err = p.x.receiver.HandlePush(t.Context(), rw, r, p.x.record)

	return rw, err
}

func requireSetError(t *testing.T, rw *httptest.ResponseRecorder, code string) (description string) {
	t.Helper()

	require.Equal(t, http.StatusBadRequest, rw.Code)
	assert.Equal(t, "application/json", rw.Header().Get("Content-Type"))
	assert.Equal(t, "en", rw.Header().Get("Content-Language"))

	var body map[string]any

	require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &body))
	assert.Len(t, body, 2)
	assert.Equal(t, code, body["err"])

	description, _ = body["description"].(string)

	assert.NotEmpty(t, description)

	return description
}

func TestReceiverHandlePush(t *testing.T) {
	t.Run("ShouldAccept202WithEmptyBody", func(t *testing.T) {
		p := newTestPush(t)

		rw, err := p.do(t, p.request(strings.NewReader(p.token(t))))

		require.NoError(t, err)
		assert.Equal(t, http.StatusAccepted, rw.Code)
		assert.Empty(t, rw.Body.Bytes())
		assert.Empty(t, rw.Header().Get("Content-Type"))

		require.Len(t, p.handler.events, 1)
		assert.Equal(t, testJTI, p.handler.events[0].Claims.JTI)
		assert.Len(t, p.store.marks, 1)
	})

	t.Run("ShouldAccept202ForKnownJTIWithoutDispatch", func(t *testing.T) {
		p := newTestPush(t)

		token := p.token(t)

		for range 2 {
			rw, err := p.do(t, p.request(strings.NewReader(token)))

			require.NoError(t, err)
			assert.Equal(t, http.StatusAccepted, rw.Code)
			assert.Empty(t, rw.Body.Bytes())
		}

		assert.Len(t, p.handler.events, 1)
	})

	t.Run("ShouldAcceptContentTypeWithParameterAndCase", func(t *testing.T) {
		p := newTestPush(t)

		r := p.request(strings.NewReader(p.token(t)))
		r.Header.Set("Content-Type", "Application/SecEvent+JWT; charset=utf-8")

		rw, err := p.do(t, r)

		require.NoError(t, err)
		assert.Equal(t, http.StatusAccepted, rw.Code)
	})

	t.Run("ShouldWriteErrAndDescriptionAsJSON", func(t *testing.T) {
		testCases := []struct {
			name     string
			setup    func(t *testing.T, p *testPush) string
			expected string
		}{
			{
				name:     "ShouldReportNotCompact",
				setup:    func(*testing.T, *testPush) string { return "not a token" },
				expected: SetErrorInvalidRequest,
			},
			{
				name:     "ShouldReportEmptyBody",
				setup:    func(*testing.T, *testPush) string { return "" },
				expected: SetErrorInvalidRequest,
			},
			{
				name: "ShouldReportIssuer",
				setup: func(t *testing.T, p *testPush) string {
					claims := p.x.claims()
					claims["iss"] = "https://other.example.com"

					return p.x.set().sign(t, claims)
				},
				expected: SetErrorInvalidIssuer,
			},
			{
				name: "ShouldReportAudience",
				setup: func(t *testing.T, p *testPush) string {
					claims := p.x.claims()
					claims["aud"] = "https://other.example.com"

					return p.x.set().sign(t, claims)
				},
				expected: SetErrorInvalidAudience,
			},
			{
				name: "ShouldReportKey",
				setup: func(t *testing.T, p *testPush) string {
					set := p.x.set()
					set.kid = "unknown"

					return set.sign(t, p.x.claims())
				},
				expected: SetErrorInvalidKey,
			},
			{
				name: "ShouldReportSetErrorOfDispatch",
				setup: func(t *testing.T, p *testPush) string {
					p.handler.err = &SetError{Code: SetErrorAccessDenied, Description: "The Transmitter may not send this event."}

					return p.token(t)
				},
				expected: SetErrorAccessDenied,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				p := newTestPush(t)

				rw, err := p.do(t, p.request(strings.NewReader(tc.setup(t, p))))

				require.NoError(t, err)
				requireSetError(t, rw, tc.expected)
				assert.Empty(t, p.store.marks)
			})
		}
	})

	t.Run("ShouldSetContentLanguage", func(t *testing.T) {
		p := newTestPush(t)

		rw, err := p.do(t, p.request(strings.NewReader("not a token")))

		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rw.Code)
		assert.Equal(t, []string{"en"}, rw.Header().Values("Content-Language"))
		assert.Equal(t, []string{"application/json"}, rw.Header().Values("Content-Type"))
	})

	t.Run("ShouldRejectBeforeReadingBodyWhenUnauthorized", func(t *testing.T) {
		denied := errors.New("denied: cHVzaC1zZWNyZXQ")

		testCases := []struct {
			name     string
			setup    func(p *testPush, r *http.Request)
			expected error
		}{
			{
				name:     "ShouldRejectWrongSecret",
				setup:    func(_ *testPush, r *http.Request) { r.Header.Set("Authorization", "Bearer wrong") },
				expected: errPushSecret,
			},
			{
				name: "ShouldRejectByPushAuthorizer",
				setup: func(p *testPush, _ *http.Request) {
					p.x.receiver.Config.PushAuthorizer = &testPushAuthorizer{err: denied}
				},
				expected: denied,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				p := newTestPush(t)

				body := &testBody{Reader: strings.NewReader(p.token(t))}
				r := p.request(body)

				tc.setup(p, r)

				rw, err := p.do(t, r)

				// The error of the authorizer is returned for the caller to log, and is not one of a 503.
				require.ErrorIs(t, err, tc.expected)
				assert.NotErrorIs(t, err, ErrPushAuthorizerUnavailable)

				description := requireSetError(t, rw, SetErrorAuthenticationFailed)

				assert.NotContains(t, description, "cHVzaC1zZWNyZXQ")
				assert.Empty(t, rw.Header().Get("WWW-Authenticate"))
				assert.Zero(t, body.reads)
				assert.Empty(t, p.handler.events)
				assert.Empty(t, p.store.marks)
			})
		}
	})

	t.Run("ShouldAnswer503WhenTheSETIsIssuedAheadOfTheClockSkew", func(t *testing.T) {
		p := newTestPush(t)

		claims := p.x.claims()
		claims["iat"] = p.x.now.Add(DefaultClockSkew + time.Minute).Unix()

		token := p.x.set().sign(t, claims)

		rw, err := p.do(t, p.request(strings.NewReader(token)))

		// RFC 8935 Section 2: the failure is recoverable, so the Transmitter delivers the SET again.
		require.ErrorIs(t, err, ErrIssuedAtAhead)
		assert.Equal(t, http.StatusServiceUnavailable, rw.Code)
		assert.Empty(t, rw.Body.Bytes())
		assert.Empty(t, p.handler.events)
		assert.Empty(t, p.store.marks)

		p.x.now = p.x.now.Add(time.Minute)

		rw, err = p.do(t, p.request(strings.NewReader(token)))

		require.NoError(t, err)
		assert.Equal(t, http.StatusAccepted, rw.Code)
		assert.Len(t, p.handler.events, 1)
	})

	t.Run("ShouldAnswer503WhenThePushAuthorizerIsUnavailable", func(t *testing.T) {
		p := newTestPush(t)

		unavailable := fmt.Errorf("introspection failed: %w", ErrPushAuthorizerUnavailable)

		p.x.receiver.Config.PushAuthorizer = &testPushAuthorizer{err: unavailable}

		body := &testBody{Reader: strings.NewReader(p.token(t))}

		rw, err := p.do(t, p.request(body))

		// The Transmitter delivers the SET again, and the caller has the cause.
		require.ErrorIs(t, err, ErrPushAuthorizerUnavailable)
		assert.Equal(t, unavailable, err)
		assert.Equal(t, http.StatusServiceUnavailable, rw.Code)
		assert.Empty(t, rw.Body.Bytes())
		assert.Zero(t, body.reads)
		assert.Empty(t, p.handler.events)
		assert.Empty(t, p.store.marks)
	})

	t.Run("ShouldRejectRecordThatIsNotOfPushStreamBeforeAuthorizing", func(t *testing.T) {
		for _, method := range []string{oauth2.SSFDeliveryMethodPoll, "urn:example:delivery"} {
			t.Run(method, func(t *testing.T) {
				p := newTestPush(t)

				authorizer := &testPushAuthorizer{}
				p.x.receiver.Config.PushAuthorizer = authorizer
				p.x.record.Delivery.Method = method

				body := &testBody{Reader: strings.NewReader(p.token(t))}

				rw, err := p.do(t, p.request(body))

				require.NoError(t, err)
				requireSetError(t, rw, SetErrorAuthenticationFailed)
				assert.Empty(t, authorizer.records)
				assert.Zero(t, body.reads)
				assert.Empty(t, p.handler.events)
				assert.Empty(t, p.store.marks)
			})
		}
	})

	t.Run("ShouldAcceptRecordWithoutDeliveryMethodAsPushStream", func(t *testing.T) {
		p := newTestPush(t)

		p.x.record.Delivery.Method = ""

		rw, err := p.do(t, p.request(strings.NewReader(p.token(t))))

		require.NoError(t, err)
		assert.Equal(t, http.StatusAccepted, rw.Code)
	})

	t.Run("ShouldUsePushAuthorizerInsteadOfSecret", func(t *testing.T) {
		p := newTestPush(t)

		authorizer := &testPushAuthorizer{}
		p.x.receiver.Config.PushAuthorizer = authorizer

		r := p.request(strings.NewReader(p.token(t)))
		r.Header.Del("Authorization")

		rw, err := p.do(t, r)

		require.NoError(t, err)
		assert.Equal(t, http.StatusAccepted, rw.Code)
		require.Len(t, authorizer.records, 1)
		assert.Same(t, p.x.record, authorizer.records[0])
	})

	t.Run("ShouldCompareAuthorizationInConstantTime", func(t *testing.T) {
		testCases := []struct {
			name     string
			secret   string
			pending  string
			have     []string
			expected int
		}{
			{name: "ShouldAcceptEqual", secret: testPushSecret, have: []string{testPushSecret}, expected: http.StatusAccepted},
			{name: "ShouldRejectMissing", secret: testPushSecret, expected: http.StatusBadRequest},
			{name: "ShouldRejectEmpty", secret: testPushSecret, have: []string{""}, expected: http.StatusBadRequest},
			{name: "ShouldRejectShorter", secret: testPushSecret, have: []string{testPushSecret[:len(testPushSecret)-1]}, expected: http.StatusBadRequest},
			{name: "ShouldRejectLonger", secret: testPushSecret, have: []string{testPushSecret + "Q"}, expected: http.StatusBadRequest},
			{name: "ShouldRejectPrefix", secret: testPushSecret, have: []string{"Bearer "}, expected: http.StatusBadRequest},
			{name: "ShouldRejectWrongValueOfSameLength", secret: testPushSecret, have: []string{"Bearer cHVzaC1zZWNyZXR"}, expected: http.StatusBadRequest},
			{name: "ShouldRejectWrongCase", secret: testPushSecret, have: []string{strings.ToLower(testPushSecret)}, expected: http.StatusBadRequest},
			{name: "ShouldRejectSurroundingSpace", secret: testPushSecret, have: []string{" " + testPushSecret}, expected: http.StatusBadRequest},
			{name: "ShouldRejectSchemeOmitted", secret: testPushSecret, have: []string{strings.TrimPrefix(testPushSecret, "Bearer ")}, expected: http.StatusBadRequest},
			{name: "ShouldRejectRepeatedHeader", secret: testPushSecret, have: []string{testPushSecret, testPushSecret}, expected: http.StatusBadRequest},
			{name: "ShouldRejectMissingWhenRecordHasNoSecret", secret: "", expected: http.StatusBadRequest},
			{name: "ShouldRejectEmptyWhenRecordHasNoSecret", secret: "", have: []string{""}, expected: http.StatusBadRequest},
			{name: "ShouldRejectAnyWhenRecordHasNoSecret", secret: "", have: []string{testPushSecret}, expected: http.StatusBadRequest},
			{name: "ShouldAcceptPendingSecret", secret: testPushSecret, pending: testPendingPushSecret, have: []string{testPendingPushSecret}, expected: http.StatusAccepted},
			{name: "ShouldAcceptSecretWhileOneIsPending", secret: testPushSecret, pending: testPendingPushSecret, have: []string{testPushSecret}, expected: http.StatusAccepted},
			{name: "ShouldAcceptPendingSecretWhenRecordHasNoSecret", secret: "", pending: testPendingPushSecret, have: []string{testPendingPushSecret}, expected: http.StatusAccepted},
			{name: "ShouldRejectWrongValueWhileOneIsPending", secret: testPushSecret, pending: testPendingPushSecret, have: []string{"Bearer wrong"}, expected: http.StatusBadRequest},
			{name: "ShouldRejectBothSecretsJoined", secret: testPushSecret, pending: testPendingPushSecret, have: []string{testPushSecret + testPendingPushSecret}, expected: http.StatusBadRequest},
			{name: "ShouldRejectEmptyWhenOnlyPendingSecret", secret: "", pending: testPendingPushSecret, have: []string{""}, expected: http.StatusBadRequest},
			{name: "ShouldRejectMissingWhenOnlyPendingSecret", secret: "", pending: testPendingPushSecret, expected: http.StatusBadRequest},
			{name: "ShouldRejectEmptyWhileOneIsPending", secret: testPushSecret, pending: testPendingPushSecret, have: []string{""}, expected: http.StatusBadRequest},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				p := newTestPush(t)

				p.x.record.Delivery.AuthorizationHeader = tc.secret
				p.x.record.PendingAuthorizationHeader = tc.pending

				r := p.request(strings.NewReader(p.token(t)))
				r.Header.Del("Authorization")

				for _, value := range tc.have {
					r.Header.Add("Authorization", value)
				}

				rw, err := p.do(t, r)

				require.Equal(t, tc.expected, rw.Code)

				if tc.expected == http.StatusAccepted {
					require.NoError(t, err)
					assert.Len(t, p.handler.events, 1)

					return
				}

				require.ErrorIs(t, err, errPushSecret)
				requireSetError(t, rw, SetErrorAuthenticationFailed)
				assert.Empty(t, p.handler.events)
			})
		}
	})
}

func TestReceiverHandlePushRefusal(t *testing.T) {
	t.Run("ShouldAnswer405WithAllow", func(t *testing.T) {
		for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodDelete, http.MethodOptions} {
			t.Run(method, func(t *testing.T) {
				p := newTestPush(t)

				body := &testBody{Reader: strings.NewReader(p.token(t))}
				r := p.request(body)
				r.Method = method

				// The method is refused before the authorization is looked at.
				r.Header.Del("Authorization")

				rw, err := p.do(t, r)

				require.NoError(t, err)
				assert.Equal(t, http.StatusMethodNotAllowed, rw.Code)
				assert.Equal(t, []string{http.MethodPost}, rw.Header().Values("Allow"))
				assert.Empty(t, rw.Body.Bytes())
				assert.Zero(t, body.reads)
				assert.Empty(t, p.handler.events)
			})
		}
	})

	t.Run("ShouldAnswer413", func(t *testing.T) {
		testCases := []struct {
			name    string
			limit   int64
			size    int
			chunked bool
			reads   bool
		}{
			{name: "ShouldRefuseDeclaredLengthWithoutReading", limit: 64, size: 65},
			{name: "ShouldRefuseChunkedBody", limit: 64, size: 65, chunked: true, reads: true},
			{name: "ShouldRefuseBeyondDefault", size: DefaultMaxRequestBytes + 1, chunked: true, reads: true},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				p := newTestPush(t)

				p.x.receiver.Config.MaxRequestBytes = tc.limit

				body := &testBody{Reader: strings.NewReader(strings.Repeat("a", tc.size))}
				r := p.request(body)

				if tc.chunked {
					r.ContentLength = -1
				} else {
					r.ContentLength = int64(tc.size)
				}

				rw, err := p.do(t, r)

				require.NoError(t, err)
				assert.Equal(t, http.StatusRequestEntityTooLarge, rw.Code)
				assert.Empty(t, rw.Body.Bytes())
				assert.Equal(t, tc.reads, body.reads > 0)
				assert.Empty(t, p.handler.events)
			})
		}

		t.Run("ShouldAcceptBodyOfTheLimit", func(t *testing.T) {
			p := newTestPush(t)

			token := p.token(t)

			p.x.receiver.Config.MaxRequestBytes = int64(len(token))

			r := p.request(strings.NewReader(token))
			r.ContentLength = -1

			rw, err := p.do(t, r)

			require.NoError(t, err)
			assert.Equal(t, http.StatusAccepted, rw.Code)
		})
	})

	t.Run("ShouldAnswer503WhilePending", func(t *testing.T) {
		p := newTestPush(t)

		p.x.record.State = StreamRecordPending
		p.x.record.StreamID = ""

		body := &testBody{Reader: strings.NewReader(p.token(t))}

		rw, err := p.do(t, p.request(body))

		require.Error(t, err)
		assert.Equal(t, http.StatusServiceUnavailable, rw.Code)
		assert.Empty(t, rw.Body.Bytes())
		assert.Zero(t, body.reads)
		assert.Empty(t, p.handler.events)
		assert.Empty(t, p.store.marks)
	})

	t.Run("ShouldRejectUnauthorizedWhilePending", func(t *testing.T) {
		p := newTestPush(t)

		p.x.record.State = StreamRecordPending

		r := p.request(strings.NewReader(p.token(t)))
		r.Header.Set("Authorization", "Bearer wrong")

		rw, err := p.do(t, r)

		require.ErrorIs(t, err, errPushSecret)
		requireSetError(t, rw, SetErrorAuthenticationFailed)
	})

	t.Run("ShouldAnswer503", func(t *testing.T) {
		cause := errors.New("database is down: eyJhbGciOiJFUzI1NiJ9")

		testCases := []struct {
			name       string
			setup      func(p *testPush)
			dispatched int
			is         error
		}{
			{
				name:       "ShouldAnswerHandlerError",
				setup:      func(p *testPush) { p.handler.err = cause },
				dispatched: 1,
				is:         cause,
			},
			{
				name:  "ShouldAnswerHandlerNotConfigured",
				setup: func(p *testPush) { p.x.receiver.Config.Handler = nil },
			},
			{
				name:  "ShouldAnswerLookupError",
				setup: func(p *testPush) { p.store.knownErr = cause },
				is:    cause,
			},
			{
				name:       "ShouldAnswerMarkError",
				setup:      func(p *testPush) { p.store.markErr = cause },
				dispatched: 1,
				is:         cause,
			},
			{
				// Only the EventHandler reports a fault of the SET.
				name: "ShouldAnswerLookupErrorWrappingSetError",
				setup: func(p *testPush) {
					p.store.knownErr = fmt.Errorf("lookup: %w", &SetError{Code: SetErrorInvalidRequest})
				},
			},
			{
				name:       "ShouldAnswerMarkErrorWrappingSetError",
				setup:      func(p *testPush) { p.store.markErr = fmt.Errorf("mark: %w", &SetError{Code: SetErrorInvalidRequest}) },
				dispatched: 1,
			},
			{
				name:  "ShouldAnswerStrategyNotConfigured",
				setup: func(p *testPush) { p.x.receiver.Config.Strategy = nil },
			},
			{
				name:  "ShouldAnswerKeysUnavailable",
				setup: func(p *testPush) { p.x.server.status.Store(http.StatusInternalServerError) },
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				p := newTestPush(t)

				tc.setup(p)

				rw, err := p.do(t, p.request(strings.NewReader(p.token(t))))

				require.Error(t, err)

				if tc.is != nil {
					assert.ErrorIs(t, err, tc.is)
				}

				assert.Equal(t, http.StatusServiceUnavailable, rw.Code)
				assert.Empty(t, rw.Body.Bytes())
				assert.Empty(t, rw.Header().Get("Content-Type"))
				assert.Len(t, p.handler.events, tc.dispatched)
				assert.Empty(t, p.store.marks)
			})
		}

		t.Run("ShouldAnswerNilRecord", func(t *testing.T) {
			p := newTestPush(t)

			rw := httptest.NewRecorder()

			err := p.x.receiver.HandlePush(t.Context(), rw, p.request(strings.NewReader(p.token(t))), nil)

			require.Error(t, err)
			assert.Equal(t, http.StatusServiceUnavailable, rw.Code)
			assert.Empty(t, p.handler.events)
		})

		t.Run("ShouldAnswerNilSetErrorOfDispatch", func(t *testing.T) {
			p := newTestPush(t)

			var serr *SetError

			p.handler.err = serr

			rw, err := p.do(t, p.request(strings.NewReader(p.token(t))))

			require.Error(t, err)
			assert.Equal(t, http.StatusServiceUnavailable, rw.Code)
			assert.Empty(t, p.store.marks)
		})
	})

	t.Run("ShouldRejectWrongContentType", func(t *testing.T) {
		testCases := []struct {
			name string
			have []string
		}{
			{name: "ShouldRejectMissing"},
			{name: "ShouldRejectEmpty", have: []string{""}},
			{name: "ShouldRejectJSON", have: []string{"application/json"}},
			{name: "ShouldRejectJWT", have: []string{"application/jwt"}},
			{name: "ShouldRejectSuffixOnly", have: []string{"secevent+jwt"}},
			{name: "ShouldRejectText", have: []string{"text/plain"}},
			{name: "ShouldRejectMalformed", have: []string{"application/secevent+jwt; charset"}},
			{name: "ShouldRejectRepeated", have: []string{"application/secevent+jwt", "application/json"}},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				p := newTestPush(t)

				body := &testBody{Reader: strings.NewReader(p.token(t))}
				r := p.request(body)
				r.Header.Del("Content-Type")

				for _, value := range tc.have {
					r.Header.Add("Content-Type", value)
				}

				rw, err := p.do(t, r)

				require.NoError(t, err)
				requireSetError(t, rw, SetErrorInvalidRequest)
				assert.Zero(t, body.reads)
				assert.Empty(t, p.handler.events)
			})
		}
	})

	t.Run("ShouldNotEchoTokenContentInDescription", func(t *testing.T) {
		const marker = "bWFya2Vy-756E69717565"

		testCases := []struct {
			name     string
			setup    func(t *testing.T, p *testPush, r *http.Request) string
			expected int
		}{
			{
				name:     "ShouldNotEchoBody",
				setup:    func(*testing.T, *testPush, *http.Request) string { return marker },
				expected: http.StatusBadRequest,
			},
			{
				name:     "ShouldNotEchoMalformedSegments",
				setup:    func(*testing.T, *testPush, *http.Request) string { return marker + "." + marker + "." + marker },
				expected: http.StatusBadRequest,
			},
			{
				name: "ShouldNotEchoIssuer",
				setup: func(t *testing.T, p *testPush, _ *http.Request) string {
					claims := p.x.claims()
					claims["iss"] = "https://" + marker + ".example.com"

					return p.x.set().sign(t, claims)
				},
				expected: http.StatusBadRequest,
			},
			{
				name: "ShouldNotEchoAudience",
				setup: func(t *testing.T, p *testPush, _ *http.Request) string {
					claims := p.x.claims()
					claims["aud"] = marker

					return p.x.set().sign(t, claims)
				},
				expected: http.StatusBadRequest,
			},
			{
				name: "ShouldNotEchoKeyID",
				setup: func(t *testing.T, p *testPush, _ *http.Request) string {
					set := p.x.set()
					set.kid = marker

					return set.sign(t, p.x.claims())
				},
				expected: http.StatusBadRequest,
			},
			{
				name: "ShouldNotEchoType",
				setup: func(t *testing.T, p *testPush, _ *http.Request) string {
					set := p.x.set()
					set.typ = marker

					return set.sign(t, p.x.claims())
				},
				expected: http.StatusBadRequest,
			},
			{
				name: "ShouldNotEchoClaim",
				setup: func(t *testing.T, p *testPush, _ *http.Request) string {
					claims := p.x.claims()
					claims["sub"] = marker

					return p.x.set().sign(t, claims)
				},
				expected: http.StatusBadRequest,
			},
			{
				name: "ShouldNotEchoJTIOfUnmarkedSET",
				setup: func(t *testing.T, p *testPush, _ *http.Request) string {
					claims := p.x.claims()
					claims["jti"] = marker

					p.store.markErr = errors.New("mark failed")

					return p.x.set().sign(t, claims)
				},
				expected: http.StatusServiceUnavailable,
			},
			{
				name: "ShouldNotEchoHandlerError",
				setup: func(t *testing.T, p *testPush, _ *http.Request) string {
					p.handler.err = errors.New(marker)

					return p.token(t)
				},
				expected: http.StatusServiceUnavailable,
			},
			{
				name: "ShouldNotEchoAuthorization",
				setup: func(t *testing.T, p *testPush, r *http.Request) string {
					r.Header.Set("Authorization", "Bearer "+marker)

					return p.token(t)
				},
				expected: http.StatusBadRequest,
			},
			{
				name: "ShouldNotEchoContentType",
				setup: func(t *testing.T, p *testPush, r *http.Request) string {
					r.Header.Set("Content-Type", "application/"+marker)

					return p.token(t)
				},
				expected: http.StatusBadRequest,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				p := newTestPush(t)

				r := p.request(nil)
				token := tc.setup(t, p, r)

				r.Body = io.NopCloser(strings.NewReader(token))
				r.ContentLength = int64(len(token))

				rw, _ := p.do(t, r)

				require.Equal(t, tc.expected, rw.Code)
				assert.NotContains(t, rw.Body.String(), marker)
				assert.NotContains(t, rw.Body.String(), "eyJ")

				for name, values := range rw.Header() {
					assert.NotContains(t, strings.Join(values, ","), marker, name)
				}
			})
		}
	})
}
