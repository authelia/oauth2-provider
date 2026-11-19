// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
)

const testPollPath = "/poll"

func testPollRecord(server *testManagementServer) *StreamRecord {
	return &StreamRecord{
		Issuer:   server.URL,
		StreamID: "stream-1",
		Audience: []string{"https://rx.example.com"},
		Delivery: oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPoll, EndpointURL: server.URL + testPollPath},
		Status:   oauth2.SSFStreamStatusEnabled,
		State:    StreamRecordActive,
	}
}

// testDeadlineAuthorizer records the time left of each request it authorizes.
type testDeadlineAuthorizer struct {
	mu   sync.Mutex
	left []time.Duration
}

func (a *testDeadlineAuthorizer) AuthorizeRequest(ctx context.Context, _, _ string, _ *http.Request) (err error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if deadline, ok := ctx.Deadline(); ok {
		a.left = append(a.left, time.Until(deadline))
	} else {
		a.left = append(a.left, -1)
	}

	return nil
}

func TestReceiverRequestPoll(t *testing.T) {
	answer := func(body string) func(w http.ResponseWriter, _ *http.Request, _ int) {
		return func(w http.ResponseWriter, _ *http.Request, _ int) {
			writeTestJSON(w, []byte(body))
		}
	}

	t.Run("ShouldSendEmptyObjectByDefault", func(t *testing.T) {
		server := newTestManagementServer(t, answer(`{"sets":{}}`))
		authorizer := &testAuthorizer{}
		receiver := testTransmitterReceiver(server, authorizer)

		response, err := receiver.requestPoll(t.Context(), testPollRecord(server), PollRequest{})

		require.NoError(t, err)
		assert.Empty(t, response.sets)
		assert.False(t, response.moreAvailable)

		require.Len(t, server.received(), 1)

		request := server.received()[0]

		// RFC 8936 Section 2.2, Figure 2.
		assert.Equal(t, http.MethodPost, request.method)
		assert.Equal(t, testPollPath, request.path)
		assert.Empty(t, request.query)
		assert.Equal(t, "application/json", request.contentType)
		assert.Equal(t, "application/json", request.accept)
		assert.Equal(t, "Bearer "+testTransmitterToken, request.authorization)
		assert.Empty(t, request.language)
		assert.Equal(t, `{}`, request.body)

		assert.Equal(t, []string{server.URL}, authorizer.issuers)
		assert.Equal(t, []string{oauth2.ScopeSSFManage}, authorizer.scopes)
	})

	t.Run("ShouldSendAckOnlyWithMaxEventsZero", func(t *testing.T) {
		server := newTestManagementServer(t, answer(`{"sets":{}}`))
		receiver := testTransmitterReceiver(server, &testAuthorizer{})

		zero := 0

		_, err := receiver.requestPoll(t.Context(), testPollRecord(server), PollRequest{
			MaxEvents:         &zero,
			ReturnImmediately: true,
			Ack:               []string{"4d3559ec67504aaba65d40b0363faad8", "3d0c3cf797584bd193bd0fb1bd4e7d30"},
		})

		require.NoError(t, err)
		require.Len(t, server.received(), 1)

		// RFC 8936 Section 2.4.2, Figure 3.
		assert.Equal(t, `{"maxEvents":0,"returnImmediately":true,"ack":["4d3559ec67504aaba65d40b0363faad8","3d0c3cf797584bd193bd0fb1bd4e7d30"]}`, server.received()[0].body)
		assert.Empty(t, server.received()[0].language)
	})

	t.Run("ShouldSendMaxEvents", func(t *testing.T) {
		server := newTestManagementServer(t, answer(`{"sets":{}}`))
		receiver := testTransmitterReceiver(server, &testAuthorizer{})

		five := 5

		_, err := receiver.requestPoll(t.Context(), testPollRecord(server), PollRequest{MaxEvents: &five})

		require.NoError(t, err)
		require.Len(t, server.received(), 1)
		assert.Equal(t, `{"maxEvents":5}`, server.received()[0].body)
	})

	t.Run("ShouldSendContentLanguageWithSetErrs", func(t *testing.T) {
		server := newTestManagementServer(t, answer(`{"sets":{}}`))
		receiver := testTransmitterReceiver(server, &testAuthorizer{})

		_, err := receiver.requestPoll(t.Context(), testPollRecord(server), PollRequest{
			ReturnImmediately: true,
			Ack:               []string{"3d0c3cf797584bd193bd0fb1bd4e7d30"},
			SetErrs: map[string]oauth2.SSFPollSetError{
				"4d3559ec67504aaba65d40b0363faad8": {Err: SetErrorAuthenticationFailed, Description: "The SET could not be authenticated"},
			},
		})

		require.NoError(t, err)
		require.Len(t, server.received(), 1)

		request := server.received()[0]

		// RFC 8936 Section 2.4.4, Figure 5, Section 2.6.
		assert.Equal(t, "en", request.language)
		assert.Equal(t, "application/json", request.contentType)
		assert.Equal(t, `{"returnImmediately":true,"ack":["3d0c3cf797584bd193bd0fb1bd4e7d30"],"setErrs":{"4d3559ec67504aaba65d40b0363faad8":{"err":"authentication_failed","description":"The SET could not be authenticated"}}}`, request.body)
	})

	t.Run("ShouldOmitEmptyAckAndSetErrs", func(t *testing.T) {
		server := newTestManagementServer(t, answer(`{"sets":{}}`))
		receiver := testTransmitterReceiver(server, &testAuthorizer{})

		_, err := receiver.requestPoll(t.Context(), testPollRecord(server), PollRequest{Ack: []string{}, SetErrs: map[string]oauth2.SSFPollSetError{}})

		require.NoError(t, err)
		require.Len(t, server.received(), 1)
		assert.Equal(t, `{}`, server.received()[0].body)
		assert.Empty(t, server.received()[0].language)
	})

	t.Run("ShouldReturnSetsInTheOrderOfTheResponse", func(t *testing.T) {
		server := newTestManagementServer(t, answer(`{"unknown":[1],"moreAvailable":true,"sets":{"c":"t.c.s","a":"t.a.s","b":"t.b.s"}}`))
		receiver := testTransmitterReceiver(server, &testAuthorizer{})

		response, err := receiver.requestPoll(t.Context(), testPollRecord(server), PollRequest{})

		require.NoError(t, err)
		assert.Equal(t, []polledSet{{name: "c", token: "t.c.s"}, {name: "a", token: "t.a.s"}, {name: "b", token: "t.b.s"}}, response.sets)
		assert.True(t, response.moreAvailable)
	})

	t.Run("ShouldRejectNonObjectSets", func(t *testing.T) {
		testCases := []struct {
			name string
			body string
		}{
			{"ShouldRejectMissingSets", `{}`},
			{"ShouldRejectNullSets", `{"sets":null}`},
			{"ShouldRejectArraySets", `{"sets":["a.b.c"]}`},
			{"ShouldRejectStringSets", `{"sets":"a.b.c"}`},
			{"ShouldRejectNumberSets", `{"sets":1}`},
			{"ShouldRejectObjectSET", `{"sets":{"a":{"jwt":"a.b.c"}}}`},
			{"ShouldRejectNullSET", `{"sets":{"a":null}}`},
			{"ShouldRejectNumberSET", `{"sets":{"a":"a.b.c","b":1}}`},
			{"ShouldRejectArrayBody", `[{"sets":{}}]`},
			{"ShouldRejectTrailingData", `{"sets":{}}{}`},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				server := newTestManagementServer(t, answer(tc.body))
				receiver := testTransmitterReceiver(server, &testAuthorizer{})

				response, err := receiver.requestPoll(t.Context(), testPollRecord(server), PollRequest{})

				require.ErrorIs(t, err, ErrPollResponse)
				assert.Nil(t, response)
				assert.NotContains(t, err.Error(), "a.b.c")
			})
		}
	})

	t.Run("ShouldRejectResponseThatIsNotJSON", func(t *testing.T) {
		server := newTestManagementServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
			w.Header().Set("Content-Type", "text/plain")

			_, _ = w.Write([]byte(`{"sets":{}}`))
		})

		receiver := testTransmitterReceiver(server, &testAuthorizer{})

		_, err := receiver.requestPoll(t.Context(), testPollRecord(server), PollRequest{})

		require.ErrorIs(t, err, ErrPollResponse)
	})

	t.Run("ShouldRejectRepeatedMemberNames", func(t *testing.T) {
		testCases := []struct {
			name string
			body string
		}{
			{"ShouldRejectRepeatedSets", `{"sets":{},"sets":{"a":"a.b.c"}}`},
			{"ShouldRejectRepeatedMoreAvailable", `{"sets":{},"moreAvailable":true,"moreAvailable":false}`},
			{"ShouldRejectRepeatedJTI", `{"sets":{"a":"a.b.c","a":"d.e.f"}}`},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				server := newTestManagementServer(t, answer(tc.body))
				receiver := testTransmitterReceiver(server, &testAuthorizer{})

				response, err := receiver.requestPoll(t.Context(), testPollRecord(server), PollRequest{})

				require.ErrorIs(t, err, ErrPollResponse)
				assert.Nil(t, response)
			})
		}
	})

	t.Run("ShouldTreatMissingMoreAvailableAsFalse", func(t *testing.T) {
		testCases := []struct {
			name     string
			body     string
			expected bool
			err      bool
		}{
			{name: "ShouldTreatMissingAsFalse", body: `{"sets":{}}`},
			{name: "ShouldTreatNullAsFalse", body: `{"sets":{},"moreAvailable":null}`},
			{name: "ShouldReadFalse", body: `{"sets":{},"moreAvailable":false}`},
			{name: "ShouldReadTrue", body: `{"sets":{},"moreAvailable":true}`, expected: true},
			{name: "ShouldRejectString", body: `{"sets":{},"moreAvailable":"true"}`, err: true},
			{name: "ShouldRejectNumber", body: `{"sets":{},"moreAvailable":1}`, err: true},
			{name: "ShouldRejectObject", body: `{"sets":{},"moreAvailable":{}}`, err: true},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				server := newTestManagementServer(t, answer(tc.body))
				receiver := testTransmitterReceiver(server, &testAuthorizer{})

				response, err := receiver.requestPoll(t.Context(), testPollRecord(server), PollRequest{})

				if tc.err {
					require.ErrorIs(t, err, ErrPollResponse)
					assert.Nil(t, response)

					return
				}

				require.NoError(t, err)
				assert.Equal(t, tc.expected, response.moreAvailable)
			})
		}
	})

	t.Run("ShouldMapStatuses", func(t *testing.T) {
		testCases := []struct {
			name       string
			status     int
			retryAfter string
			is         error
			delay      time.Duration
		}{
			{name: "ShouldMap401", status: http.StatusUnauthorized, is: ErrTransmitterUnauthorized},
			{name: "ShouldMap403", status: http.StatusForbidden, is: ErrTransmitterForbidden},
			{name: "ShouldMap404", status: http.StatusNotFound, is: ErrStreamNotFound},
			{name: "ShouldMap409", status: http.StatusConflict, is: ErrStreamConflict},
			{name: "ShouldMap429", status: http.StatusTooManyRequests, retryAfter: "7", is: ErrTransmitterThrottled, delay: 7 * time.Second},
			{name: "ShouldMap400", status: http.StatusBadRequest},
			{name: "ShouldMap500", status: http.StatusInternalServerError},
			{name: "ShouldMap503", status: http.StatusServiceUnavailable, retryAfter: "3", delay: 3 * time.Second},
			{name: "ShouldMap202", status: http.StatusAccepted},
			{name: "ShouldMap204", status: http.StatusNoContent},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				server := newTestManagementServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
					if tc.retryAfter != "" {
						w.Header().Set("Retry-After", tc.retryAfter)
					}

					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(tc.status)

					if tc.status != http.StatusNoContent {
						_, _ = w.Write([]byte(`{"sets":{"a":"a.b.c"}}`))
					}
				})

				receiver := testTransmitterReceiver(server, &testAuthorizer{})

				response, err := receiver.requestPoll(t.Context(), testPollRecord(server), PollRequest{Ack: []string{"x"}})

				assert.Nil(t, response)

				var terr *TransmitterError

				require.ErrorAs(t, err, &terr)
				assert.Equal(t, tc.status, terr.Status)
				assert.Equal(t, tc.delay, terr.RetryAfter)

				if tc.is != nil {
					require.ErrorIs(t, err, tc.is)
				}

				assert.NotErrorIs(t, err, ErrStreamUpdatePending)

				// A POST is not sent again.
				assert.Len(t, server.received(), 1)
			})
		}
	})

	t.Run("ShouldUseTheLongPollTimeout", func(t *testing.T) {
		testCases := []struct {
			name     string
			timeout  time.Duration
			request  PollRequest
			expected time.Duration
		}{
			{name: "ShouldUseTheDefaultForLongPoll", expected: DefaultLongPollTimeout},
			{name: "ShouldUseTheConfiguredForLongPoll", timeout: 90 * time.Second, expected: 90 * time.Second},
			{name: "ShouldUseTheFetchTimeoutForShortPoll", timeout: 90 * time.Second, request: PollRequest{ReturnImmediately: true}, expected: oauth2.FetchTimeout},
			{name: "ShouldUseTheFetchTimeoutForShortPollByDefault", request: PollRequest{ReturnImmediately: true}, expected: oauth2.FetchTimeout},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				server := newTestManagementServer(t, answer(`{"sets":{}}`))
				authorizer := &testDeadlineAuthorizer{}
				receiver := testTransmitterReceiver(server, authorizer)

				receiver.Config.LongPollTimeout = tc.timeout

				_, err := receiver.requestPoll(t.Context(), testPollRecord(server), tc.request)

				require.NoError(t, err)
				require.Len(t, authorizer.left, 1)
				assert.InDelta(t, tc.expected.Seconds(), authorizer.left[0].Seconds(), 5)
			})
		}

		assert.Greater(t, DefaultLongPollTimeout, oauth2.FetchTimeout)
	})

	t.Run("ShouldEndTheLongPollAtTheTimeout", func(t *testing.T) {
		release := make(chan struct{})

		server := newTestManagementServer(t, func(w http.ResponseWriter, r *http.Request, _ int) {
			select {
			case <-release:
			case <-r.Context().Done():
			}

			writeTestJSON(w, []byte(`{"sets":{}}`))
		})

		t.Cleanup(func() { close(release) })

		receiver := testTransmitterReceiver(server, &testAuthorizer{})

		receiver.Config.LongPollTimeout = 50 * time.Millisecond

		response, err := receiver.requestPoll(t.Context(), testPollRecord(server), PollRequest{Ack: []string{"x"}})

		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Nil(t, response)

		// The Transmitter may have the acknowledgements of a poll request without a response.
		assert.True(t, isUnconfirmed(err))
		assert.Len(t, server.received(), 1)
	})

	t.Run("ShouldRefuseBeforeAnyRequest", func(t *testing.T) {
		negative := -1

		testCases := []struct {
			name    string
			record  func(record *StreamRecord) *StreamRecord
			request PollRequest
			is      error
		}{
			{name: "ShouldRefuseNoRecord", record: func(*StreamRecord) *StreamRecord { return nil }, is: ErrStreamRequest},
			{
				name: "ShouldRefusePushStream",
				record: func(record *StreamRecord) *StreamRecord {
					record.Delivery.Method = oauth2.SSFDeliveryMethodPush

					return record
				},
				is: ErrStreamRequest,
			},
			{
				name: "ShouldRefuseStreamWithoutMethod",
				record: func(record *StreamRecord) *StreamRecord {
					record.Delivery.Method = ""

					return record
				},
				is: ErrStreamRequest,
			},
			{
				name: "ShouldRefuseEndpointWithoutTLS",
				record: func(record *StreamRecord) *StreamRecord {
					record.Delivery.EndpointURL = "http://tx.example.com/poll"

					return record
				},
				is: ErrEndpointNotHTTPS,
			},
			{
				name: "ShouldRefuseNoEndpoint",
				record: func(record *StreamRecord) *StreamRecord {
					record.Delivery.EndpointURL = ""

					return record
				},
				is: ErrEndpointNotSupported,
			},
			{name: "ShouldRefuseNegativeMaxEvents", request: PollRequest{MaxEvents: &negative}, is: ErrStreamRequest},
			{name: "ShouldRefuseEmptyAck", request: PollRequest{Ack: []string{"a", ""}}, is: ErrStreamRequest},
			{name: "ShouldRefuseSetErrWithoutJTI", request: PollRequest{SetErrs: map[string]oauth2.SSFPollSetError{"": {Err: SetErrorInvalidRequest}}}, is: ErrStreamRequest},
			{name: "ShouldRefuseSetErrWithoutErr", request: PollRequest{SetErrs: map[string]oauth2.SSFPollSetError{"a": {Description: "x"}}}, is: ErrStreamRequest},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				server := newTestManagementServer(t, answer(`{"sets":{}}`))
				receiver := testTransmitterReceiver(server, &testAuthorizer{})

				record := testPollRecord(server)

				if tc.record != nil {
					record = tc.record(record)
				}

				response, err := receiver.requestPoll(t.Context(), record, tc.request)

				require.ErrorIs(t, err, tc.is)
				assert.Nil(t, response)
				assert.Empty(t, server.received())
			})
		}
	})
}
