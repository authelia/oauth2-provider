// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/ssfreceiver"
)

const (
	testStreamToken    = "c3RyZWFtLXRva2Vu"
	testStreamAudience = "https://rx.example.com"
	testStreamsPath    = "/streams"
	testStatusPath     = "/status"
	testVerifyPath     = "/verify"
	testAddPath        = "/subjects:add"
	testRemovePath     = "/subjects:remove"
	testEventType2     = "urn:example:secevent:events:type_2"
	testEventType3     = "urn:example:secevent:events:type_3"
	testEventType4     = "urn:example:secevent:events:type_4"
)

type testStreamCall struct {
	path          string
	method        string
	query         string
	authorization string
	contentType   string
	body          string

	// done is closed when the client gives up the request.
	done <-chan struct{}
}

// testStreamTransmitter is a Transmitter which serves its metadata and records the requests to its stream management
// endpoints, which the respond function answers.
type testStreamTransmitter struct {
	*httptest.Server

	mu       sync.Mutex
	calls    []testStreamCall
	scopes   []string
	metadata map[string]any
	respond  func(w http.ResponseWriter, call testStreamCall)
}

func newTestStreamTransmitter(t *testing.T) *testStreamTransmitter {
	t.Helper()

	tx := &testStreamTransmitter{}

	tx.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/ssf-configuration":
			members := map[string]any{
				"spec_version":           "1_0",
				"issuer":                 tx.URL,
				"jwks_uri":               tx.URL + "/jwks.json",
				"configuration_endpoint": tx.URL + testStreamsPath,
				"status_endpoint":        tx.URL + testStatusPath,
				"verification_endpoint":  tx.URL + testVerifyPath,
			}

			tx.mu.Lock()

			for name, value := range tx.metadata {
				if value == nil {
					delete(members, name)
				} else {
					members[name] = value
				}
			}

			tx.mu.Unlock()

			writeTestStream(w, http.StatusOK, members)
		case testStreamsPath, testStatusPath, testVerifyPath, testAddPath, testRemovePath:
			body, _ := io.ReadAll(r.Body)

			call := testStreamCall{
				path:          r.URL.Path,
				method:        r.Method,
				query:         r.URL.RawQuery,
				authorization: r.Header.Get("Authorization"),
				contentType:   r.Header.Get("Content-Type"),
				body:          string(body),
				done:          r.Context().Done(),
			}

			tx.mu.Lock()
			tx.calls = append(tx.calls, call)
			respond := tx.respond
			tx.mu.Unlock()

			if respond == nil {
				w.WriteHeader(http.StatusInternalServerError)

				return
			}

			respond(w, call)
		default:
			http.NotFound(w, r)
		}
	}))

	t.Cleanup(tx.Close)

	return tx
}

func (tx *testStreamTransmitter) on(respond func(w http.ResponseWriter, call testStreamCall)) {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	tx.respond = respond
}

// answer responds to every request with the status code and the JSON value.
func (tx *testStreamTransmitter) answer(status int, value any) {
	tx.on(func(w http.ResponseWriter, _ testStreamCall) {
		writeTestStream(w, status, value)
	})
}

func (tx *testStreamTransmitter) received() []testStreamCall {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	return append([]testStreamCall(nil), tx.calls...)
}

func (tx *testStreamTransmitter) requestedScopes() []string {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	return append([]string(nil), tx.scopes...)
}

// receiver returns a Receiver over a new store which authorizes with a bearer token.
func (tx *testStreamTransmitter) receiver(st testStore) *ssfreceiver.Receiver {
	client := &retryablehttp.Client{HTTPClient: tx.Client(), CheckRetry: retryablehttp.DefaultRetryPolicy, Backoff: retryablehttp.DefaultBackoff}

	return &ssfreceiver.Receiver{
		Store: st.new(nil),
		Config: ssfreceiver.Config{
			HTTPClient:             client,
			SpecialUseAddressGuard: testLoopbackGuard{},
			Authorizer: &ssfreceiver.BearerAuthorizer{Token: func(_ context.Context, _, scope string) (token string, err error) {
				tx.mu.Lock()
				defer tx.mu.Unlock()

				tx.scopes = append(tx.scopes, scope)

				return testStreamToken, nil
			}},
		},
	}
}

// configuration returns the configuration of a push stream of the Transmitter with the extra members, where a nil
// one is absent.
func (tx *testStreamTransmitter) configuration(extra map[string]any) map[string]any {
	members := map[string]any{
		"stream_id":        testStreamID,
		"iss":              tx.URL,
		"aud":              []string{testStreamAudience},
		"delivery":         map[string]any{"method": oauth2.SSFDeliveryMethodPush, "endpoint_url": testPushURL},
		"events_supported": []string{testEventType2, testEventType3},
		"events_requested": []string{testEventType2, testEventType3, testEventType4},
		"events_delivered": []string{testEventType2, testEventType3},
	}

	for name, value := range extra {
		if value == nil {
			delete(members, name)
		} else {
			members[name] = value
		}
	}

	return members
}

func (tx *testStreamTransmitter) pollDelivery() map[string]any {
	return map[string]any{"method": oauth2.SSFDeliveryMethodPoll, "endpoint_url": tx.URL + "/poll"}
}

func (tx *testStreamTransmitter) pushRequest() ssfreceiver.CreateStreamRequest {
	return ssfreceiver.CreateStreamRequest{
		Issuer:          tx.URL,
		Audience:        []string{testStreamAudience},
		Delivery:        oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPush, EndpointURL: testPushURL, AuthorizationHeader: testPushSecret},
		EventsRequested: []string{testEventType2, testEventType3, testEventType4},
		Description:     "Stream for Receiver A",
	}
}

func (tx *testStreamTransmitter) pollRequest() ssfreceiver.CreateStreamRequest {
	request := tx.pushRequest()

	request.Delivery = oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPoll}

	return request
}

// testContextStore is a store which, as one over a database does, deletes nothing once the context is done.
type testContextStore struct {
	ssfreceiver.Storage
}

func (s testContextStore) UpdateSSFReceiverStream(ctx context.Context, issuer, streamID string, record *ssfreceiver.StreamRecord) (err error) {
	if err = ctx.Err(); err != nil {
		return err
	}

	return s.Storage.UpdateSSFReceiverStream(ctx, issuer, streamID, record)
}

func (s testContextStore) SetSSFReceiverStreamPendingAuthorizationHeader(ctx context.Context, issuer, streamID, header string) (err error) {
	if err = ctx.Err(); err != nil {
		return err
	}

	return s.Storage.SetSSFReceiverStreamPendingAuthorizationHeader(ctx, issuer, streamID, header)
}

func (s testContextStore) DeleteSSFReceiverStream(ctx context.Context, issuer, streamID string) (err error) {
	if err = ctx.Err(); err != nil {
		return err
	}

	return s.Storage.DeleteSSFReceiverStream(ctx, issuer, streamID)
}

// cancelAfterResponse returns a context which is cancelled once the Receiver has the whole response of a request to
// a stream management endpoint, as when the caller gives up after the Transmitter processed the request. The store of
// the Receiver then stores nothing once a context is done.
func (tx *testStreamTransmitter) cancelAfterResponse(t *testing.T, receiver *ssfreceiver.Receiver) (ctx context.Context) {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())

	t.Cleanup(cancel)

	receiver.Config.HTTPClient.ResponseLogHook = func(_ retryablehttp.Logger, response *http.Response) {
		if response.Request.URL.Path == "/.well-known/ssf-configuration" {
			return
		}

		body, _ := io.ReadAll(response.Body)

		_ = response.Body.Close()

		response.Body = io.NopCloser(bytes.NewReader(body))

		cancel()
	}

	receiver.Store = testContextStore{Storage: receiver.Store}

	return ctx
}

func writeTestStream(w http.ResponseWriter, status int, value any) {
	if value == nil {
		w.WriteHeader(status)

		return
	}

	data, _ := json.Marshal(value)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_, _ = w.Write(data)
}

func requireNoStreamRecords(t *testing.T, store ssfreceiver.Storage, issuer string) {
	t.Helper()

	records, err := store.ListSSFReceiverStreams(t.Context(), issuer)
	require.NoError(t, err)

	assert.Empty(t, records)
}

func TestStreamConfiguration(t *testing.T) {
	testCases := []struct {
		name     string
		have     string
		expected *ssfreceiver.StreamConfiguration
		err      string
	}{
		{
			name: "ShouldParseAudienceAsString",
			have: `{"stream_id":"abc","iss":"https://tx.example.com","aud":"https://rx.example.com","delivery":{"method":"urn:ietf:rfc:8935","endpoint_url":"https://rx.example.com/push"},"events_delivered":[]}`,
			expected: &ssfreceiver.StreamConfiguration{
				StreamID:        "abc",
				Issuer:          "https://tx.example.com",
				Audience:        []string{"https://rx.example.com"},
				Delivery:        oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPush, EndpointURL: "https://rx.example.com/push"},
				EventsDelivered: []string{},
			},
		},
		{
			name: "ShouldParseAudienceAsArray",
			have: `{"aud":["https://rx.example.com/web","https://rx.example.com/mobile"]}`,
			expected: &ssfreceiver.StreamConfiguration{
				Audience: []string{"https://rx.example.com/web", "https://rx.example.com/mobile"},
			},
		},
		{
			name: "ShouldParseEveryMember",
			have: `{"stream_id":"abc","iss":"https://tx.example.com","aud":["a"],"events_supported":["1","2"],"events_requested":["2","3"],"events_delivered":["2"],"delivery":{"method":"urn:ietf:rfc:8936","endpoint_url":"https://tx.example.com/poll"},"min_verification_interval":60,"description":"d","inactivity_timeout":3600}`,
			expected: &ssfreceiver.StreamConfiguration{
				StreamID:                "abc",
				Issuer:                  "https://tx.example.com",
				Audience:                []string{"a"},
				EventsSupported:         []string{"1", "2"},
				EventsRequested:         []string{"2", "3"},
				EventsDelivered:         []string{"2"},
				Delivery:                oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPoll, EndpointURL: "https://tx.example.com/poll"},
				MinVerificationInterval: 60,
				Description:             "d",
				InactivityTimeout:       3600,
			},
		},
		{
			name:     "ShouldIgnoreUnknownMembers",
			have:     `{"stream_id":"abc","unknown":{"a":1},"delivery":{"method":"urn:ietf:rfc:8935","other":[1]}}`,
			expected: &ssfreceiver.StreamConfiguration{StreamID: "abc", Delivery: oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPush}},
		},
		{
			name:     "ShouldTreatNullAsAbsent",
			have:     `{"stream_id":"abc","aud":null,"events_delivered":null,"description":null}`,
			expected: &ssfreceiver.StreamConfiguration{StreamID: "abc"},
		},
		{
			name:     "ShouldNotKeepAnEchoedAuthorizationHeader",
			have:     `{"delivery":{"method":"urn:ietf:rfc:8935","authorization_header":"Bearer echoed"}}`,
			expected: &ssfreceiver.StreamConfiguration{Delivery: oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPush}},
		},
		{name: "ShouldRefuseRepeatedMember", have: `{"iss":"https://tx.example.com","iss":"https://other.example.com"}`, err: "not a JSON object"},
		{name: "ShouldRefuseRepeatedDeliveryMember", have: `{"delivery":{"method":"a","method":"b"}}`, err: "'delivery'"},
		{name: "ShouldRefuseArray", have: `[]`, err: "not a JSON object"},
		{name: "ShouldRefuseStreamIDNumber", have: `{"stream_id":1}`, err: "'stream_id'"},
		{name: "ShouldRefuseIssuerArray", have: `{"iss":["https://tx.example.com"]}`, err: "'iss'"},
		{name: "ShouldRefuseAudienceNumber", have: `{"aud":1}`, err: "'aud'"},
		{name: "ShouldRefuseAudienceWithNumber", have: `{"aud":["a",1]}`, err: "'aud'"},
		{name: "ShouldRefuseAudienceWithNull", have: `{"aud":[null]}`, err: "'aud'"},
		{name: "ShouldRefuseEventsDeliveredString", have: `{"events_delivered":"a"}`, err: "'events_delivered'"},
		{name: "ShouldRefuseDeliveryString", have: `{"delivery":"urn:ietf:rfc:8935"}`, err: "'delivery'"},
		{name: "ShouldRefuseDeliveryMethodNumber", have: `{"delivery":{"method":1}}`, err: "'delivery'"},
		{name: "ShouldRefuseDeliveryEndpointNumber", have: `{"delivery":{"method":"a","endpoint_url":1}}`, err: "'delivery'"},
		{name: "ShouldRefuseIntervalString", have: `{"min_verification_interval":"60"}`, err: "'min_verification_interval'"},
		{name: "ShouldRefuseIntervalFraction", have: `{"min_verification_interval":1.5}`, err: "'min_verification_interval'"},
		{name: "ShouldRefuseNegativeTimeout", have: `{"inactivity_timeout":-1}`, err: "'inactivity_timeout'"},
		{name: "ShouldRefuseDescriptionNumber", have: `{"description":1}`, err: "'description'"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := &ssfreceiver.StreamConfiguration{StreamID: "kept"}

			err := json.Unmarshal([]byte(tc.have), actual)

			if tc.err != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.err)
				assert.Equal(t, &ssfreceiver.StreamConfiguration{StreamID: "kept"}, actual)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestReceiverCreateStream(t *testing.T) {
	for _, st := range testStores() {
		t.Run(st.name, func(t *testing.T) {
			t.Run("ShouldStorePendingRecordThenActivate", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)

				var (
					pending    *ssfreceiver.StreamRecord
					pendingErr error
				)

				tx.on(func(w http.ResponseWriter, _ testStreamCall) {
					pending, pendingErr = receiver.Store.GetSSFReceiverStream(context.Background(), tx.URL, "")

					writeTestStream(w, http.StatusCreated, tx.configuration(map[string]any{"min_verification_interval": 60, "inactivity_timeout": 3600, "description": "truncated"}))
				})

				request := tx.pushRequest()

				record, err := receiver.CreateStream(t.Context(), request)
				require.NoError(t, err)

				// The record is stored before the request, so a SET the Transmitter delivers at once finds it.
				require.NoError(t, pendingErr)
				assert.Equal(t, &ssfreceiver.StreamRecord{
					Issuer:          tx.URL,
					Delivery:        request.Delivery,
					EventsRequested: request.EventsRequested,
					Description:     request.Description,
					State:           ssfreceiver.StreamRecordPending,
				}, pending)

				require.Len(t, tx.received(), 1)

				call := tx.received()[0]

				assert.Equal(t, http.MethodPost, call.method)
				assert.Empty(t, call.query)
				assert.Equal(t, "Bearer "+testStreamToken, call.authorization)
				assert.Equal(t, "application/json", call.contentType)
				assert.JSONEq(t, `{"delivery":{"method":"urn:ietf:rfc:8935","endpoint_url":"`+testPushURL+`","authorization_header":"`+testPushSecret+`"},"events_requested":["`+testEventType2+`","`+testEventType3+`","`+testEventType4+`"],"description":"Stream for Receiver A"}`, call.body)
				assert.Equal(t, []string{oauth2.ScopeSSFManage}, tx.requestedScopes())

				expected := &ssfreceiver.StreamRecord{
					Issuer:                  tx.URL,
					StreamID:                testStreamID,
					Audience:                []string{testStreamAudience},
					Delivery:                request.Delivery,
					EventsRequested:         request.EventsRequested,
					Description:             request.Description,
					EventsSupported:         []string{testEventType2, testEventType3},
					EventsDelivered:         []string{testEventType2, testEventType3},
					State:                   ssfreceiver.StreamRecordActive,
					MinVerificationInterval: 60,
					InactivityTimeout:       3600,
				}

				assert.Equal(t, expected, record)

				// The returned record and the request share no memory with the stored record.
				mutateTestRecord(record)

				record.EventsSupported[0] = "mutated"
				request.EventsRequested[1] = "mutated"

				stored, err := receiver.Store.GetSSFReceiverStream(t.Context(), tx.URL, testStreamID)
				require.NoError(t, err)

				expected.EventsRequested = []string{testEventType2, testEventType3, testEventType4}

				assert.Equal(t, expected, stored)

				_, err = receiver.Store.GetSSFReceiverStream(t.Context(), tx.URL, "")
				assert.ErrorIs(t, err, oauth2.ErrNotFound)

				byEndpoint, err := receiver.Store.GetSSFReceiverStreamByPushEndpoint(t.Context(), testPushURL)
				require.NoError(t, err)
				assert.Equal(t, testStreamID, byEndpoint.StreamID)
			})

			t.Run("ShouldOmitDeliveryForPoll", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)

				tx.answer(http.StatusCreated, tx.configuration(map[string]any{"delivery": tx.pollDelivery()}))

				request := tx.pollRequest()

				// The endpoint URL of a poll stream is supplied by the Transmitter, so one of the request is not sent.
				request.Delivery.EndpointURL = "https://rx.example.com/not-sent"
				request.Delivery.AuthorizationHeader = testPushSecret
				request.EventsRequested = nil
				request.Description = ""

				record, err := receiver.CreateStream(t.Context(), request)
				require.NoError(t, err)

				require.Len(t, tx.received(), 1)
				assert.JSONEq(t, `{"delivery":{"method":"urn:ietf:rfc:8936"}}`, tx.received()[0].body)

				assert.Equal(t, oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPoll, EndpointURL: tx.URL + "/poll"}, record.Delivery)

				stored, err := receiver.Store.GetSSFReceiverStream(t.Context(), tx.URL, testStreamID)
				require.NoError(t, err)
				assert.Equal(t, record, stored)
			})

			t.Run("ShouldStoreEventsDelivered", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)

				tx.answer(http.StatusCreated, tx.configuration(map[string]any{"events_delivered": []string{testEventType3}, "events_requested": []string{testEventType3}, "events_supported": nil}))

				record, err := receiver.CreateStream(t.Context(), tx.pushRequest())
				require.NoError(t, err)

				stored, err := receiver.Store.GetSSFReceiverStream(t.Context(), tx.URL, testStreamID)
				require.NoError(t, err)

				for _, r := range []*ssfreceiver.StreamRecord{record, stored} {
					assert.Equal(t, []string{testEventType3}, r.EventsDelivered)
					assert.Equal(t, []string{testEventType2, testEventType3, testEventType4}, r.EventsRequested)
					assert.Nil(t, r.EventsSupported)
				}
			})

			t.Run("ShouldAcceptAudienceString", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)

				tx.answer(http.StatusOK, tx.configuration(map[string]any{"aud": testStreamAudience}))

				request := tx.pushRequest()

				request.Audience = []string{"https://other.example.com", testStreamAudience}

				record, err := receiver.CreateStream(t.Context(), request)
				require.NoError(t, err)

				assert.Equal(t, []string{testStreamAudience}, record.Audience)
			})

			t.Run("ShouldAcceptAnyAudienceWhenNoneIsExpected", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)

				tx.answer(http.StatusCreated, tx.configuration(map[string]any{"aud": []string{"https://assigned.example.com"}}))

				request := tx.pushRequest()

				request.Audience = nil

				record, err := receiver.CreateStream(t.Context(), request)
				require.NoError(t, err)

				assert.Equal(t, []string{"https://assigned.example.com"}, record.Audience)
			})

			t.Run("ShouldReturnConflictOn409", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)

				tx.answer(http.StatusConflict, nil)

				record, err := receiver.CreateStream(t.Context(), tx.pushRequest())

				assert.Nil(t, record)
				require.ErrorIs(t, err, ssfreceiver.ErrStreamConflict)

				var e *ssfreceiver.TransmitterError

				require.ErrorAs(t, err, &e)
				assert.Equal(t, http.StatusConflict, e.Status)

				assert.Len(t, tx.received(), 1)
				requireNoStreamRecords(t, receiver.Store, tx.URL)
			})

			t.Run("ShouldActivateWhenTheContextIsDoneAfterTheResponse", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)

				tx.answer(http.StatusCreated, tx.configuration(nil))

				// The Transmitter has the stream, so the record is stored though the caller gave up.
				record, err := receiver.CreateStream(tx.cancelAfterResponse(t, receiver), tx.pushRequest())
				require.NoError(t, err)

				stored, err := receiver.Store.GetSSFReceiverStream(t.Context(), tx.URL, testStreamID)
				require.NoError(t, err)

				assert.Equal(t, ssfreceiver.StreamRecordActive, stored.State)
				assert.Equal(t, record, stored)
			})

			t.Run("ShouldNotDeleteAnotherPendingRecord", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)

				other := &ssfreceiver.StreamRecord{Issuer: tx.URL, State: ssfreceiver.StreamRecordPending, Delivery: oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPoll}}

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), other))

				record, err := receiver.CreateStream(t.Context(), tx.pushRequest())

				assert.Nil(t, record)
				require.ErrorIs(t, err, ssfreceiver.ErrStreamRecordConflict)
				assert.Empty(t, tx.received())

				stored, err := receiver.Store.GetSSFReceiverStream(t.Context(), tx.URL, "")
				require.NoError(t, err)
				assert.Equal(t, other, stored)
			})

			t.Run("ShouldNotReplaceTheRecordOfAnExistingStream", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)

				existing := newTestRecord(tx.URL, testStreamID, "https://rx.example.com/push/existing")

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), existing))

				// The Transmitter must assign a new stream ID, and this one answers with the ID of another stream.
				tx.answer(http.StatusCreated, tx.configuration(nil))

				record, err := receiver.CreateStream(t.Context(), tx.pushRequest())

				assert.Nil(t, record)
				require.ErrorIs(t, err, ssfreceiver.ErrStreamRecordConflict)

				records, err := receiver.Store.ListSSFReceiverStreams(t.Context(), tx.URL)
				require.NoError(t, err)
				assert.Equal(t, []*ssfreceiver.StreamRecord{existing}, records)
			})
		})
	}
}

func TestReceiverCreateStreamFailure(t *testing.T) {
	testCases := []struct {
		name    string
		request func(tx *testStreamTransmitter) ssfreceiver.CreateStreamRequest
		respond func(tx *testStreamTransmitter) func(w http.ResponseWriter, call testStreamCall)
		is      []error
		err     string
	}{
		{
			name: "ShouldRejectResponseIssuerMismatch",
			respond: func(tx *testStreamTransmitter) func(w http.ResponseWriter, call testStreamCall) {
				return func(w http.ResponseWriter, _ testStreamCall) {
					writeTestStream(w, http.StatusCreated, tx.configuration(map[string]any{"iss": "https://other.example.com"}))
				}
			},
			is:  []error{ssfreceiver.ErrStreamConfiguration, ssfreceiver.ErrIssuerMismatch},
			err: "ssfreceiver: the stream configuration of the transmitter is not valid: the 'iss': the 'issuer' is not the requested issuer",
		},
		{
			name: "ShouldRejectResponseIssuerMismatchByTrailingSlash",
			respond: func(tx *testStreamTransmitter) func(w http.ResponseWriter, call testStreamCall) {
				return func(w http.ResponseWriter, _ testStreamCall) {
					writeTestStream(w, http.StatusCreated, tx.configuration(map[string]any{"iss": tx.URL + "/"}))
				}
			},
			is: []error{ssfreceiver.ErrStreamConfiguration, ssfreceiver.ErrIssuerMismatch},
		},
		{
			name: "ShouldRejectResponseWithoutIssuer",
			respond: func(tx *testStreamTransmitter) func(w http.ResponseWriter, call testStreamCall) {
				return func(w http.ResponseWriter, _ testStreamCall) {
					writeTestStream(w, http.StatusCreated, tx.configuration(map[string]any{"iss": nil}))
				}
			},
			is: []error{ssfreceiver.ErrStreamConfiguration, ssfreceiver.ErrIssuerMismatch},
		},
		{
			name: "ShouldRejectUnexpectedAudience",
			respond: func(tx *testStreamTransmitter) func(w http.ResponseWriter, call testStreamCall) {
				return func(w http.ResponseWriter, _ testStreamCall) {
					writeTestStream(w, http.StatusCreated, tx.configuration(map[string]any{"aud": []string{testStreamAudience, "https://other.example.com"}}))
				}
			},
			is:  []error{ssfreceiver.ErrStreamConfiguration},
			err: "'aud'",
		},
		{
			name: "ShouldRejectMissingAudience",
			request: func(tx *testStreamTransmitter) ssfreceiver.CreateStreamRequest {
				request := tx.pushRequest()

				request.Audience = nil

				return request
			},
			respond: func(tx *testStreamTransmitter) func(w http.ResponseWriter, call testStreamCall) {
				return func(w http.ResponseWriter, _ testStreamCall) {
					writeTestStream(w, http.StatusCreated, tx.configuration(map[string]any{"aud": nil}))
				}
			},
			is:  []error{ssfreceiver.ErrStreamConfiguration},
			err: "'aud'",
		},
		{
			name: "ShouldRejectEmptyAudienceValue",
			request: func(tx *testStreamTransmitter) ssfreceiver.CreateStreamRequest {
				request := tx.pushRequest()

				request.Audience = nil

				return request
			},
			respond: func(tx *testStreamTransmitter) func(w http.ResponseWriter, call testStreamCall) {
				return func(w http.ResponseWriter, _ testStreamCall) {
					writeTestStream(w, http.StatusCreated, tx.configuration(map[string]any{"aud": []string{""}}))
				}
			},
			is:  []error{ssfreceiver.ErrStreamConfiguration},
			err: "'aud'",
		},
		{
			name:    "ShouldRequirePollEndpointURL",
			request: (*testStreamTransmitter).pollRequest,
			respond: func(tx *testStreamTransmitter) func(w http.ResponseWriter, call testStreamCall) {
				return func(w http.ResponseWriter, _ testStreamCall) {
					writeTestStream(w, http.StatusCreated, tx.configuration(map[string]any{"delivery": map[string]any{"method": oauth2.SSFDeliveryMethodPoll}}))
				}
			},
			is:  []error{ssfreceiver.ErrStreamConfiguration},
			err: "'endpoint_url'",
		},
		{
			name:    "ShouldRejectHTTPPollEndpoint",
			request: (*testStreamTransmitter).pollRequest,
			respond: func(tx *testStreamTransmitter) func(w http.ResponseWriter, call testStreamCall) {
				return func(w http.ResponseWriter, _ testStreamCall) {
					writeTestStream(w, http.StatusCreated, tx.configuration(map[string]any{"delivery": map[string]any{"method": oauth2.SSFDeliveryMethodPoll, "endpoint_url": "http://tx.example.com/poll"}}))
				}
			},
			is:  []error{ssfreceiver.ErrStreamConfiguration},
			err: "'endpoint_url'",
		},
		{
			name: "ShouldRejectChangedDeliveryMethod",
			respond: func(tx *testStreamTransmitter) func(w http.ResponseWriter, call testStreamCall) {
				return func(w http.ResponseWriter, _ testStreamCall) {
					writeTestStream(w, http.StatusCreated, tx.configuration(map[string]any{"delivery": tx.pollDelivery()}))
				}
			},
			is:  []error{ssfreceiver.ErrStreamConfiguration},
			err: "'method'",
		},
		{
			name:    "ShouldRejectChangedDeliveryMethodForPoll",
			request: (*testStreamTransmitter).pollRequest,
			respond: func(tx *testStreamTransmitter) func(w http.ResponseWriter, call testStreamCall) {
				return func(w http.ResponseWriter, _ testStreamCall) {
					writeTestStream(w, http.StatusCreated, tx.configuration(nil))
				}
			},
			is:  []error{ssfreceiver.ErrStreamConfiguration},
			err: "'method'",
		},
		{
			name: "ShouldRejectMissingDelivery",
			respond: func(tx *testStreamTransmitter) func(w http.ResponseWriter, call testStreamCall) {
				return func(w http.ResponseWriter, _ testStreamCall) {
					writeTestStream(w, http.StatusCreated, tx.configuration(map[string]any{"delivery": nil}))
				}
			},
			is:  []error{ssfreceiver.ErrStreamConfiguration},
			err: "'delivery'",
		},
		{
			name: "ShouldRejectChangedPushEndpoint",
			respond: func(tx *testStreamTransmitter) func(w http.ResponseWriter, call testStreamCall) {
				return func(w http.ResponseWriter, _ testStreamCall) {
					writeTestStream(w, http.StatusCreated, tx.configuration(map[string]any{"delivery": map[string]any{"method": oauth2.SSFDeliveryMethodPush, "endpoint_url": "https://other.example.com/push"}}))
				}
			},
			is:  []error{ssfreceiver.ErrStreamConfiguration},
			err: "'endpoint_url'",
		},
		{
			name: "ShouldRejectMissingStreamID",
			respond: func(tx *testStreamTransmitter) func(w http.ResponseWriter, call testStreamCall) {
				return func(w http.ResponseWriter, _ testStreamCall) {
					writeTestStream(w, http.StatusCreated, tx.configuration(map[string]any{"stream_id": nil}))
				}
			},
			is:  []error{ssfreceiver.ErrStreamConfiguration},
			err: "'stream_id'",
		},
		{
			name: "ShouldRejectMissingEventsDelivered",
			respond: func(tx *testStreamTransmitter) func(w http.ResponseWriter, call testStreamCall) {
				return func(w http.ResponseWriter, _ testStreamCall) {
					writeTestStream(w, http.StatusCreated, tx.configuration(map[string]any{"events_delivered": nil}))
				}
			},
			is:  []error{ssfreceiver.ErrStreamConfiguration},
			err: "'events_delivered'",
		},
		{
			name: "ShouldRejectRepeatedMember",
			respond: func(tx *testStreamTransmitter) func(w http.ResponseWriter, call testStreamCall) {
				return func(w http.ResponseWriter, _ testStreamCall) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusCreated)

					_, _ = w.Write([]byte(`{"iss":"` + tx.URL + `","iss":"https://other.example.com"}`))
				}
			},
			is: []error{ssfreceiver.ErrStreamConfiguration},
		},
		{
			name: "ShouldRejectWrongContentType",
			respond: func(tx *testStreamTransmitter) func(w http.ResponseWriter, call testStreamCall) {
				return func(w http.ResponseWriter, _ testStreamCall) {
					data, _ := json.Marshal(tx.configuration(nil))

					w.Header().Set("Content-Type", "text/plain")
					w.WriteHeader(http.StatusCreated)

					_, _ = w.Write(data)
				}
			},
			is: []error{ssfreceiver.ErrStreamConfiguration},
		},
		{
			name: "ShouldRejectAcceptedButNotCreated",
			respond: func(tx *testStreamTransmitter) func(w http.ResponseWriter, call testStreamCall) {
				return func(w http.ResponseWriter, _ testStreamCall) {
					writeTestStream(w, http.StatusAccepted, tx.configuration(nil))
				}
			},
			err: "status code 202",
		},
		{
			name: "ShouldReturnForbiddenOn403",
			respond: func(*testStreamTransmitter) func(w http.ResponseWriter, call testStreamCall) {
				return func(w http.ResponseWriter, _ testStreamCall) {
					w.WriteHeader(http.StatusForbidden)
				}
			},
			is: []error{ssfreceiver.ErrTransmitterForbidden},
		},
		{
			name: "ShouldReturnTransmitterErrorOn500",
			respond: func(*testStreamTransmitter) func(w http.ResponseWriter, call testStreamCall) {
				return func(w http.ResponseWriter, _ testStreamCall) {
					w.WriteHeader(http.StatusInternalServerError)
				}
			},
			err: "status code 500",
		},
	}

	for _, st := range testStores() {
		t.Run(st.name, func(t *testing.T) {
			// SSF Section 8.1.1.1: every failure after the pending record is stored removes it.
			t.Run("ShouldDeletePendingRecordOnFailure", func(t *testing.T) {
				for _, tc := range testCases {
					t.Run(tc.name, func(t *testing.T) {
						tx := newTestStreamTransmitter(t)
						receiver := tx.receiver(st)

						var pendingErr error

						respond := tc.respond(tx)

						tx.on(func(w http.ResponseWriter, call testStreamCall) {
							_, pendingErr = receiver.Store.GetSSFReceiverStream(context.Background(), tx.URL, "")

							respond(w, call)
						})

						request := tx.pushRequest()

						if tc.request != nil {
							request = tc.request(tx)
						}

						record, err := receiver.CreateStream(t.Context(), request)

						assert.Nil(t, record)
						require.Error(t, err)

						for _, is := range tc.is {
							assert.ErrorIs(t, err, is)
						}

						if tc.err != "" {
							assert.Contains(t, err.Error(), tc.err)
						}

						assert.NotContains(t, err.Error(), testPushSecret)
						assert.NotContains(t, err.Error(), testStreamToken)

						// A POST is not sent again, and the record existed while it was sent.
						require.Len(t, tx.received(), 1)
						require.NoError(t, pendingErr)

						requireNoStreamRecords(t, receiver.Store, tx.URL)

						_, err = receiver.Store.GetSSFReceiverStreamByPushEndpoint(t.Context(), testPushURL)
						assert.ErrorIs(t, err, oauth2.ErrNotFound)
					})
				}
			})

			t.Run("ShouldDeletePendingRecordWhenTheContextIsDone", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)

				receiver.Store = testContextStore{Storage: receiver.Store}

				ctx, cancel := context.WithCancel(t.Context())

				// The response is written once the client gave up the request, so it is never read.
				tx.on(func(w http.ResponseWriter, call testStreamCall) {
					cancel()

					select {
					case <-call.done:
					case <-time.After(10 * time.Second):
					}

					writeTestStream(w, http.StatusCreated, tx.configuration(nil))
				})

				record, err := receiver.CreateStream(ctx, tx.pushRequest())

				assert.Nil(t, record)
				require.ErrorIs(t, err, context.Canceled)

				requireNoStreamRecords(t, receiver.Store, tx.URL)
			})
		})
	}
}

func TestReceiverCreateStreamRequest(t *testing.T) {
	testCases := []struct {
		name     string
		metadata map[string]any
		request  func(request *ssfreceiver.CreateStreamRequest)
		is       error
		err      string
	}{
		{
			name:    "ShouldRefuseMissingDeliveryMethod",
			request: func(request *ssfreceiver.CreateStreamRequest) { request.Delivery.Method = "" },
			is:      ssfreceiver.ErrStreamRequest,
			err:     "method",
		},
		{
			name:    "ShouldRefuseUnknownDeliveryMethod",
			request: func(request *ssfreceiver.CreateStreamRequest) { request.Delivery.Method = "urn:example:method" },
			is:      ssfreceiver.ErrStreamRequest,
			err:     "method",
		},
		{
			name:    "ShouldRefusePushWithoutEndpoint",
			request: func(request *ssfreceiver.CreateStreamRequest) { request.Delivery.EndpointURL = "" },
			is:      ssfreceiver.ErrStreamRequest,
			err:     "endpoint",
		},
		{
			name: "ShouldRefuseHTTPPushEndpoint",
			request: func(request *ssfreceiver.CreateStreamRequest) {
				request.Delivery.EndpointURL = "http://rx.example.com/push/1"
			},
			is:  ssfreceiver.ErrStreamRequest,
			err: "endpoint",
		},
		{
			name: "ShouldRefuseEmptyEventType",
			request: func(request *ssfreceiver.CreateStreamRequest) {
				request.EventsRequested = []string{testEventType2, ""}
			},
			is:  ssfreceiver.ErrStreamRequest,
			err: "event",
		},
		{
			name: "ShouldRefuseEmptyExpectedAudience",
			request: func(request *ssfreceiver.CreateStreamRequest) {
				request.Audience = []string{""}
			},
			is:  ssfreceiver.ErrStreamRequest,
			err: "audience",
		},
		{
			name:    "ShouldRefuseIssuerWhichIsNotValid",
			request: func(request *ssfreceiver.CreateStreamRequest) { request.Issuer = "http://tx.example.com" },
			err:     "issuer",
		},
		{
			name:     "ShouldReturnNotSupportedWithoutEndpoint",
			metadata: map[string]any{"configuration_endpoint": nil},
			request:  func(*ssfreceiver.CreateStreamRequest) {},
			is:       ssfreceiver.ErrEndpointNotSupported,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tx := newTestStreamTransmitter(t)

			tx.metadata = tc.metadata

			receiver := tx.receiver(testStores()[0])
			request := tx.pushRequest()

			tc.request(&request)

			record, err := receiver.CreateStream(t.Context(), request)

			assert.Nil(t, record)
			require.Error(t, err)

			if tc.is != nil {
				assert.ErrorIs(t, err, tc.is)
			}

			if tc.err != "" {
				assert.Contains(t, err.Error(), tc.err)
			}

			assert.NotContains(t, err.Error(), testPushSecret)

			// Nothing is stored and nothing is sent for a request which could not be made.
			assert.Empty(t, tx.received())
			requireNoStreamRecords(t, receiver.Store, tx.URL)
		})
	}
}

func TestReceiverReadStream(t *testing.T) {
	for _, st := range testStores() {
		t.Run(st.name, func(t *testing.T) {
			t.Run("ShouldSendStreamIDInQueryWithReadScope", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)

				tx.answer(http.StatusOK, tx.configuration(map[string]any{"description": "d"}))

				configuration, err := receiver.ReadStream(t.Context(), tx.URL, testStreamID)
				require.NoError(t, err)

				require.Len(t, tx.received(), 1)

				call := tx.received()[0]

				assert.Equal(t, http.MethodGet, call.method)
				assert.Equal(t, "stream_id="+testStreamID, call.query)
				assert.Empty(t, call.body)
				assert.Equal(t, []string{oauth2.ScopeSSFRead}, tx.requestedScopes())

				assert.Equal(t, &ssfreceiver.StreamConfiguration{
					StreamID:        testStreamID,
					Issuer:          tx.URL,
					Audience:        []string{testStreamAudience},
					EventsSupported: []string{testEventType2, testEventType3},
					EventsRequested: []string{testEventType2, testEventType3, testEventType4},
					EventsDelivered: []string{testEventType2, testEventType3},
					Delivery:        oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPush, EndpointURL: testPushURL},
					Description:     "d",
				}, configuration)

				// A stream this Receiver has no record of is read and not stored.
				requireNoStreamRecords(t, receiver.Store, tx.URL)
			})

			t.Run("ShouldStoreTransmitterSuppliedMembers", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)

				record := newTestRecord(tx.URL, testStreamID, testPushURL)

				record.Description = "ours"
				record.VerificationState = "state-1"

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

				tx.answer(http.StatusOK, tx.configuration(map[string]any{
					"events_delivered":          []string{testEventType3},
					"events_requested":          []string{testEventType3},
					"description":               "theirs",
					"min_verification_interval": 30,
					"inactivity_timeout":        600,
				}))

				_, err := receiver.ReadStream(t.Context(), tx.URL, testStreamID)
				require.NoError(t, err)

				stored, err := receiver.Store.GetSSFReceiverStream(t.Context(), tx.URL, testStreamID)
				require.NoError(t, err)

				record.EventsDelivered = []string{testEventType3}
				record.EventsSupported = []string{testEventType2, testEventType3}
				record.MinVerificationInterval = 30
				record.InactivityTimeout = 600

				// The Receiver-Supplied members, the secret, the status and the verification are kept.
				assert.Equal(t, record, stored)
			})

			t.Run("ShouldRejectResponseIssuerMismatch", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)

				record := newTestRecord(tx.URL, testStreamID, testPushURL)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

				tx.answer(http.StatusOK, tx.configuration(map[string]any{"iss": "https://other.example.com", "events_delivered": []string{testEventType4}}))

				configuration, err := receiver.ReadStream(t.Context(), tx.URL, testStreamID)

				assert.Nil(t, configuration)
				require.ErrorIs(t, err, ssfreceiver.ErrIssuerMismatch)
				require.ErrorIs(t, err, ssfreceiver.ErrStreamConfiguration)

				stored, err := receiver.Store.GetSSFReceiverStream(t.Context(), tx.URL, testStreamID)
				require.NoError(t, err)
				assert.Equal(t, record, stored)
			})

			t.Run("ShouldRejectStreamIDMismatchOnReadWithoutRecord", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)

				tx.answer(http.StatusOK, tx.configuration(map[string]any{"stream_id": "stream-2"}))

				configuration, err := receiver.ReadStream(t.Context(), tx.URL, testStreamID)

				assert.Nil(t, configuration)
				require.ErrorIs(t, err, ssfreceiver.ErrStreamConfiguration)
				assert.Contains(t, err.Error(), "'stream_id'")
			})

			t.Run("ShouldRejectStreamIDMismatchOnRead", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)

				record := newTestRecord(tx.URL, testStreamID, testPushURL)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

				tx.answer(http.StatusOK, tx.configuration(map[string]any{"stream_id": "stream-2", "events_delivered": []string{testEventType4}}))

				configuration, err := receiver.ReadStream(t.Context(), tx.URL, testStreamID)

				assert.Nil(t, configuration)
				require.ErrorIs(t, err, ssfreceiver.ErrStreamConfiguration)
				assert.Contains(t, err.Error(), "'stream_id'")

				stored, err := receiver.Store.GetSSFReceiverStream(t.Context(), tx.URL, testStreamID)
				require.NoError(t, err)
				assert.Equal(t, record, stored)
			})

			t.Run("ShouldNotStoreAConfigurationWhichDisagreesWithTheRecord", func(t *testing.T) {
				testCases := []struct {
					name  string
					extra func(tx *testStreamTransmitter) map[string]any
					err   string
				}{
					{
						name: "ShouldRejectChangedDeliveryMethod",
						extra: func(tx *testStreamTransmitter) map[string]any {
							return map[string]any{"delivery": tx.pollDelivery()}
						},
						err: "'method'",
					},
					{
						name: "ShouldRejectChangedPushEndpoint",
						extra: func(*testStreamTransmitter) map[string]any {
							return map[string]any{"delivery": map[string]any{"method": oauth2.SSFDeliveryMethodPush, "endpoint_url": "https://other.example.com/push"}}
						},
						err: "'endpoint_url'",
					},
					{
						name: "ShouldRejectUnexpectedAudience",
						extra: func(*testStreamTransmitter) map[string]any {
							return map[string]any{"aud": []string{testStreamAudience, "https://other.example.com"}}
						},
						err: "'aud'",
					},
				}

				for _, tc := range testCases {
					t.Run(tc.name, func(t *testing.T) {
						tx := newTestStreamTransmitter(t)
						receiver := tx.receiver(st)

						record := newTestRecord(tx.URL, testStreamID, testPushURL)

						require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

						extra := tc.extra(tx)

						extra["events_delivered"] = []string{testEventType4}

						tx.answer(http.StatusOK, tx.configuration(extra))

						configuration, err := receiver.ReadStream(t.Context(), tx.URL, testStreamID)

						assert.Nil(t, configuration)
						require.ErrorIs(t, err, ssfreceiver.ErrStreamConfiguration)
						assert.Contains(t, err.Error(), tc.err)

						stored, err := receiver.Store.GetSSFReceiverStream(t.Context(), tx.URL, testStreamID)
						require.NoError(t, err)
						assert.Equal(t, record, stored)
					})
				}
			})

			t.Run("ShouldAcceptRecordWithoutDeliveryMethod", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)

				record := newTestRecord(tx.URL, testStreamID, testPushURL)

				// A record without a delivery method is one of a push stream.
				record.Delivery.Method = ""

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

				tx.answer(http.StatusOK, tx.configuration(map[string]any{"events_delivered": []string{testEventType4}}))

				_, err := receiver.ReadStream(t.Context(), tx.URL, testStreamID)
				require.NoError(t, err)

				stored, err := receiver.Store.GetSSFReceiverStream(t.Context(), tx.URL, testStreamID)
				require.NoError(t, err)

				record.Delivery.Method = oauth2.SSFDeliveryMethodPush
				record.EventsDelivered = []string{testEventType4}
				record.EventsSupported = []string{testEventType2, testEventType3}

				assert.Equal(t, record, stored)
			})

			t.Run("ShouldRequireTheAudienceOfTheRecord", func(t *testing.T) {
				testCases := []struct {
					name     string
					have     []string
					audience []string
					expected []string
					refused  bool
				}{
					{
						name:     "ShouldAcceptTheSameValuesInAnotherOrder",
						have:     []string{testStreamAudience, "https://rx.example.com/mobile"},
						audience: []string{"https://rx.example.com/mobile", testStreamAudience},
						expected: []string{testStreamAudience, "https://rx.example.com/mobile"},
					},
					{
						name:     "ShouldRejectNarrowedAudience",
						have:     []string{testStreamAudience, "https://rx.example.com/mobile"},
						audience: []string{testStreamAudience},
						expected: []string{testStreamAudience, "https://rx.example.com/mobile"},
						refused:  true,
					},
					{
						name:     "ShouldStoreTheAudienceOfARecordWithoutOne",
						audience: []string{"https://assigned.example.com"},
						expected: []string{"https://assigned.example.com"},
					},
				}

				for _, tc := range testCases {
					t.Run(tc.name, func(t *testing.T) {
						tx := newTestStreamTransmitter(t)
						receiver := tx.receiver(st)

						record := newTestRecord(tx.URL, testStreamID, testPushURL)

						record.Audience = tc.have

						require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

						tx.answer(http.StatusOK, tx.configuration(map[string]any{"aud": tc.audience, "events_supported": nil}))

						_, err := receiver.ReadStream(t.Context(), tx.URL, testStreamID)

						if tc.refused {
							require.ErrorIs(t, err, ssfreceiver.ErrStreamConfiguration)
							assert.Contains(t, err.Error(), "'aud'")
						} else {
							require.NoError(t, err)
						}

						stored, err := receiver.Store.GetSSFReceiverStream(t.Context(), tx.URL, testStreamID)
						require.NoError(t, err)

						// SSF Section 8.1.1: the 'aud' cannot be updated, so the stored audience is kept as it is.
						assert.Equal(t, tc.expected, stored.Audience)
					})
				}
			})

			t.Run("ShouldReturnNotFoundOn404", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)

				record := newTestRecord(tx.URL, testStreamID, testPushURL)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

				tx.answer(http.StatusNotFound, nil)

				_, err := receiver.ReadStream(t.Context(), tx.URL, testStreamID)
				require.ErrorIs(t, err, ssfreceiver.ErrStreamNotFound)

				stored, err := receiver.Store.GetSSFReceiverStream(t.Context(), tx.URL, testStreamID)
				require.NoError(t, err)
				assert.Equal(t, record, stored)
			})

			t.Run("ShouldRefuseEmptyStreamID", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)

				_, err := receiver.ReadStream(t.Context(), tx.URL, "")
				require.ErrorIs(t, err, ssfreceiver.ErrStreamRequest)

				assert.Empty(t, tx.received())
			})
		})
	}
}

func TestReceiverListStreams(t *testing.T) {
	t.Run("ShouldListWithoutStreamID", func(t *testing.T) {
		tx := newTestStreamTransmitter(t)
		receiver := tx.receiver(testStores()[0])

		tx.answer(http.StatusOK, []any{
			tx.configuration(nil),
			tx.configuration(map[string]any{"stream_id": "stream-2", "aud": testStreamAudience, "delivery": tx.pollDelivery(), "unknown": true}),
		})

		configurations, err := receiver.ListStreams(t.Context(), tx.URL)
		require.NoError(t, err)

		require.Len(t, tx.received(), 1)

		call := tx.received()[0]

		assert.Equal(t, http.MethodGet, call.method)
		assert.Empty(t, call.query)
		assert.Empty(t, call.body)
		assert.Equal(t, []string{oauth2.ScopeSSFRead}, tx.requestedScopes())

		require.Len(t, configurations, 2)

		assert.Equal(t, testStreamID, configurations[0].StreamID)
		assert.Equal(t, oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPush, EndpointURL: testPushURL}, configurations[0].Delivery)
		assert.Equal(t, "stream-2", configurations[1].StreamID)
		assert.Equal(t, []string{testStreamAudience}, configurations[1].Audience)
		assert.Equal(t, oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPoll, EndpointURL: tx.URL + "/poll"}, configurations[1].Delivery)

		// Listing stores nothing.
		requireNoStreamRecords(t, receiver.Store, tx.URL)
	})

	t.Run("ShouldReturnEmptyList", func(t *testing.T) {
		tx := newTestStreamTransmitter(t)
		receiver := tx.receiver(testStores()[0])

		tx.answer(http.StatusOK, []any{})

		configurations, err := receiver.ListStreams(t.Context(), tx.URL)
		require.NoError(t, err)

		assert.Empty(t, configurations)
	})

	testCases := []struct {
		name  string
		value func(tx *testStreamTransmitter) any
		is    []error
	}{
		{
			name: "ShouldRejectResponseIssuerMismatch",
			value: func(tx *testStreamTransmitter) any {
				return []any{tx.configuration(nil), tx.configuration(map[string]any{"stream_id": "stream-2", "iss": "https://other.example.com"})}
			},
			is: []error{ssfreceiver.ErrStreamConfiguration, ssfreceiver.ErrIssuerMismatch},
		},
		{
			name: "ShouldRejectObject",
			value: func(tx *testStreamTransmitter) any {
				return tx.configuration(nil)
			},
			is: []error{ssfreceiver.ErrStreamConfiguration},
		},
		{
			name: "ShouldRejectListOfStrings",
			value: func(*testStreamTransmitter) any {
				return []any{testStreamID}
			},
			is: []error{ssfreceiver.ErrStreamConfiguration},
		},
		{
			name: "ShouldRejectMissingStreamID",
			value: func(tx *testStreamTransmitter) any {
				return []any{tx.configuration(map[string]any{"stream_id": nil})}
			},
			is: []error{ssfreceiver.ErrStreamConfiguration},
		},
		{
			name: "ShouldRejectRepeatedStreamID",
			value: func(tx *testStreamTransmitter) any {
				return []any{tx.configuration(nil), tx.configuration(nil)}
			},
			is: []error{ssfreceiver.ErrStreamConfiguration},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tx := newTestStreamTransmitter(t)
			receiver := tx.receiver(testStores()[0])

			tx.answer(http.StatusOK, tc.value(tx))

			configurations, err := receiver.ListStreams(t.Context(), tx.URL)

			assert.Nil(t, configurations)
			require.Error(t, err)

			for _, is := range tc.is {
				assert.ErrorIs(t, err, is)
			}
		})
	}

	t.Run("ShouldRejectNoContent", func(t *testing.T) {
		tx := newTestStreamTransmitter(t)
		receiver := tx.receiver(testStores()[0])

		tx.answer(http.StatusNoContent, nil)

		_, err := receiver.ListStreams(t.Context(), tx.URL)
		require.Error(t, err)
	})
}

func TestStreamRecordCloneOfStreamMembers(t *testing.T) {
	record := &ssfreceiver.StreamRecord{Issuer: testIssuer, Description: "d", EventsSupported: []string{"a"}}

	clone := record.Clone()

	assert.Equal(t, record, clone)

	clone.EventsSupported[0] = "mutated"

	assert.Equal(t, []string{"a"}, record.EventsSupported)
}
