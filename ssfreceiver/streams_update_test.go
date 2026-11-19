// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/ssfreceiver"
)

const (
	testOtherPushURL    = "https://rx.example.com/push/2"
	testOtherPushSecret = "Bearer bmV3LXB1c2gtc2VjcmV0"
)

// testStreamChange is an update or a replace of the stream of a record.
type testStreamChange struct {
	name   string
	method string
	change func(ctx context.Context, receiver *ssfreceiver.Receiver, issuer string) (record *ssfreceiver.StreamRecord, err error)
}

func testStreamChanges() []testStreamChange {
	return []testStreamChange{
		{
			name:   "Update",
			method: http.MethodPatch,
			change: func(ctx context.Context, receiver *ssfreceiver.Receiver, issuer string) (record *ssfreceiver.StreamRecord, err error) {
				description := "new"

				return receiver.UpdateStream(ctx, issuer, testStreamID, ssfreceiver.StreamUpdate{Description: &description})
			},
		},
		{
			name:   "Replace",
			method: http.MethodPut,
			change: func(ctx context.Context, receiver *ssfreceiver.Receiver, issuer string) (record *ssfreceiver.StreamRecord, err error) {
				return receiver.ReplaceStream(ctx, issuer, testStreamID, ssfreceiver.StreamReplacement{
					Delivery:        oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPush, EndpointURL: testPushURL, AuthorizationHeader: testPushSecret},
					EventsRequested: []string{testEventType2, testEventType3, testEventType4},
					Description:     "new",
				})
			},
		},
	}
}

// newTestStreamRecord returns the record of a push stream of the Transmitter, with every member the Transmitter
// supplied and every member a change must keep.
func newTestStreamRecord(issuer string) *ssfreceiver.StreamRecord {
	return &ssfreceiver.StreamRecord{
		Issuer:                  issuer,
		StreamID:                testStreamID,
		Audience:                []string{testStreamAudience},
		Delivery:                oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPush, EndpointURL: testPushURL, AuthorizationHeader: testPushSecret},
		EventsRequested:         []string{testEventType2, testEventType3, testEventType4},
		Description:             "old",
		EventsSupported:         []string{testEventType2, testEventType3},
		EventsDelivered:         []string{testEventType2, testEventType3},
		Status:                  oauth2.SSFStreamStatusPaused,
		StatusReason:            "maintenance",
		State:                   ssfreceiver.StreamRecordActive,
		VerificationState:       "state-1",
		VerificationRequestedAt: time.Unix(1700000000, 0).UTC(),
		VerifiedAt:              time.Unix(1600000000, 0).UTC(),
		MinVerificationInterval: 60,
		InactivityTimeout:       3600,
	}
}

func newTestPollStreamRecord(tx *testStreamTransmitter) *ssfreceiver.StreamRecord {
	record := newTestStreamRecord(tx.URL)

	record.Delivery = oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPoll, EndpointURL: tx.URL + "/poll"}

	return record
}

// testUnreadResponse arranges for the Transmitter to answer with a 200 whose body the Receiver can not read.
type testUnreadResponse struct {
	name    string
	arrange func(t *testing.T, tx *testStreamTransmitter, receiver *ssfreceiver.Receiver)
}

func testUnreadResponses() []testUnreadResponse {
	return []testUnreadResponse{
		{
			name: "ShouldTreatTooLargeBodyAsApplied",
			arrange: func(t *testing.T, tx *testStreamTransmitter, receiver *ssfreceiver.Receiver) {
				t.Helper()

				// The metadata is read before the limit is lowered.
				_, err := receiver.Discover(t.Context(), tx.URL)
				require.NoError(t, err)

				receiver.Config.MaxResponseBytes = 8

				tx.answer(http.StatusOK, tx.configuration(nil))
			},
		},
		{
			name: "ShouldTreatTruncatedBodyAsApplied",
			arrange: func(_ *testing.T, tx *testStreamTransmitter, _ *ssfreceiver.Receiver) {
				tx.on(func(w http.ResponseWriter, _ testStreamCall) {
					conn, buffer, err := w.(http.Hijacker).Hijack()
					if err != nil {
						return
					}

					_, _ = buffer.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{")
					_ = buffer.Flush()
					_ = conn.Close()
				})
			},
		},
	}
}

func requireStreamRecord(t *testing.T, store ssfreceiver.Storage, expected *ssfreceiver.StreamRecord) {
	t.Helper()

	stored, err := store.GetSSFReceiverStream(t.Context(), expected.Issuer, expected.StreamID)
	require.NoError(t, err)

	assert.Equal(t, expected, stored)
}

func TestReceiverUpdateStream(t *testing.T) {
	for _, st := range testStores() {
		t.Run(st.name, func(t *testing.T) {
			t.Run("ShouldSendStreamIDAndChangedMembers", func(t *testing.T) {
				description, empty := "new", ""

				testCases := []struct {
					name     string
					update   ssfreceiver.StreamUpdate
					body     string
					expected func(record *ssfreceiver.StreamRecord)
				}{
					{
						name:     "ShouldSendDescription",
						update:   ssfreceiver.StreamUpdate{Description: &description},
						body:     `{"stream_id":"` + testStreamID + `","description":"new"}`,
						expected: func(record *ssfreceiver.StreamRecord) { record.Description = "new" },
					},
					{
						name:     "ShouldSendEmptyDescription",
						update:   ssfreceiver.StreamUpdate{Description: &empty},
						body:     `{"stream_id":"` + testStreamID + `","description":""}`,
						expected: func(record *ssfreceiver.StreamRecord) { record.Description = "" },
					},
					{
						name:     "ShouldSendEventsRequested",
						update:   ssfreceiver.StreamUpdate{EventsRequested: []string{testEventType4}},
						body:     `{"stream_id":"` + testStreamID + `","events_requested":["` + testEventType4 + `"]}`,
						expected: func(record *ssfreceiver.StreamRecord) { record.EventsRequested = []string{testEventType4} },
					},
					{
						name:     "ShouldSendEmptyEventsRequested",
						update:   ssfreceiver.StreamUpdate{EventsRequested: []string{}},
						body:     `{"stream_id":"` + testStreamID + `","events_requested":[]}`,
						expected: func(record *ssfreceiver.StreamRecord) { record.EventsRequested = []string{} },
					},
					{
						name:     "ShouldSendStreamIDAloneWhenNothingChanges",
						update:   ssfreceiver.StreamUpdate{},
						body:     `{"stream_id":"` + testStreamID + `"}`,
						expected: func(*ssfreceiver.StreamRecord) {},
					},
				}

				for _, tc := range testCases {
					t.Run(tc.name, func(t *testing.T) {
						tx := newTestStreamTransmitter(t)
						receiver := tx.receiver(st)
						record := newTestStreamRecord(tx.URL)

						require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

						// The response has what the Transmitter kept of the request, which is not what is stored.
						tx.answer(http.StatusOK, tx.configuration(map[string]any{
							"events_requested":   []string{testEventType2},
							"events_delivered":   []string{testEventType2},
							"events_supported":   []string{testEventType2},
							"description":        "truncated",
							"inactivity_timeout": 600,
						}))

						updated, err := receiver.UpdateStream(t.Context(), tx.URL, testStreamID, tc.update)
						require.NoError(t, err)

						require.Len(t, tx.received(), 1)

						call := tx.received()[0]

						assert.Equal(t, http.MethodPatch, call.method)
						assert.Empty(t, call.query)
						assert.JSONEq(t, tc.body, call.body)
						assert.Equal(t, []string{oauth2.ScopeSSFManage}, tx.requestedScopes())

						// The Transmitter-Supplied members are stored from the response, and the status and the
						// verification are kept.
						record.EventsDelivered = []string{testEventType2}
						record.EventsSupported = []string{testEventType2}
						record.MinVerificationInterval = 0
						record.InactivityTimeout = 600

						tc.expected(record)

						if len(record.EventsRequested) == 0 {
							assert.Empty(t, updated.EventsRequested)

							updated.EventsRequested = record.EventsRequested
						}

						assert.Equal(t, record, updated)

						stored, err := receiver.Store.GetSSFReceiverStream(t.Context(), tx.URL, testStreamID)
						require.NoError(t, err)

						if len(record.EventsRequested) == 0 {
							assert.Empty(t, stored.EventsRequested)

							stored.EventsRequested = record.EventsRequested
						}

						assert.Equal(t, record, stored)
					})
				}
			})

			t.Run("ShouldSendChangedPushDelivery", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)
				record := newTestStreamRecord(tx.URL)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

				tx.answer(http.StatusOK, tx.configuration(map[string]any{"delivery": map[string]any{"method": oauth2.SSFDeliveryMethodPush, "endpoint_url": testOtherPushURL}}))

				delivery := oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPush, EndpointURL: testOtherPushURL, AuthorizationHeader: testOtherPushSecret}

				updated, err := receiver.UpdateStream(t.Context(), tx.URL, testStreamID, ssfreceiver.StreamUpdate{Delivery: &delivery})
				require.NoError(t, err)

				require.Len(t, tx.received(), 1)
				assert.JSONEq(t, `{"stream_id":"`+testStreamID+`","delivery":{"method":"urn:ietf:rfc:8935","endpoint_url":"`+testOtherPushURL+`","authorization_header":"`+testOtherPushSecret+`"}}`, tx.received()[0].body)

				assert.Equal(t, delivery, updated.Delivery)

				// The update shares no memory with the stored record.
				delivery.AuthorizationHeader = "mutated"

				stored, err := receiver.Store.GetSSFReceiverStreamByPushEndpoint(t.Context(), testOtherPushURL)
				require.NoError(t, err)

				assert.Equal(t, testStreamID, stored.StreamID)
				assert.Equal(t, testOtherPushSecret, stored.Delivery.AuthorizationHeader)

				_, err = receiver.Store.GetSSFReceiverStreamByPushEndpoint(t.Context(), testPushURL)
				assert.ErrorIs(t, err, oauth2.ErrNotFound)
			})

			t.Run("ShouldStoreThePollEndpointWhenTheDeliveryBecomesPoll", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)
				record := newTestStreamRecord(tx.URL)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

				tx.answer(http.StatusOK, tx.configuration(map[string]any{"delivery": tx.pollDelivery()}))

				delivery := oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPoll, EndpointURL: "https://rx.example.com/not-sent", AuthorizationHeader: testPushSecret}

				updated, err := receiver.UpdateStream(t.Context(), tx.URL, testStreamID, ssfreceiver.StreamUpdate{Delivery: &delivery})
				require.NoError(t, err)

				require.Len(t, tx.received(), 1)
				assert.JSONEq(t, `{"stream_id":"`+testStreamID+`","delivery":{"method":"urn:ietf:rfc:8936"}}`, tx.received()[0].body)

				// The secret of the push delivery is not kept for a poll stream.
				assert.Equal(t, oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPoll, EndpointURL: tx.URL + "/poll"}, updated.Delivery)

				record.Delivery = updated.Delivery
				record.MinVerificationInterval = 0
				record.InactivityTimeout = 0

				requireStreamRecord(t, receiver.Store, record)
			})

			t.Run("ShouldRefuseUpdateWhichIsNotValid", func(t *testing.T) {
				testCases := []struct {
					name   string
					update ssfreceiver.StreamUpdate
				}{
					{name: "ShouldRefuseEmptyEventType", update: ssfreceiver.StreamUpdate{EventsRequested: []string{""}}},
					{name: "ShouldRefuseUnknownDeliveryMethod", update: ssfreceiver.StreamUpdate{Delivery: &oauth2.SSFDelivery{Method: "urn:example:method"}}},
					{name: "ShouldRefuseHTTPPushEndpoint", update: ssfreceiver.StreamUpdate{Delivery: &oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPush, EndpointURL: "http://rx.example.com/push/1"}}},
				}

				for _, tc := range testCases {
					t.Run(tc.name, func(t *testing.T) {
						tx := newTestStreamTransmitter(t)
						receiver := tx.receiver(st)
						record := newTestStreamRecord(tx.URL)

						require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

						updated, err := receiver.UpdateStream(t.Context(), tx.URL, testStreamID, tc.update)

						assert.Nil(t, updated)
						require.ErrorIs(t, err, ssfreceiver.ErrStreamRequest)
						assert.Empty(t, tx.received())

						requireStreamRecord(t, receiver.Store, record)
					})
				}
			})
		})
	}
}

func TestReceiverReplaceStream(t *testing.T) {
	for _, st := range testStores() {
		t.Run(st.name, func(t *testing.T) {
			t.Run("ShouldSendFullDeliveryOnReplace", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)
				record := newTestStreamRecord(tx.URL)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

				tx.answer(http.StatusOK, tx.configuration(map[string]any{
					"delivery":         map[string]any{"method": oauth2.SSFDeliveryMethodPush, "endpoint_url": testOtherPushURL},
					"events_delivered": []string{testEventType3},
					"description":      "truncated",
				}))

				replacement := ssfreceiver.StreamReplacement{
					Delivery:        oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPush, EndpointURL: testOtherPushURL, AuthorizationHeader: testOtherPushSecret},
					EventsRequested: []string{testEventType3, testEventType4},
					Description:     "Stream for Receiver C",
				}

				replaced, err := receiver.ReplaceStream(t.Context(), tx.URL, testStreamID, replacement)
				require.NoError(t, err)

				require.Len(t, tx.received(), 1)

				call := tx.received()[0]

				// SSF Section 8.1.1.4: a missing member is deleted, so the secret is sent again.
				assert.Equal(t, http.MethodPut, call.method)
				assert.Empty(t, call.query)
				assert.JSONEq(t, `{"stream_id":"`+testStreamID+`","delivery":{"method":"urn:ietf:rfc:8935","endpoint_url":"`+testOtherPushURL+`","authorization_header":"`+testOtherPushSecret+`"},"events_requested":["`+testEventType3+`","`+testEventType4+`"],"description":"Stream for Receiver C"}`, call.body)
				assert.Equal(t, []string{oauth2.ScopeSSFManage}, tx.requestedScopes())

				record.Delivery = replacement.Delivery
				record.EventsRequested = []string{testEventType3, testEventType4}
				record.Description = "Stream for Receiver C"
				record.EventsDelivered = []string{testEventType3}
				record.MinVerificationInterval = 0
				record.InactivityTimeout = 0

				assert.Equal(t, record, replaced)

				// The replacement shares no memory with the stored record.
				replacement.EventsRequested[0] = "mutated"

				requireStreamRecord(t, receiver.Store, record)
			})

			t.Run("ShouldSendTheStoredDeliveryAgain", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)
				record := newTestStreamRecord(tx.URL)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

				tx.answer(http.StatusOK, tx.configuration(nil))

				stored, err := receiver.Store.GetSSFReceiverStream(t.Context(), tx.URL, testStreamID)
				require.NoError(t, err)

				_, err = receiver.ReplaceStream(t.Context(), tx.URL, testStreamID, ssfreceiver.StreamReplacement{Delivery: stored.Delivery})
				require.NoError(t, err)

				// The 'events_requested' and the 'description' are not sent, which asks for them to be deleted.
				require.Len(t, tx.received(), 1)
				assert.JSONEq(t, `{"stream_id":"`+testStreamID+`","delivery":{"method":"urn:ietf:rfc:8935","endpoint_url":"`+testPushURL+`","authorization_header":"`+testPushSecret+`"}}`, tx.received()[0].body)

				record.EventsRequested = nil
				record.Description = ""
				record.MinVerificationInterval = 0
				record.InactivityTimeout = 0

				requireStreamRecord(t, receiver.Store, record)
			})

			t.Run("ShouldSendTheMethodAloneForPoll", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)
				record := newTestPollStreamRecord(tx)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

				tx.answer(http.StatusOK, tx.configuration(map[string]any{"delivery": map[string]any{"method": oauth2.SSFDeliveryMethodPoll, "endpoint_url": tx.URL + "/poll/2"}}))

				// The delivery of the record is given back as it was read, with the endpoint URL of the Transmitter.
				replaced, err := receiver.ReplaceStream(t.Context(), tx.URL, testStreamID, ssfreceiver.StreamReplacement{
					Delivery:        record.Delivery,
					EventsRequested: []string{testEventType2},
				})
				require.NoError(t, err)

				require.Len(t, tx.received(), 1)
				assert.JSONEq(t, `{"stream_id":"`+testStreamID+`","delivery":{"method":"urn:ietf:rfc:8936"},"events_requested":["`+testEventType2+`"]}`, tx.received()[0].body)

				assert.Equal(t, oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPoll, EndpointURL: tx.URL + "/poll/2"}, replaced.Delivery)

				record.Delivery = replaced.Delivery
				record.EventsRequested = []string{testEventType2}
				record.Description = ""
				record.MinVerificationInterval = 0
				record.InactivityTimeout = 0

				requireStreamRecord(t, receiver.Store, record)
			})

			t.Run("ShouldRefuseReplacementWhichIsNotValid", func(t *testing.T) {
				testCases := []struct {
					name        string
					replacement ssfreceiver.StreamReplacement
				}{
					{name: "ShouldRefuseMissingDelivery", replacement: ssfreceiver.StreamReplacement{Description: "d"}},
					{name: "ShouldRefusePushWithoutEndpoint", replacement: ssfreceiver.StreamReplacement{Delivery: oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPush}}},
					{name: "ShouldRefuseEmptyEventType", replacement: ssfreceiver.StreamReplacement{Delivery: oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPoll}, EventsRequested: []string{""}}},
				}

				for _, tc := range testCases {
					t.Run(tc.name, func(t *testing.T) {
						tx := newTestStreamTransmitter(t)
						receiver := tx.receiver(st)
						record := newTestStreamRecord(tx.URL)

						require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

						replaced, err := receiver.ReplaceStream(t.Context(), tx.URL, testStreamID, tc.replacement)

						assert.Nil(t, replaced)
						require.ErrorIs(t, err, ssfreceiver.ErrStreamRequest)
						assert.Empty(t, tx.received())

						requireStreamRecord(t, receiver.Store, record)
					})
				}
			})
		})
	}
}

func TestReceiverChangeStreamRefusedResponse(t *testing.T) {
	for _, st := range testStores() {
		t.Run(st.name, func(t *testing.T) {
			t.Run("ShouldStoreTheNewSecretWhenTheResponseIsRefused", func(t *testing.T) {
				delivery := oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPush, EndpointURL: testOtherPushURL, AuthorizationHeader: testOtherPushSecret}

				testCases := []struct {
					name   string
					change func(ctx context.Context, receiver *ssfreceiver.Receiver, issuer string) (record *ssfreceiver.StreamRecord, err error)
					stored func(record *ssfreceiver.StreamRecord)
				}{
					{
						name: "ShouldStoreOnUpdate",
						change: func(ctx context.Context, receiver *ssfreceiver.Receiver, issuer string) (record *ssfreceiver.StreamRecord, err error) {
							return receiver.UpdateStream(ctx, issuer, testStreamID, ssfreceiver.StreamUpdate{Delivery: &delivery, EventsRequested: []string{testEventType4}})
						},
						stored: func(record *ssfreceiver.StreamRecord) {
							record.EventsRequested = []string{testEventType4}
						},
					},
					{
						name: "ShouldStoreOnReplace",
						change: func(ctx context.Context, receiver *ssfreceiver.Receiver, issuer string) (record *ssfreceiver.StreamRecord, err error) {
							return receiver.ReplaceStream(ctx, issuer, testStreamID, ssfreceiver.StreamReplacement{Delivery: delivery, Description: "replaced"})
						},
						stored: func(record *ssfreceiver.StreamRecord) {
							record.EventsRequested = nil
							record.Description = "replaced"
						},
					},
				}

				for _, tc := range testCases {
					t.Run(tc.name, func(t *testing.T) {
						tx := newTestStreamTransmitter(t)
						receiver := tx.receiver(st)
						record := newTestStreamRecord(tx.URL)

						require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

						// The Transmitter rotated the secret and answers with a configuration which is refused.
						tx.answer(http.StatusOK, tx.configuration(map[string]any{
							"iss":                "https://other.example.com",
							"delivery":           map[string]any{"method": oauth2.SSFDeliveryMethodPush, "endpoint_url": testOtherPushURL},
							"events_delivered":   []string{testEventType4},
							"events_supported":   []string{testEventType4},
							"inactivity_timeout": 1,
						}))

						changed, err := tc.change(t.Context(), receiver, tx.URL)

						assert.Nil(t, changed)
						require.ErrorIs(t, err, ssfreceiver.ErrStreamChangeApplied)
						require.ErrorIs(t, err, ssfreceiver.ErrIssuerMismatch)
						assert.NotContains(t, err.Error(), testOtherPushSecret)

						// The record has the secret the Transmitter now sends, and its Transmitter-Supplied members
						// as they were.
						record.Delivery = delivery

						tc.stored(record)

						requireStreamRecord(t, receiver.Store, record)

						stored, err := receiver.Store.GetSSFReceiverStreamByPushEndpoint(t.Context(), testOtherPushURL)
						require.NoError(t, err)
						assert.Equal(t, testOtherPushSecret, stored.Delivery.AuthorizationHeader)

						_, err = receiver.Store.GetSSFReceiverStreamByPushEndpoint(t.Context(), testPushURL)
						assert.ErrorIs(t, err, oauth2.ErrNotFound)
					})
				}
			})

			t.Run("ShouldKeepThePollEndpointWhenTheResponseIsRefused", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)
				record := newTestPollStreamRecord(tx)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

				tx.answer(http.StatusOK, tx.configuration(map[string]any{"delivery": map[string]any{"method": oauth2.SSFDeliveryMethodPoll, "endpoint_url": "http://tx.example.com/poll"}}))

				_, err := receiver.ReplaceStream(t.Context(), tx.URL, testStreamID, ssfreceiver.StreamReplacement{Delivery: oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPoll}, Description: "replaced"})
				require.ErrorIs(t, err, ssfreceiver.ErrStreamChangeApplied)

				// The endpoint URL is supplied by the Transmitter, so the one of the record is kept.
				record.EventsRequested = nil
				record.Description = "replaced"

				requireStreamRecord(t, receiver.Store, record)
			})

			t.Run("ShouldReturnAppliedWhenTheRecordIsNotStored", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)
				record := newTestStreamRecord(tx.URL)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

				tx.on(func(w http.ResponseWriter, _ testStreamCall) {
					// The record is gone by the time the Transmitter answers.
					_ = receiver.Store.DeleteSSFReceiverStream(context.Background(), tx.URL, testStreamID)

					writeTestStream(w, http.StatusOK, tx.configuration(nil))
				})

				description := "new"

				_, err := receiver.UpdateStream(t.Context(), tx.URL, testStreamID, ssfreceiver.StreamUpdate{Description: &description})
				require.ErrorIs(t, err, ssfreceiver.ErrStreamChangeApplied)
				require.ErrorIs(t, err, oauth2.ErrNotFound)
			})
		})
	}
}

// TestReceiverChangeStream has what an update and a replace share.
func TestReceiverChangeStream(t *testing.T) {
	for _, st := range testStores() {
		for _, change := range testStreamChanges() {
			t.Run(st.name+"/"+change.name, func(t *testing.T) {
				t.Run("ShouldCheckIssuerOnUpdateAndReplace", func(t *testing.T) {
					tx := newTestStreamTransmitter(t)
					receiver := tx.receiver(st)
					record := newTestStreamRecord(tx.URL)

					require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

					tx.answer(http.StatusOK, tx.configuration(map[string]any{"iss": "https://other.example.com", "events_delivered": []string{testEventType4}}))

					changed, err := change.change(t.Context(), receiver, tx.URL)

					assert.Nil(t, changed)
					require.ErrorIs(t, err, ssfreceiver.ErrIssuerMismatch)
					require.ErrorIs(t, err, ssfreceiver.ErrStreamConfiguration)
					require.ErrorIs(t, err, ssfreceiver.ErrStreamChangeApplied)
					assert.Equal(t, 1, strings.Count(err.Error(), "ssfreceiver:"), err.Error())

					require.Len(t, tx.received(), 1)
					assert.Equal(t, change.method, tx.received()[0].method)

					// The Transmitter applied the change, so what was sent is stored, and nothing of the response is.
					record.Description = "new"

					requireStreamRecord(t, receiver.Store, record)
				})

				t.Run("ShouldStoreSentMembersWhenResponseIsNotRead", func(t *testing.T) {
					for _, unread := range testUnreadResponses() {
						t.Run(unread.name, func(t *testing.T) {
							tx := newTestStreamTransmitter(t)
							receiver := tx.receiver(st)
							record := newTestStreamRecord(tx.URL)

							require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

							unread.arrange(t, tx, receiver)

							changed, err := change.change(t.Context(), receiver, tx.URL)

							assert.Nil(t, changed)
							require.ErrorIs(t, err, ssfreceiver.ErrStreamChangeApplied)

							require.Len(t, tx.received(), 1)

							// The 200 means the Transmitter applied the change, so what was sent is stored.
							record.Description = "new"

							requireStreamRecord(t, receiver.Store, record)
						})
					}
				})

				t.Run("ShouldKeepRecordWhenRequestIsNotAnswered", func(t *testing.T) {
					tx := newTestStreamTransmitter(t)
					receiver := tx.receiver(st)
					record := newTestStreamRecord(tx.URL)

					require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

					tx.on(func(w http.ResponseWriter, _ testStreamCall) {
						if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
							_ = conn.Close()
						}
					})

					changed, err := change.change(t.Context(), receiver, tx.URL)

					// The Transmitter may have applied the change.
					assert.Nil(t, changed)
					require.ErrorIs(t, err, ssfreceiver.ErrTransmitterUnconfirmed)
					assert.NotErrorIs(t, err, ssfreceiver.ErrStreamChangeApplied)

					requireStreamRecord(t, receiver.Store, record)
				})

				t.Run("ShouldReturnPendingOn202AndKeepRecord", func(t *testing.T) {
					tx := newTestStreamTransmitter(t)
					receiver := tx.receiver(st)
					record := newTestStreamRecord(tx.URL)

					require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

					// The body of a 202 is not the configuration of the stream.
					tx.answer(http.StatusAccepted, tx.configuration(map[string]any{"events_delivered": []string{testEventType4}}))

					changed, err := change.change(t.Context(), receiver, tx.URL)

					assert.Nil(t, changed)
					require.ErrorIs(t, err, ssfreceiver.ErrStreamUpdatePending)

					var e *ssfreceiver.TransmitterError

					require.ErrorAs(t, err, &e)
					assert.Equal(t, http.StatusAccepted, e.Status)

					require.Len(t, tx.received(), 1)

					requireStreamRecord(t, receiver.Store, record)
				})

				t.Run("ShouldNeverSendTransmitterSuppliedMembersItDidNotRead", func(t *testing.T) {
					testCases := []struct {
						name     string
						record   func(tx *testStreamTransmitter) *ssfreceiver.StreamRecord
						delivery func(tx *testStreamTransmitter) map[string]any
						members  []string
					}{
						{
							name:     "ShouldSendReceiverSuppliedMembersOfPush",
							record:   func(tx *testStreamTransmitter) *ssfreceiver.StreamRecord { return newTestStreamRecord(tx.URL) },
							delivery: func(*testStreamTransmitter) map[string]any { return nil },
							members:  []string{"method", "endpoint_url", "authorization_header"},
						},
						{
							name:     "ShouldSendReceiverSuppliedMembersOfPoll",
							record:   newTestPollStreamRecord,
							delivery: (*testStreamTransmitter).pollDelivery,
							members:  []string{"method"},
						},
					}

					for _, tc := range testCases {
						t.Run(tc.name, func(t *testing.T) {
							tx := newTestStreamTransmitter(t)
							receiver := tx.receiver(st)
							record := tc.record(tx)

							require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

							extra := map[string]any{}

							if delivery := tc.delivery(tx); delivery != nil {
								extra["delivery"] = delivery
							}

							tx.answer(http.StatusOK, tx.configuration(extra))

							var err error

							if change.method == http.MethodPut {
								_, err = receiver.ReplaceStream(t.Context(), tx.URL, testStreamID, ssfreceiver.StreamReplacement{Delivery: record.Delivery, EventsRequested: record.EventsRequested, Description: record.Description})
							} else {
								_, err = receiver.UpdateStream(t.Context(), tx.URL, testStreamID, ssfreceiver.StreamUpdate{Delivery: &record.Delivery, EventsRequested: record.EventsRequested, Description: &record.Description})
							}

							require.NoError(t, err)
							require.Len(t, tx.received(), 1)

							var body map[string]json.RawMessage

							require.NoError(t, json.Unmarshal([]byte(tx.received()[0].body), &body))

							// SSF Sections 8.1.1.3 and 8.1.1.4: a Transmitter-Supplied member must match the value of
							// the Transmitter, which the record may no longer have, so none but the 'stream_id' is sent.
							names := make([]string, 0, len(body))

							for name := range body {
								names = append(names, name)
							}

							assert.ElementsMatch(t, []string{"stream_id", "delivery", "events_requested", "description"}, names)
							assert.JSONEq(t, `"`+testStreamID+`"`, string(body["stream_id"]))

							var delivery map[string]json.RawMessage

							require.NoError(t, json.Unmarshal(body["delivery"], &delivery))

							names = names[:0]

							for name := range delivery {
								names = append(names, name)
							}

							assert.ElementsMatch(t, tc.members, names)
						})
					}
				})
			})
		}
	}
}

// TestReceiverChangeStreamRecord has how an update and a replace read the record of the stream.
func TestReceiverChangeStreamRecord(t *testing.T) {
	for _, st := range testStores() {
		for _, change := range testStreamChanges() {
			t.Run(st.name+"/"+change.name, func(t *testing.T) {
				t.Run("ShouldRefuseStreamWithoutActiveRecord", func(t *testing.T) {
					tx := newTestStreamTransmitter(t)
					receiver := tx.receiver(st)

					changed, err := change.change(t.Context(), receiver, tx.URL)

					assert.Nil(t, changed)
					require.ErrorIs(t, err, oauth2.ErrNotFound)

					pending := &ssfreceiver.StreamRecord{Issuer: tx.URL, StreamID: testStreamID, State: ssfreceiver.StreamRecordPending, Delivery: oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPoll}}

					require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), pending))

					changed, err = change.change(t.Context(), receiver, tx.URL)

					assert.Nil(t, changed)
					require.ErrorIs(t, err, ssfreceiver.ErrStreamRequest)

					assert.Empty(t, tx.received())

					requireStreamRecord(t, receiver.Store, pending)
				})

				t.Run("ShouldReturnTheStoredRecord", func(t *testing.T) {
					tx := newTestStreamTransmitter(t)
					receiver := tx.receiver(st)
					record := newTestStreamRecord(tx.URL)

					require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

					// A stream updated event is stored while the request is made, and the store keeps it.
					tx.on(func(w http.ResponseWriter, _ testStreamCall) {
						assert.NoError(t, receiver.Store.UpdateSSFReceiverStreamStatus(context.Background(), tx.URL, testStreamID, oauth2.SSFStreamStatusPaused, "event"))

						writeTestStream(w, http.StatusOK, tx.configuration(nil))
					})

					changed, err := change.change(t.Context(), receiver, tx.URL)
					require.NoError(t, err)

					stored, err := receiver.Store.GetSSFReceiverStream(t.Context(), tx.URL, testStreamID)
					require.NoError(t, err)

					assert.Equal(t, oauth2.SSFStreamStatusPaused, changed.Status)
					assert.Equal(t, "event", changed.StatusReason)
					assert.Equal(t, stored.Status, changed.Status)
				})

				t.Run("ShouldStoreWhenTheContextIsDoneAfterTheResponse", func(t *testing.T) {
					tx := newTestStreamTransmitter(t)
					receiver := tx.receiver(st)
					record := newTestStreamRecord(tx.URL)

					require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

					tx.answer(http.StatusOK, tx.configuration(nil))

					// The Transmitter changed the stream, so the record is stored though the caller gave up.
					changed, err := change.change(tx.cancelAfterResponse(t, receiver), receiver, tx.URL)
					require.NoError(t, err)

					assert.Equal(t, "new", changed.Description)

					requireStreamRecord(t, receiver.Store, changed)
				})

				// A 200 means the Transmitter applied the change: the members that were sent are stored and the
				// Transmitter-Supplied members are not. Any other response keeps the record.
				t.Run("ShouldStoreOnlyTheSentMembersWhenTheResponseIsRefused", func(t *testing.T) {
					testCases := []struct {
						name   string
						status int
						extra  func(tx *testStreamTransmitter) map[string]any
						is     error
						err    string
					}{
						{
							name: "ShouldRejectStreamIDMismatch",
							extra: func(*testStreamTransmitter) map[string]any {
								return map[string]any{"stream_id": "stream-2"}
							},
							is:  ssfreceiver.ErrStreamConfiguration,
							err: "'stream_id'",
						},
						{
							name:  "ShouldRejectChangedDeliveryMethod",
							extra: func(tx *testStreamTransmitter) map[string]any { return map[string]any{"delivery": tx.pollDelivery()} },
							is:    ssfreceiver.ErrStreamConfiguration,
							err:   "'method'",
						},
						{
							name: "ShouldRejectChangedPushEndpoint",
							extra: func(*testStreamTransmitter) map[string]any {
								return map[string]any{"delivery": map[string]any{"method": oauth2.SSFDeliveryMethodPush, "endpoint_url": testOtherPushURL}}
							},
							is:  ssfreceiver.ErrStreamConfiguration,
							err: "'endpoint_url'",
						},
						{
							name: "ShouldRejectUnexpectedAudience",
							extra: func(*testStreamTransmitter) map[string]any {
								return map[string]any{"aud": []string{"https://other.example.com"}}
							},
							is:  ssfreceiver.ErrStreamConfiguration,
							err: "'aud'",
						},
						{
							name:  "ShouldRejectMissingEventsDelivered",
							extra: func(*testStreamTransmitter) map[string]any { return map[string]any{"events_delivered": nil} },
							is:    ssfreceiver.ErrStreamConfiguration,
							err:   "'events_delivered'",
						},
						{name: "ShouldReturnNotFoundOn404", status: http.StatusNotFound, is: ssfreceiver.ErrStreamNotFound},
						{name: "ShouldReturnForbiddenOn403", status: http.StatusForbidden, is: ssfreceiver.ErrTransmitterForbidden},
						{name: "ShouldNotAcceptCreated", status: http.StatusCreated, err: "status code 201"},
						{name: "ShouldNotAcceptNoContent", status: http.StatusNoContent, err: "status code 204"},
					}

					for _, tc := range testCases {
						t.Run(tc.name, func(t *testing.T) {
							tx := newTestStreamTransmitter(t)
							receiver := tx.receiver(st)
							record := newTestStreamRecord(tx.URL)

							require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

							status := http.StatusOK
							extra := map[string]any{}

							if tc.status != 0 {
								status = tc.status
							}

							if tc.extra != nil {
								extra = tc.extra(tx)
							}

							if _, ok := extra["events_delivered"]; !ok {
								extra["events_delivered"] = []string{testEventType4}
							}

							if status == http.StatusNoContent {
								tx.answer(status, nil)
							} else {
								tx.answer(status, tx.configuration(extra))
							}

							changed, err := change.change(t.Context(), receiver, tx.URL)

							assert.Nil(t, changed)
							require.Error(t, err)

							if tc.is != nil {
								assert.ErrorIs(t, err, tc.is)
							}

							if tc.err != "" {
								assert.Contains(t, err.Error(), tc.err)
							}

							assert.NotContains(t, err.Error(), testPushSecret)
							assert.NotContains(t, err.Error(), testStreamToken)

							require.Len(t, tx.received(), 1)

							assert.Equal(t, status == http.StatusOK, errors.Is(err, ssfreceiver.ErrStreamChangeApplied))

							if status == http.StatusOK {
								record.Description = "new"
							}

							requireStreamRecord(t, receiver.Store, record)
						})
					}
				})

				t.Run("ShouldAcceptRecordWithoutDeliveryMethod", func(t *testing.T) {
					tx := newTestStreamTransmitter(t)
					receiver := tx.receiver(st)
					record := newTestStreamRecord(tx.URL)

					// A record without a delivery method is one of a push stream.
					record.Delivery.Method = ""

					require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

					tx.answer(http.StatusOK, tx.configuration(map[string]any{"min_verification_interval": 60, "inactivity_timeout": 3600}))

					changed, err := change.change(t.Context(), receiver, tx.URL)
					require.NoError(t, err)

					require.Len(t, tx.received(), 1)

					record.Delivery.Method = oauth2.SSFDeliveryMethodPush
					record.Description = "new"

					assert.Equal(t, record, changed)

					requireStreamRecord(t, receiver.Store, record)
				})

				t.Run("ShouldRequireTheAudienceOfTheRecord", func(t *testing.T) {
					testCases := []struct {
						name     string
						audience []string
						refused  bool
					}{
						{name: "ShouldAcceptTheSameValuesInAnotherOrder", audience: []string{"https://rx.example.com/mobile", testStreamAudience}},
						{name: "ShouldRejectNarrowedAudience", audience: []string{testStreamAudience}, refused: true},
						{name: "ShouldRejectWidenedAudience", audience: []string{testStreamAudience, "https://rx.example.com/mobile", "https://other.example.com"}, refused: true},
					}

					for _, tc := range testCases {
						t.Run(tc.name, func(t *testing.T) {
							tx := newTestStreamTransmitter(t)
							receiver := tx.receiver(st)
							record := newTestStreamRecord(tx.URL)

							record.Audience = []string{testStreamAudience, "https://rx.example.com/mobile"}

							require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

							tx.answer(http.StatusOK, tx.configuration(map[string]any{"aud": tc.audience, "events_delivered": []string{testEventType4}}))

							_, err := change.change(t.Context(), receiver, tx.URL)

							record.Description = "new"

							if tc.refused {
								require.ErrorIs(t, err, ssfreceiver.ErrStreamConfiguration)
								require.ErrorIs(t, err, ssfreceiver.ErrStreamChangeApplied)
								assert.Contains(t, err.Error(), "'aud'")
							} else {
								require.NoError(t, err)

								record.EventsDelivered = []string{testEventType4}
								record.MinVerificationInterval = 0
								record.InactivityTimeout = 0
							}

							// SSF Section 8.1.1: the 'aud' cannot be updated, so the stored audience is kept as it is.
							requireStreamRecord(t, receiver.Store, record)
						})
					}
				})
			})
		}
	}
}

// testSecretChanges is an update and a replace which change the secret of the push stream of a record.
func testSecretChanges() []testStreamChange {
	delivery := oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPush, EndpointURL: testPushURL, AuthorizationHeader: testOtherPushSecret}

	return []testStreamChange{
		{
			name:   "Update",
			method: http.MethodPatch,
			change: func(ctx context.Context, receiver *ssfreceiver.Receiver, issuer string) (record *ssfreceiver.StreamRecord, err error) {
				return receiver.UpdateStream(ctx, issuer, testStreamID, ssfreceiver.StreamUpdate{Delivery: &delivery})
			},
		},
		{
			name:   "Replace",
			method: http.MethodPut,
			change: func(ctx context.Context, receiver *ssfreceiver.Receiver, issuer string) (record *ssfreceiver.StreamRecord, err error) {
				return receiver.ReplaceStream(ctx, issuer, testStreamID, ssfreceiver.StreamReplacement{
					Delivery:        delivery,
					EventsRequested: []string{testEventType2, testEventType3, testEventType4},
					Description:     "old",
				})
			},
		},
	}
}

// testPendingSecretStore is a store which does not store a pending secret, or does not clear one.
type testPendingSecretStore struct {
	ssfreceiver.Storage

	err       error
	clearOnly bool
}

func (s testPendingSecretStore) SetSSFReceiverStreamPendingAuthorizationHeader(ctx context.Context, issuer, streamID, header string) (err error) {
	if s.clearOnly && header != "" {
		return s.Storage.SetSSFReceiverStreamPendingAuthorizationHeader(ctx, issuer, streamID, header)
	}

	return s.err
}

// testPushSecrets is the secrets of the stored record of the stream, and the ones of the candidates a push delivery
// request is authorized with.
type testPushSecrets struct {
	secret, pending string
	authorized      []string
}

func readTestPushSecrets(receiver *ssfreceiver.Receiver, issuer string) (secrets testPushSecrets, err error) {
	record, err := receiver.Store.GetSSFReceiverStream(context.Background(), issuer, testStreamID)
	if err != nil {
		return secrets, err
	}

	secrets.secret, secrets.pending = record.Delivery.AuthorizationHeader, record.PendingAuthorizationHeader

	for _, candidate := range []string{testPushSecret, testOtherPushSecret, "Bearer bmVpdGhlcg"} {
		request := httptest.NewRequest(http.MethodPost, testPushURL, strings.NewReader("not a SET"))

		request.Header.Set("Content-Type", "application/secevent+jwt")
		request.Header.Set("Authorization", candidate)

		rw := httptest.NewRecorder()

		// A request which is authorized fails later, as its body is not a SET.
		_ = receiver.HandlePush(context.Background(), rw, request, record)

		if rw.Code == http.StatusAccepted {
			return secrets, errors.New("the push was not refused")
		}

		if !strings.Contains(rw.Body.String(), ssfreceiver.SetErrorAuthenticationFailed) {
			secrets.authorized = append(secrets.authorized, candidate)
		}
	}

	return secrets, nil
}

// requirePushSecrets requires the stored record of the stream to have the secret and the pending secret, and a push
// delivery request to be authorized with exactly the ones of them which are not empty.
func requirePushSecrets(t *testing.T, receiver *ssfreceiver.Receiver, issuer, secret, pending string) {
	t.Helper()

	secrets, err := readTestPushSecrets(receiver, issuer)
	require.NoError(t, err)

	requireTestPushSecrets(t, secrets, secret, pending)
}

func requireTestPushSecrets(t *testing.T, secrets testPushSecrets, secret, pending string) {
	t.Helper()

	expected := testPushSecrets{secret: secret, pending: pending, authorized: []string{secret}}

	if pending != "" {
		expected.authorized = append(expected.authorized, pending)
	}

	assert.Equal(t, expected, secrets)
}

// TestReceiverChangeStreamPushSecret has the secrets a push is authorized with while and after the secret of a push
// stream is changed.
func TestReceiverChangeStreamPushSecret(t *testing.T) {
	for _, st := range testStores() {
		for _, change := range testSecretChanges() {
			t.Run(st.name+"/"+change.name, func(t *testing.T) {
				t.Run("ShouldAcceptBothSecretsBeforeTheResponseAndTheNewOneAfterA200", func(t *testing.T) {
					tx := newTestStreamTransmitter(t)
					receiver := tx.receiver(st)

					require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), newTestStreamRecord(tx.URL)))

					var during testPushSecrets

					tx.on(func(w http.ResponseWriter, _ testStreamCall) {
						during, _ = readTestPushSecrets(receiver, tx.URL)

						writeTestStream(w, http.StatusOK, tx.configuration(nil))
					})

					changed, err := change.change(t.Context(), receiver, tx.URL)
					require.NoError(t, err)

					// The Transmitter may send the new secret before it answers.
					requireTestPushSecrets(t, during, testPushSecret, testOtherPushSecret)

					assert.Equal(t, testOtherPushSecret, changed.Delivery.AuthorizationHeader)
					assert.Empty(t, changed.PendingAuthorizationHeader)

					require.Len(t, tx.received(), 1)

					requirePushSecrets(t, receiver, tx.URL, testOtherPushSecret, "")
				})

				t.Run("ShouldAcceptBothSecretsWhileTheChangeIsPending", func(t *testing.T) {
					tx := newTestStreamTransmitter(t)
					receiver := tx.receiver(st)

					require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), newTestStreamRecord(tx.URL)))

					tx.answer(http.StatusAccepted, nil)

					for range 2 {
						changed, err := change.change(t.Context(), receiver, tx.URL)

						assert.Nil(t, changed)
						require.ErrorIs(t, err, ssfreceiver.ErrStreamUpdatePending)
						assert.NotErrorIs(t, err, ssfreceiver.ErrTransmitterUnconfirmed)

						requirePushSecrets(t, receiver, tx.URL, testPushSecret, testOtherPushSecret)
					}

					// The same request is repeated until the Transmitter answers with a 200.
					tx.answer(http.StatusOK, tx.configuration(nil))

					_, err := change.change(t.Context(), receiver, tx.URL)
					require.NoError(t, err)

					requirePushSecrets(t, receiver, tx.URL, testOtherPushSecret, "")
				})

				t.Run("ShouldAcceptOnlyTheNewSecretWhenTheResponseIsRefused", func(t *testing.T) {
					tx := newTestStreamTransmitter(t)
					receiver := tx.receiver(st)

					require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), newTestStreamRecord(tx.URL)))

					tx.answer(http.StatusOK, tx.configuration(map[string]any{"iss": "https://other.example.com"}))

					_, err := change.change(t.Context(), receiver, tx.URL)
					require.ErrorIs(t, err, ssfreceiver.ErrStreamChangeApplied)
					assert.NotContains(t, err.Error(), testOtherPushSecret)

					requirePushSecrets(t, receiver, tx.URL, testOtherPushSecret, "")
				})

				t.Run("ShouldAcceptOnlyTheNewSecretWhenTheResponseIsNotRead", func(t *testing.T) {
					for _, unread := range testUnreadResponses() {
						t.Run(unread.name, func(t *testing.T) {
							tx := newTestStreamTransmitter(t)
							receiver := tx.receiver(st)

							require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), newTestStreamRecord(tx.URL)))

							unread.arrange(t, tx, receiver)

							_, err := change.change(t.Context(), receiver, tx.URL)
							require.ErrorIs(t, err, ssfreceiver.ErrStreamChangeApplied)
							assert.Equal(t, 1, strings.Count(err.Error(), "ssfreceiver:"), err.Error())

							requirePushSecrets(t, receiver, tx.URL, testOtherPushSecret, "")
						})
					}
				})

				t.Run("ShouldAcceptOnlyTheOldSecretAfterARefusal", func(t *testing.T) {
					for _, status := range []int{http.StatusMovedPermanently, http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusTooManyRequests} {
						t.Run(http.StatusText(status), func(t *testing.T) {
							tx := newTestStreamTransmitter(t)
							receiver := tx.receiver(st)

							require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), newTestStreamRecord(tx.URL)))

							var during testPushSecrets

							tx.on(func(w http.ResponseWriter, _ testStreamCall) {
								during, _ = readTestPushSecrets(receiver, tx.URL)

								w.WriteHeader(status)
							})

							_, err := change.change(t.Context(), receiver, tx.URL)

							requireTestPushSecrets(t, during, testPushSecret, testOtherPushSecret)

							var terr *ssfreceiver.TransmitterError

							require.ErrorAs(t, err, &terr)
							assert.Equal(t, status, terr.Status)
							assert.NotErrorIs(t, err, ssfreceiver.ErrTransmitterUnconfirmed)

							require.Len(t, tx.received(), 1)

							requirePushSecrets(t, receiver, tx.URL, testPushSecret, "")
						})
					}
				})

				// RFC 9110 Sections 15.3 and 15.6: neither rules out that the Transmitter applied the change.
				t.Run("ShouldKeepBothSecretsWhenTheOutcomeIsUncertain", func(t *testing.T) {
					for _, status := range []int{http.StatusNoContent, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
						t.Run(http.StatusText(status), func(t *testing.T) {
							tx := newTestStreamTransmitter(t)
							receiver := tx.receiver(st)

							require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), newTestStreamRecord(tx.URL)))

							tx.on(func(w http.ResponseWriter, _ testStreamCall) {
								w.WriteHeader(status)
							})

							_, err := change.change(t.Context(), receiver, tx.URL)

							var terr *ssfreceiver.TransmitterError

							require.ErrorAs(t, err, &terr)
							assert.Equal(t, status, terr.Status)
							assert.NotErrorIs(t, err, ssfreceiver.ErrStreamChangeApplied)

							require.Len(t, tx.received(), 1)

							requirePushSecrets(t, receiver, tx.URL, testPushSecret, testOtherPushSecret)
						})
					}
				})

				t.Run("ShouldKeepBothSecretsWhenTheResponseIsLost", func(t *testing.T) {
					tx := newTestStreamTransmitter(t)
					receiver := tx.receiver(st)

					require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), newTestStreamRecord(tx.URL)))

					tx.on(func(w http.ResponseWriter, _ testStreamCall) {
						if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
							_ = conn.Close()
						}
					})

					changed, err := change.change(t.Context(), receiver, tx.URL)

					// The Transmitter may have applied the change.
					assert.Nil(t, changed)
					require.ErrorIs(t, err, ssfreceiver.ErrTransmitterUnconfirmed)
					assert.NotErrorIs(t, err, ssfreceiver.ErrStreamChangeApplied)

					requirePushSecrets(t, receiver, tx.URL, testPushSecret, testOtherPushSecret)
				})

				t.Run("ShouldNotSendTheChangeAgainAfterTheResponseIsLost", func(t *testing.T) {
					tx := newTestStreamTransmitter(t)
					receiver := tx.receiver(st)
					receiver.Config.HTTPClient.RetryMax = 3
					receiver.Config.HTTPClient.RetryWaitMin, receiver.Config.HTTPClient.RetryWaitMax = time.Millisecond, time.Millisecond

					require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), newTestStreamRecord(tx.URL)))

					// The refusal of a second attempt would hide that the first may have been applied.
					var n atomic.Int32

					tx.on(func(w http.ResponseWriter, _ testStreamCall) {
						if n.Add(1) == 1 {
							if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
								_ = conn.Close()
							}

							return
						}

						w.WriteHeader(http.StatusForbidden)
					})

					_, err := change.change(t.Context(), receiver, tx.URL)

					require.ErrorIs(t, err, ssfreceiver.ErrTransmitterUnconfirmed)
					assert.Len(t, tx.received(), 1)

					requirePushSecrets(t, receiver, tx.URL, testPushSecret, testOtherPushSecret)
				})

				t.Run("ShouldKeepThePendingSecretOfAnEarlierChangeAfterARefusal", func(t *testing.T) {
					tx := newTestStreamTransmitter(t)
					receiver := tx.receiver(st)

					require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), newTestStreamRecord(tx.URL)))

					tx.answer(http.StatusAccepted, nil)

					_, err := change.change(t.Context(), receiver, tx.URL)
					require.ErrorIs(t, err, ssfreceiver.ErrStreamUpdatePending)

					// The Transmitter may still process the change it accepted.
					tx.answer(http.StatusTooManyRequests, nil)

					_, err = change.change(t.Context(), receiver, tx.URL)
					require.ErrorIs(t, err, ssfreceiver.ErrTransmitterThrottled)

					requirePushSecrets(t, receiver, tx.URL, testPushSecret, testOtherPushSecret)
				})

				t.Run("ShouldAcceptOnlyTheOldSecretWhenTheRequestIsNotSent", func(t *testing.T) {
					tx := newTestStreamTransmitter(t)
					receiver := tx.receiver(st)

					require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), newTestStreamRecord(tx.URL)))

					denied := errors.New("no token")

					receiver.Config.Authorizer = &ssfreceiver.BearerAuthorizer{Token: func(context.Context, string, string) (string, error) {
						return "", denied
					}}

					_, err := change.change(t.Context(), receiver, tx.URL)
					require.ErrorIs(t, err, denied)
					assert.NotErrorIs(t, err, ssfreceiver.ErrTransmitterUnconfirmed)

					assert.Empty(t, tx.received())

					requirePushSecrets(t, receiver, tx.URL, testPushSecret, "")
				})

				t.Run("ShouldNotSendWhenThePendingSecretIsNotStored", func(t *testing.T) {
					tx := newTestStreamTransmitter(t)
					receiver := tx.receiver(st)

					require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), newTestStreamRecord(tx.URL)))

					failed := errors.New("store failed")

					receiver.Store = testPendingSecretStore{Storage: receiver.Store, err: failed}

					_, err := change.change(t.Context(), receiver, tx.URL)
					require.ErrorIs(t, err, failed)
					assert.NotContains(t, err.Error(), testOtherPushSecret)

					assert.Empty(t, tx.received())

					requirePushSecrets(t, receiver, tx.URL, testPushSecret, "")
				})

				t.Run("ShouldReturnAppliedWhenThePendingSecretIsNotCleared", func(t *testing.T) {
					tx := newTestStreamTransmitter(t)
					receiver := tx.receiver(st)

					require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), newTestStreamRecord(tx.URL)))

					failed := errors.New("store failed")

					receiver.Store = testPendingSecretStore{Storage: receiver.Store, err: failed, clearOnly: true}

					tx.answer(http.StatusOK, tx.configuration(nil))

					changed, err := change.change(t.Context(), receiver, tx.URL)

					assert.Nil(t, changed)
					require.ErrorIs(t, err, ssfreceiver.ErrStreamChangeApplied)
					require.ErrorIs(t, err, failed)

					// The record has the new secret, which is the one the Transmitter sends.
					secrets, err := readTestPushSecrets(receiver, tx.URL)
					require.NoError(t, err)

					assert.Equal(t, testPushSecrets{secret: testOtherPushSecret, pending: testOtherPushSecret, authorized: []string{testOtherPushSecret}}, secrets)
				})

				t.Run("ShouldClearThePendingSecretWhenTheContextIsDoneAfterTheResponse", func(t *testing.T) {
					tx := newTestStreamTransmitter(t)
					receiver := tx.receiver(st)

					require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), newTestStreamRecord(tx.URL)))

					tx.answer(http.StatusOK, tx.configuration(nil))

					_, err := change.change(tx.cancelAfterResponse(t, receiver), receiver, tx.URL)
					require.NoError(t, err)

					requirePushSecrets(t, receiver, tx.URL, testOtherPushSecret, "")
				})
			})
		}

		t.Run(st.name, func(t *testing.T) {
			t.Run("ShouldNotSetAPendingSecretWhenTheSecretIsNotChanged", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), newTestStreamRecord(tx.URL)))

				var during []testPushSecrets

				tx.on(func(w http.ResponseWriter, _ testStreamCall) {
					secrets, _ := readTestPushSecrets(receiver, tx.URL)

					during = append(during, secrets)

					w.WriteHeader(http.StatusAccepted)
				})

				// The stored secret is sent again, and an update without a delivery has none.
				for _, change := range testStreamChanges() {
					_, err := change.change(t.Context(), receiver, tx.URL)
					require.ErrorIs(t, err, ssfreceiver.ErrStreamUpdatePending)
				}

				require.Len(t, during, 2)

				requireTestPushSecrets(t, during[0], testPushSecret, "")
				requireTestPushSecrets(t, during[1], testPushSecret, "")

				require.Len(t, tx.received(), 2)

				requirePushSecrets(t, receiver, tx.URL, testPushSecret, "")
			})

			t.Run("ShouldKeepThePendingSecretWhenAnUpdateHasNoDelivery", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), newTestStreamRecord(tx.URL)))

				tx.answer(http.StatusAccepted, nil)

				_, err := testSecretChanges()[0].change(t.Context(), receiver, tx.URL)
				require.ErrorIs(t, err, ssfreceiver.ErrStreamUpdatePending)

				// The Transmitter has not said that it processed the change of the secret.
				for _, status := range []int{http.StatusOK, http.StatusBadRequest} {
					tx.answer(status, tx.configuration(nil))

					description := "new"

					_, _ = receiver.UpdateStream(t.Context(), tx.URL, testStreamID, ssfreceiver.StreamUpdate{Description: &description})

					requirePushSecrets(t, receiver, tx.URL, testPushSecret, testOtherPushSecret)
				}
			})

			t.Run("ShouldClearThePendingSecretWhenTheStoredSecretIsConfirmed", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), newTestStreamRecord(tx.URL)))

				tx.answer(http.StatusAccepted, nil)

				_, err := testSecretChanges()[0].change(t.Context(), receiver, tx.URL)
				require.ErrorIs(t, err, ssfreceiver.ErrStreamUpdatePending)

				// A 200 to a delivery with the stored secret means the Transmitter sends that one.
				tx.answer(http.StatusOK, tx.configuration(nil))

				_, err = testStreamChanges()[1].change(t.Context(), receiver, tx.URL)
				require.NoError(t, err)

				requirePushSecrets(t, receiver, tx.URL, testPushSecret, "")
			})
		})
	}
}

func TestReceiverChangeStreamPushEndpointConflict(t *testing.T) {
	delivery := oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPush, EndpointURL: testOtherPushURL, AuthorizationHeader: testOtherPushSecret}

	testCases := []struct {
		name   string
		change func(ctx context.Context, receiver *ssfreceiver.Receiver, issuer string) (record *ssfreceiver.StreamRecord, err error)
	}{
		{
			name: "ShouldRefuseUpdateToThePushEndpointOfAnotherRecord",
			change: func(ctx context.Context, receiver *ssfreceiver.Receiver, issuer string) (record *ssfreceiver.StreamRecord, err error) {
				return receiver.UpdateStream(ctx, issuer, testStreamID, ssfreceiver.StreamUpdate{Delivery: &delivery})
			},
		},
		{
			name: "ShouldRefuseReplaceWithThePushEndpointOfAnotherRecord",
			change: func(ctx context.Context, receiver *ssfreceiver.Receiver, issuer string) (record *ssfreceiver.StreamRecord, err error) {
				return receiver.ReplaceStream(ctx, issuer, testStreamID, ssfreceiver.StreamReplacement{Delivery: delivery})
			},
		},
	}

	for _, st := range testStores() {
		for _, tc := range testCases {
			t.Run(st.name+"/"+tc.name, func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)
				record := newTestStreamRecord(tx.URL)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))
				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), newTestRecord(testIssuer, "other", testOtherPushURL)))

				changed, err := tc.change(t.Context(), receiver, tx.URL)

				assert.Nil(t, changed)
				require.ErrorIs(t, err, ssfreceiver.ErrStreamRecordConflict)

				// The Transmitter is not asked for a change the Receiver could not store.
				assert.Empty(t, tx.received())

				requireStreamRecord(t, receiver.Store, record)
			})
		}
	}
}

func TestReceiverDeleteStream(t *testing.T) {
	for _, st := range testStores() {
		t.Run(st.name, func(t *testing.T) {
			t.Run("ShouldDeleteRecordOn204", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), newTestStreamRecord(tx.URL)))
				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), newTestRecord(tx.URL, "other", testOtherPushURL)))

				tx.answer(http.StatusNoContent, nil)

				require.NoError(t, receiver.DeleteStream(t.Context(), tx.URL, testStreamID))

				require.Len(t, tx.received(), 1)

				call := tx.received()[0]

				// SSF Section 8.1.1.5: the 'stream_id' is a query parameter.
				assert.Equal(t, http.MethodDelete, call.method)
				assert.Equal(t, "stream_id="+testStreamID, call.query)
				assert.Empty(t, call.body)
				assert.Empty(t, call.contentType)
				assert.Equal(t, []string{oauth2.ScopeSSFManage}, tx.requestedScopes())

				_, err := receiver.Store.GetSSFReceiverStream(t.Context(), tx.URL, testStreamID)
				require.ErrorIs(t, err, oauth2.ErrNotFound)

				_, err = receiver.Store.GetSSFReceiverStreamByPushEndpoint(t.Context(), testPushURL)
				require.ErrorIs(t, err, oauth2.ErrNotFound)

				records, err := receiver.Store.ListSSFReceiverStreams(t.Context(), tx.URL)
				require.NoError(t, err)
				require.Len(t, records, 1)
				assert.Equal(t, "other", records[0].StreamID)
			})

			// SSF Section 8.1.1.5: a 404 is no such stream for this Receiver, as after a 204 which was lost.
			t.Run("ShouldDeleteRecordOn404", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), newTestStreamRecord(tx.URL)))

				tx.answer(http.StatusNotFound, nil)

				require.NoError(t, receiver.DeleteStream(t.Context(), tx.URL, testStreamID))

				assert.Len(t, tx.received(), 1)

				requireNoStreamRecords(t, receiver.Store, tx.URL)

				_, err := receiver.Store.GetSSFReceiverStreamByPushEndpoint(t.Context(), testPushURL)
				require.ErrorIs(t, err, oauth2.ErrNotFound)

				// A stream neither side has is deleted without an error too.
				require.NoError(t, receiver.DeleteStream(t.Context(), tx.URL, testStreamID))
			})

			t.Run("ShouldEncodeStreamIDInQuery", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)

				tx.answer(http.StatusNoContent, nil)

				// A stream this Receiver has no record of is deleted too.
				require.NoError(t, receiver.DeleteStream(t.Context(), tx.URL, "a b&c=d"))

				require.Len(t, tx.received(), 1)
				assert.Equal(t, "stream_id=a+b%26c%3Dd", tx.received()[0].query)
			})

			t.Run("ShouldKeepRecordWhenDeleteFails", func(t *testing.T) {
				testCases := []struct {
					name   string
					status int
					is     error
				}{
					{name: "ShouldKeepRecordOn401", status: http.StatusUnauthorized, is: ssfreceiver.ErrTransmitterUnauthorized},
					{name: "ShouldKeepRecordOn403", status: http.StatusForbidden, is: ssfreceiver.ErrTransmitterForbidden},
					{name: "ShouldKeepRecordOn500", status: http.StatusInternalServerError},
					{name: "ShouldKeepRecordOn202", status: http.StatusAccepted},
					{name: "ShouldKeepRecordOn200", status: http.StatusOK},
				}

				for _, tc := range testCases {
					t.Run(tc.name, func(t *testing.T) {
						tx := newTestStreamTransmitter(t)
						receiver := tx.receiver(st)
						record := newTestStreamRecord(tx.URL)

						require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

						tx.answer(tc.status, nil)

						err := receiver.DeleteStream(t.Context(), tx.URL, testStreamID)
						require.Error(t, err)

						var e *ssfreceiver.TransmitterError

						require.ErrorAs(t, err, &e)
						assert.Equal(t, tc.status, e.Status)

						if tc.is != nil {
							assert.ErrorIs(t, err, tc.is)
						}

						assert.Len(t, tx.received(), 1)

						requireStreamRecord(t, receiver.Store, record)
					})
				}
			})

			t.Run("ShouldDeleteRecordWhenTheContextIsDoneAfterTheResponse", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), newTestStreamRecord(tx.URL)))

				tx.answer(http.StatusNoContent, nil)

				require.NoError(t, receiver.DeleteStream(tx.cancelAfterResponse(t, receiver), tx.URL, testStreamID))

				requireNoStreamRecords(t, receiver.Store, tx.URL)
			})

			t.Run("ShouldRefuseEmptyStreamID", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)

				pending := &ssfreceiver.StreamRecord{Issuer: tx.URL, State: ssfreceiver.StreamRecordPending, Delivery: oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPoll}}

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), pending))

				require.ErrorIs(t, receiver.DeleteStream(t.Context(), tx.URL, ""), ssfreceiver.ErrStreamRequest)

				assert.Empty(t, tx.received())

				requireStreamRecord(t, receiver.Store, pending)
			})
		})
	}
}
