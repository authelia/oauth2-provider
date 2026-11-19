// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/ssfreceiver"
)

func testStreamStatus(status string, extra map[string]any) map[string]any {
	members := map[string]any{"stream_id": testStreamID, "status": status}

	for name, value := range extra {
		if value == nil {
			delete(members, name)
		} else {
			members[name] = value
		}
	}

	return members
}

// testStatusCall is a read or an update of the status of the stream of a record.
type testStatusCall struct {
	name   string
	method string
	scope  string
	call   func(ctx context.Context, receiver *ssfreceiver.Receiver, issuer string) (status *ssfreceiver.StreamStatus, err error)
}

func testStatusCalls() []testStatusCall {
	return []testStatusCall{
		{
			name:   "Read",
			method: http.MethodGet,
			scope:  oauth2.ScopeSSFRead,
			call: func(ctx context.Context, receiver *ssfreceiver.Receiver, issuer string) (status *ssfreceiver.StreamStatus, err error) {
				return receiver.ReadStreamStatus(ctx, issuer, testStreamID)
			},
		},
		{
			name:   "Update",
			method: http.MethodPost,
			scope:  oauth2.ScopeSSFManage,
			call: func(ctx context.Context, receiver *ssfreceiver.Receiver, issuer string) (status *ssfreceiver.StreamStatus, err error) {
				return receiver.UpdateStreamStatus(ctx, issuer, testStreamID, oauth2.SSFStreamStatusDisabled, "requested")
			},
		},
	}
}

// testFirstReadFailStore fails the first read of a stream record.
type testFirstReadFailStore struct {
	ssfreceiver.Storage

	read bool
}

func (s *testFirstReadFailStore) GetSSFReceiverStream(ctx context.Context, issuer, streamID string) (record *ssfreceiver.StreamRecord, err error) {
	if !s.read {
		s.read = true

		return nil, errors.New("the store is unavailable")
	}

	return s.Storage.GetSSFReceiverStream(ctx, issuer, streamID)
}

func TestReceiverReadStreamStatus(t *testing.T) {
	for _, st := range testStores() {
		t.Run(st.name, func(t *testing.T) {
			t.Run("ShouldSendStreamIDInQueryOnGet", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)

				tx.answer(http.StatusOK, testStreamStatus(oauth2.SSFStreamStatusEnabled, nil))

				status, err := receiver.ReadStreamStatus(t.Context(), tx.URL, testStreamID)

				require.NoError(t, err)
				assert.Equal(t, &ssfreceiver.StreamStatus{StreamID: testStreamID, Status: oauth2.SSFStreamStatusEnabled}, status)

				require.Len(t, tx.received(), 1)

				call := tx.received()[0]

				assert.Equal(t, testStatusPath, call.path)
				assert.Equal(t, http.MethodGet, call.method)
				assert.Equal(t, "stream_id="+testStreamID, call.query)
				assert.Equal(t, "Bearer "+testStreamToken, call.authorization)
				assert.Empty(t, call.body)

				// Profile Section 2.7.3: the 'ssf.read' scope allows Get Stream Status.
				assert.Equal(t, []string{oauth2.ScopeSSFRead}, tx.requestedScopes())

				// Without a record nothing is stored.
				requireNoStreamRecords(t, receiver.Store, tx.URL)
			})

			t.Run("ShouldStoreStatusOn200", func(t *testing.T) {
				testCases := []struct {
					name   string
					status map[string]any
					reason string
				}{
					{"ShouldStoreStatusAndReason", testStreamStatus(oauth2.SSFStreamStatusDisabled, map[string]any{"reason": "License is not valid"}), "License is not valid"},
					{"ShouldStoreStatusAndClearReason", testStreamStatus(oauth2.SSFStreamStatusEnabled, nil), ""},
					{"ShouldReadNullReasonAsAbsent", testStreamStatus(oauth2.SSFStreamStatusEnabled, map[string]any{"reason": (*string)(nil)}), ""},
					{"ShouldIgnoreUnknownMembers", testStreamStatus(oauth2.SSFStreamStatusEnabled, map[string]any{"extra": []int{1}}), ""},
				}

				for _, tc := range testCases {
					t.Run(tc.name, func(t *testing.T) {
						tx := newTestStreamTransmitter(t)
						receiver := tx.receiver(st)
						record := newTestStreamRecord(tx.URL)

						require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

						tx.answer(http.StatusOK, tc.status)

						status, err := receiver.ReadStreamStatus(t.Context(), tx.URL, testStreamID)

						require.NoError(t, err)
						assert.Equal(t, &ssfreceiver.StreamStatus{StreamID: testStreamID, Status: tc.status["status"].(string), Reason: tc.reason}, status)

						// Only the status and its reason change.
						record.Status, record.StatusReason = status.Status, tc.reason

						requireStreamRecord(t, receiver.Store, record)
					})
				}
			})

			t.Run("ShouldNotStoreStatusOfPendingRecord", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)
				record := newTestStreamRecord(tx.URL)

				record.State = ssfreceiver.StreamRecordPending

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

				tx.answer(http.StatusOK, testStreamStatus(oauth2.SSFStreamStatusEnabled, nil))

				_, err := receiver.ReadStreamStatus(t.Context(), tx.URL, testStreamID)

				require.NoError(t, err)

				requireStreamRecord(t, receiver.Store, record)
			})

			t.Run("ShouldReadWithoutStore", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)
				receiver.Store = nil

				tx.answer(http.StatusOK, testStreamStatus(oauth2.SSFStreamStatusPaused, nil))

				status, err := receiver.ReadStreamStatus(t.Context(), tx.URL, testStreamID)

				require.NoError(t, err)
				assert.Equal(t, oauth2.SSFStreamStatusPaused, status.Status)
			})

			t.Run("ShouldRequireStreamID", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)

				status, err := receiver.ReadStreamStatus(t.Context(), tx.URL, "")

				assert.Nil(t, status)
				require.ErrorIs(t, err, ssfreceiver.ErrStreamRequest)
				assert.Empty(t, tx.received())
			})

			t.Run("ShouldTouchWithStatusRead", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)
				record := newTestStreamRecord(tx.URL)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

				tx.answer(http.StatusOK, testStreamStatus(oauth2.SSFStreamStatusEnabled, nil))

				require.NoError(t, receiver.Touch(t.Context(), tx.URL, testStreamID))

				require.Len(t, tx.received(), 1)

				call := tx.received()[0]

				assert.Equal(t, testStatusPath, call.path)
				assert.Equal(t, http.MethodGet, call.method)
				assert.Equal(t, "stream_id="+testStreamID, call.query)
				assert.Equal(t, []string{oauth2.ScopeSSFRead}, tx.requestedScopes())

				record.Status, record.StatusReason = oauth2.SSFStreamStatusEnabled, ""

				requireStreamRecord(t, receiver.Store, record)

				tx.answer(http.StatusNotFound, nil)

				require.ErrorIs(t, receiver.Touch(t.Context(), tx.URL, testStreamID), ssfreceiver.ErrStreamNotFound)
			})

			t.Run("ShouldTouchWithConfigurationReadWithoutStatusEndpoint", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				tx.metadata = map[string]any{"status_endpoint": nil}
				receiver := tx.receiver(st)
				record := newTestStreamRecord(tx.URL)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

				tx.answer(http.StatusOK, tx.configuration(map[string]any{"description": "changed"}))

				require.NoError(t, receiver.Touch(t.Context(), tx.URL, testStreamID))

				require.Len(t, tx.received(), 1)

				call := tx.received()[0]

				// SSF Section 8.1.1: a request which references the stream is activity, and nothing is stored.
				assert.Equal(t, testStreamsPath, call.path)
				assert.Equal(t, http.MethodGet, call.method)
				assert.Equal(t, "stream_id="+testStreamID, call.query)

				requireStreamRecord(t, receiver.Store, record)
			})

			t.Run("ShouldNotStoreTheStatusWhenItCouldNotBeReadBefore", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)
				record := newTestStreamRecord(tx.URL)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

				store := receiver.Store
				receiver.Store = &testFirstReadFailStore{Storage: store}

				tx.on(func(w http.ResponseWriter, _ testStreamCall) {
					assert.NoError(t, store.UpdateSSFReceiverStreamStatus(context.Background(), tx.URL, testStreamID, oauth2.SSFStreamStatusDisabled, "event"))

					writeTestStream(w, http.StatusOK, testStreamStatus(oauth2.SSFStreamStatusEnabled, nil))
				})

				status, err := receiver.ReadStreamStatus(t.Context(), tx.URL, testStreamID)

				require.NoError(t, err)
				assert.Equal(t, oauth2.SSFStreamStatusEnabled, status.Status)

				record.Status, record.StatusReason = oauth2.SSFStreamStatusDisabled, "event"

				requireStreamRecord(t, store, record)
			})

			t.Run("ShouldKeepTheStatusOfAStreamEventDuringTheRead", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)
				record := newTestStreamRecord(tx.URL)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

				// A stream updated event is stored while the request is made.
				tx.on(func(w http.ResponseWriter, _ testStreamCall) {
					assert.NoError(t, receiver.Store.UpdateSSFReceiverStreamStatus(context.Background(), tx.URL, testStreamID, oauth2.SSFStreamStatusDisabled, "event"))

					writeTestStream(w, http.StatusOK, testStreamStatus(oauth2.SSFStreamStatusEnabled, nil))
				})

				status, err := receiver.ReadStreamStatus(t.Context(), tx.URL, testStreamID)

				require.NoError(t, err)
				assert.Equal(t, oauth2.SSFStreamStatusEnabled, status.Status)

				record.Status, record.StatusReason = oauth2.SSFStreamStatusDisabled, "event"

				requireStreamRecord(t, receiver.Store, record)
			})
		})
	}
}

func TestReceiverUpdateStreamStatus(t *testing.T) {
	for _, st := range testStores() {
		t.Run(st.name, func(t *testing.T) {
			t.Run("ShouldSendStreamIDStatusAndReason", func(t *testing.T) {
				testCases := []struct {
					name   string
					status string
					reason string
					body   string
				}{
					{"ShouldSendReason", oauth2.SSFStreamStatusPaused, "Disabled by administrator action.", `{"stream_id":"` + testStreamID + `","status":"paused","reason":"Disabled by administrator action."}`},
					{"ShouldOmitEmptyReason", oauth2.SSFStreamStatusEnabled, "", `{"stream_id":"` + testStreamID + `","status":"enabled"}`},
				}

				for _, tc := range testCases {
					t.Run(tc.name, func(t *testing.T) {
						tx := newTestStreamTransmitter(t)
						receiver := tx.receiver(st)

						require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), newTestStreamRecord(tx.URL)))

						tx.answer(http.StatusOK, testStreamStatus(tc.status, nil))

						_, err := receiver.UpdateStreamStatus(t.Context(), tx.URL, testStreamID, tc.status, tc.reason)

						require.NoError(t, err)
						require.Len(t, tx.received(), 1)

						call := tx.received()[0]

						assert.Equal(t, testStatusPath, call.path)
						assert.Equal(t, http.MethodPost, call.method)
						assert.Empty(t, call.query)
						assert.Equal(t, "application/json", call.contentType)
						assert.JSONEq(t, tc.body, call.body)
						assert.Equal(t, []string{oauth2.ScopeSSFManage}, tx.requestedScopes())
					})
				}
			})

			t.Run("ShouldStoreStatusOn200", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)
				record := newTestStreamRecord(tx.URL)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

				// The status of the response is the one of the Transmitter, whatever was asked for.
				tx.answer(http.StatusOK, testStreamStatus(oauth2.SSFStreamStatusPaused, map[string]any{"reason": "held"}))

				status, err := receiver.UpdateStreamStatus(t.Context(), tx.URL, testStreamID, oauth2.SSFStreamStatusDisabled, "requested")

				require.NoError(t, err)
				assert.Equal(t, &ssfreceiver.StreamStatus{StreamID: testStreamID, Status: oauth2.SSFStreamStatusPaused, Reason: "held"}, status)

				record.Status, record.StatusReason = oauth2.SSFStreamStatusPaused, "held"

				requireStreamRecord(t, receiver.Store, record)
			})

			t.Run("ShouldStoreStatusOn200ThoughContextIsDone", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)
				record := newTestStreamRecord(tx.URL)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

				ctx := tx.cancelAfterResponse(t, receiver)

				tx.answer(http.StatusOK, testStreamStatus(oauth2.SSFStreamStatusDisabled, nil))

				_, err := receiver.UpdateStreamStatus(ctx, tx.URL, testStreamID, oauth2.SSFStreamStatusDisabled, "")

				require.NoError(t, err)

				record.Status, record.StatusReason = oauth2.SSFStreamStatusDisabled, ""

				requireStreamRecord(t, receiver.Store, record)
			})

			t.Run("ShouldReturnPendingOn202AndKeepRecord", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)
				record := newTestStreamRecord(tx.URL)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

				// The body of a 202 is not the status of the stream.
				tx.answer(http.StatusAccepted, testStreamStatus(oauth2.SSFStreamStatusDisabled, nil))

				status, err := receiver.UpdateStreamStatus(t.Context(), tx.URL, testStreamID, oauth2.SSFStreamStatusDisabled, "requested")

				assert.Nil(t, status)
				require.ErrorIs(t, err, ssfreceiver.ErrStreamUpdatePending)

				var e *ssfreceiver.TransmitterError

				require.ErrorAs(t, err, &e)
				assert.Equal(t, http.StatusAccepted, e.Status)

				require.Len(t, tx.received(), 1)

				requireStreamRecord(t, receiver.Store, record)
			})

			t.Run("ShouldStoreRequestedStatusWhenResponseIsRefused", func(t *testing.T) {
				testCases := []struct {
					name   string
					status any
				}{
					{"ShouldRejectUnknownStatusValue", testStreamStatus("suspended", nil)},
					{"ShouldRejectStreamIDMismatch", testStreamStatus(oauth2.SSFStreamStatusEnabled, map[string]any{"stream_id": "stream-2"})},
					{"ShouldRejectArray", []string{}},
				}

				for _, tc := range testCases {
					t.Run(tc.name, func(t *testing.T) {
						tx := newTestStreamTransmitter(t)
						receiver := tx.receiver(st)
						record := newTestStreamRecord(tx.URL)

						require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

						tx.answer(http.StatusOK, tc.status)

						status, err := receiver.UpdateStreamStatus(t.Context(), tx.URL, testStreamID, oauth2.SSFStreamStatusDisabled, "requested")

						assert.Nil(t, status)
						require.ErrorIs(t, err, ssfreceiver.ErrStreamStatus)
						require.ErrorIs(t, err, ssfreceiver.ErrStreamChangeApplied)
						assert.Equal(t, 1, strings.Count(err.Error(), "ssfreceiver:"), err.Error())

						// The Transmitter applied the update, so what was sent is stored, and nothing of the response is.
						record.Status, record.StatusReason = oauth2.SSFStreamStatusDisabled, "requested"

						requireStreamRecord(t, receiver.Store, record)
					})
				}
			})

			t.Run("ShouldStoreRequestedStatusWhenResponseIsNotRead", func(t *testing.T) {
				for _, unread := range testUnreadResponses() {
					t.Run(unread.name, func(t *testing.T) {
						tx := newTestStreamTransmitter(t)
						receiver := tx.receiver(st)
						record := newTestStreamRecord(tx.URL)

						require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

						unread.arrange(t, tx, receiver)

						status, err := receiver.UpdateStreamStatus(t.Context(), tx.URL, testStreamID, oauth2.SSFStreamStatusDisabled, "requested")

						assert.Nil(t, status)
						require.ErrorIs(t, err, ssfreceiver.ErrStreamChangeApplied)
						require.ErrorIs(t, err, ssfreceiver.ErrTransmitterUnconfirmed)
						assert.Equal(t, 1, strings.Count(err.Error(), "ssfreceiver:"), err.Error())

						require.Len(t, tx.received(), 1)

						// The 200 means the Transmitter applied the update, so what was sent is stored.
						record.Status, record.StatusReason = oauth2.SSFStreamStatusDisabled, "requested"

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

				status, err := receiver.UpdateStreamStatus(t.Context(), tx.URL, testStreamID, oauth2.SSFStreamStatusDisabled, "requested")

				// The Transmitter may have applied the update.
				assert.Nil(t, status)
				require.ErrorIs(t, err, ssfreceiver.ErrTransmitterUnconfirmed)
				assert.NotErrorIs(t, err, ssfreceiver.ErrStreamChangeApplied)

				requireStreamRecord(t, receiver.Store, record)
			})

			t.Run("ShouldRefuseBeforeAnyRequest", func(t *testing.T) {
				testCases := []struct {
					name     string
					record   func(record *ssfreceiver.StreamRecord)
					streamID string
					status   string
					expected error
				}{
					{"ShouldRejectUnknownStatusValue", nil, testStreamID, "suspended", ssfreceiver.ErrStreamRequest},
					{"ShouldRejectEmptyStatus", nil, testStreamID, "", ssfreceiver.ErrStreamRequest},
					{"ShouldRequireStreamID", nil, "", oauth2.SSFStreamStatusPaused, ssfreceiver.ErrStreamRequest},
					{"ShouldRequireRecord", nil, "stream-2", oauth2.SSFStreamStatusPaused, oauth2.ErrNotFound},
					{
						"ShouldRequireActiveRecord",
						func(record *ssfreceiver.StreamRecord) { record.State = ssfreceiver.StreamRecordPending },
						testStreamID, oauth2.SSFStreamStatusPaused, ssfreceiver.ErrStreamRequest,
					},
				}

				for _, tc := range testCases {
					t.Run(tc.name, func(t *testing.T) {
						tx := newTestStreamTransmitter(t)
						receiver := tx.receiver(st)
						record := newTestStreamRecord(tx.URL)

						if tc.record != nil {
							tc.record(record)
						}

						require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

						status, err := receiver.UpdateStreamStatus(t.Context(), tx.URL, tc.streamID, tc.status, "")

						assert.Nil(t, status)
						require.ErrorIs(t, err, tc.expected)
						assert.Empty(t, tx.received())

						requireStreamRecord(t, receiver.Store, record)
					})
				}
			})
		})
	}
}

// TestReceiverStreamStatus has what a read and an update of the status share.
func TestReceiverStreamStatus(t *testing.T) {
	for _, st := range testStores() {
		for _, sc := range testStatusCalls() {
			t.Run(st.name+"/"+sc.name, func(t *testing.T) {
				t.Run("ShouldRefuseResponse", func(t *testing.T) {
					testCases := []struct {
						name    string
						respond func(w http.ResponseWriter)
					}{
						{"ShouldRejectUnknownStatusValue", func(w http.ResponseWriter) {
							writeTestStream(w, http.StatusOK, testStreamStatus("suspended", nil))
						}},
						{"ShouldRejectStatusOfOtherCase", func(w http.ResponseWriter) {
							writeTestStream(w, http.StatusOK, testStreamStatus("Enabled", nil))
						}},
						{"ShouldRejectMissingStatus", func(w http.ResponseWriter) {
							writeTestStream(w, http.StatusOK, testStreamStatus("", map[string]any{"status": nil}))
						}},
						{"ShouldRejectStatusOfWrongType", func(w http.ResponseWriter) {
							writeTestStream(w, http.StatusOK, testStreamStatus("", map[string]any{"status": 1}))
						}},
						{"ShouldRejectStreamIDMismatch", func(w http.ResponseWriter) {
							writeTestStream(w, http.StatusOK, testStreamStatus(oauth2.SSFStreamStatusEnabled, map[string]any{"stream_id": "stream-2"}))
						}},
						{"ShouldRejectMissingStreamID", func(w http.ResponseWriter) {
							writeTestStream(w, http.StatusOK, testStreamStatus(oauth2.SSFStreamStatusEnabled, map[string]any{"stream_id": nil}))
						}},
						{"ShouldRejectReasonOfWrongType", func(w http.ResponseWriter) {
							writeTestStream(w, http.StatusOK, testStreamStatus(oauth2.SSFStreamStatusEnabled, map[string]any{"reason": 1}))
						}},
						{"ShouldRejectRepeatedMember", func(w http.ResponseWriter) {
							w.Header().Set("Content-Type", "application/json")
							_, _ = w.Write([]byte(`{"stream_id":"` + testStreamID + `","status":"enabled","status":"paused"}`))
						}},
						{"ShouldRejectOtherContentType", func(w http.ResponseWriter) {
							w.Header().Set("Content-Type", "text/plain")
							_, _ = w.Write([]byte(`{"stream_id":"` + testStreamID + `","status":"enabled"}`))
						}},
						{"ShouldRejectEmptyBody", func(w http.ResponseWriter) {
							w.Header().Set("Content-Type", "application/json")
							w.WriteHeader(http.StatusOK)
						}},
					}

					for _, tc := range testCases {
						t.Run(tc.name, func(t *testing.T) {
							tx := newTestStreamTransmitter(t)
							receiver := tx.receiver(st)
							record := newTestStreamRecord(tx.URL)

							require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

							tx.on(func(w http.ResponseWriter, _ testStreamCall) { tc.respond(w) })

							status, err := sc.call(t.Context(), receiver, tx.URL)

							assert.Nil(t, status)
							require.ErrorIs(t, err, ssfreceiver.ErrStreamStatus)

							// A read which is refused changed nothing at the Transmitter, and stores nothing.
							assert.Equal(t, sc.method == http.MethodPost, errors.Is(err, ssfreceiver.ErrStreamChangeApplied))

							if sc.method == http.MethodGet {
								requireStreamRecord(t, receiver.Store, record)
							}
						})
					}
				})

				t.Run("ShouldReturnTransmitterErrorAndKeepRecord", func(t *testing.T) {
					testCases := []struct {
						name     string
						status   int
						expected error
					}{
						{"ShouldReturnUnauthorizedOn401", http.StatusUnauthorized, ssfreceiver.ErrTransmitterUnauthorized},
						{"ShouldReturnForbiddenOn403", http.StatusForbidden, ssfreceiver.ErrTransmitterForbidden},
						{"ShouldReturnNotFoundOn404", http.StatusNotFound, ssfreceiver.ErrStreamNotFound},
						{"ShouldReturnErrorOn400", http.StatusBadRequest, nil},
						{"ShouldReturnErrorOn204", http.StatusNoContent, nil},
					}

					for _, tc := range testCases {
						t.Run(tc.name, func(t *testing.T) {
							tx := newTestStreamTransmitter(t)
							receiver := tx.receiver(st)
							record := newTestStreamRecord(tx.URL)

							require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

							tx.answer(tc.status, nil)

							status, err := sc.call(t.Context(), receiver, tx.URL)

							assert.Nil(t, status)

							var e *ssfreceiver.TransmitterError

							require.ErrorAs(t, err, &e)
							assert.Equal(t, tc.status, e.Status)

							if tc.expected != nil {
								require.ErrorIs(t, err, tc.expected)
							}

							assert.NotErrorIs(t, err, ssfreceiver.ErrStreamChangeApplied)

							assert.Equal(t, sc.method, tx.received()[0].method)

							requireStreamRecord(t, receiver.Store, record)
						})
					}
				})

				t.Run("ShouldReturnNotSupportedWithoutEndpoint", func(t *testing.T) {
					tx := newTestStreamTransmitter(t)
					tx.metadata = map[string]any{"status_endpoint": nil}

					receiver := tx.receiver(st)
					record := newTestStreamRecord(tx.URL)

					require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

					status, err := sc.call(t.Context(), receiver, tx.URL)

					assert.Nil(t, status)
					require.ErrorIs(t, err, ssfreceiver.ErrEndpointNotSupported)
					assert.Empty(t, tx.received())

					requireStreamRecord(t, receiver.Store, record)
				})
			})
		}
	}
}
