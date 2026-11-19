// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/ssfreceiver"
)

// testVerificationStore is a store which can refuse to set or to withdraw the requested verification.
type testVerificationStore struct {
	ssfreceiver.Storage

	failRequest  bool
	failWithdraw bool
}

func (s testVerificationStore) SetSSFReceiverStreamVerificationState(ctx context.Context, issuer, streamID, state string, requestedAt time.Time) (err error) {
	if err = ctx.Err(); err != nil {
		return err
	}

	if (requestedAt.IsZero() && s.failWithdraw) || (!requestedAt.IsZero() && s.failRequest) {
		return errors.New("the store is not available")
	}

	return s.Storage.SetSSFReceiverStreamVerificationState(ctx, issuer, streamID, state, requestedAt)
}

func testVerificationBody(t *testing.T, call testStreamCall) (state string) {
	t.Helper()

	var body map[string]string

	require.NoError(t, json.Unmarshal([]byte(call.body), &body))

	// SSF Section 8.1.4.2: the request has the 'stream_id' and the 'state', and nothing else.
	require.Len(t, body, 2)
	assert.Equal(t, testStreamID, body["stream_id"])

	return body["state"]
}

// requireVerificationRequested checks the record has only the requested verification changed, to the state.
func requireVerificationRequested(t *testing.T, store ssfreceiver.Storage, record *ssfreceiver.StreamRecord, state string) {
	t.Helper()

	stored, err := store.GetSSFReceiverStream(t.Context(), record.Issuer, record.StreamID)
	require.NoError(t, err)

	assert.Equal(t, state, stored.VerificationState)

	if state == "" {
		assert.True(t, stored.VerificationRequestedAt.IsZero())
	} else {
		assert.WithinDuration(t, time.Now(), stored.VerificationRequestedAt, time.Minute)
	}

	expected := record.Clone()

	expected.VerificationState, expected.VerificationRequestedAt = stored.VerificationState, stored.VerificationRequestedAt

	assert.Equal(t, expected, stored)
}

func TestReceiverRequestStreamVerification(t *testing.T) {
	for _, st := range testStores() {
		t.Run(st.name, func(t *testing.T) {
			t.Run("ShouldStoreStateBeforeRequest", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)
				record := newTestStreamRecord(tx.URL)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

				var during *ssfreceiver.StreamRecord

				// The verification event may be delivered before the response to the request.
				tx.on(func(w http.ResponseWriter, _ testStreamCall) {
					during, _ = receiver.Store.GetSSFReceiverStream(context.Background(), tx.URL, testStreamID)

					w.WriteHeader(http.StatusNoContent)
				})

				require.NoError(t, receiver.RequestStreamVerification(t.Context(), tx.URL, testStreamID))

				require.Len(t, tx.received(), 1)

				call := tx.received()[0]

				assert.Equal(t, testVerifyPath, call.path)
				assert.Equal(t, http.MethodPost, call.method)
				assert.Empty(t, call.query)
				assert.Equal(t, "application/json", call.contentType)
				assert.Equal(t, "Bearer "+testStreamToken, call.authorization)

				// Profile Section 2.7.3: the 'ssf.manage' scope allows Stream Verification.
				assert.Equal(t, []string{oauth2.ScopeSSFManage}, tx.requestedScopes())

				state := testVerificationBody(t, call)

				// The state is 32 random bytes, and not the one of an earlier request.
				assert.Len(t, state, 43)
				assert.NotEqual(t, record.VerificationState, state)

				require.NotNil(t, during)
				assert.Equal(t, state, during.VerificationState)
				assert.WithinDuration(t, time.Now(), during.VerificationRequestedAt, time.Minute)

				requireVerificationRequested(t, receiver.Store, record, state)

				// The verification event with the state verifies the stream.
				require.NoError(t, receiver.Store.ConsumeSSFReceiverStreamVerificationState(t.Context(), tx.URL, testStreamID, state, time.Now()))
			})

			t.Run("ShouldUseNewStateForEachRequest", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)
				record := newTestStreamRecord(tx.URL)

				record.MinVerificationInterval = 0

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

				tx.answer(http.StatusNoContent, nil)

				require.NoError(t, receiver.RequestStreamVerification(t.Context(), tx.URL, testStreamID))
				require.NoError(t, receiver.RequestStreamVerification(t.Context(), tx.URL, testStreamID))

				require.Len(t, tx.received(), 2)

				first, second := testVerificationBody(t, tx.received()[0]), testVerificationBody(t, tx.received()[1])

				assert.NotEqual(t, first, second)

				requireVerificationRequested(t, receiver.Store, record, second)
			})

			t.Run("ShouldRefuseInsideMinVerificationInterval", func(t *testing.T) {
				testCases := []struct {
					name        string
					interval    int
					requestedAt time.Duration
					verifiedAt  time.Duration
					refused     bool
				}{
					{"ShouldRefuseAfterRecentRequest", 60, 10 * time.Second, 0, true},
					{"ShouldRefuseAfterRecentVerification", 60, 0, 10 * time.Second, true},
					{"ShouldRefuseAfterRecentVerificationOfOlderRequest", 60, time.Hour, 10 * time.Second, true},
					{"ShouldRefuseAfterRecentRequestAndOlderVerification", 60, 10 * time.Second, time.Hour, true},
					{"ShouldRefuseWhenRequestIsAhead", 60, -time.Hour, 0, true},
					{"ShouldPermitAfterInterval", 60, 2 * time.Minute, 2 * time.Minute, false},
					{"ShouldPermitFirstRequest", 60, 0, 0, false},
					{"ShouldPermitWithoutInterval", 0, time.Second, time.Second, false},
					{"ShouldPermitLargestInterval", int(^uint(0) >> 1), 0, 0, false},
					{"ShouldRefuseInsideLargestInterval", int(^uint(0) >> 1), time.Hour, 0, true},
				}

				for _, tc := range testCases {
					t.Run(tc.name, func(t *testing.T) {
						tx := newTestStreamTransmitter(t)
						receiver := tx.receiver(st)
						record := newTestStreamRecord(tx.URL)

						record.MinVerificationInterval = tc.interval
						record.VerificationState, record.VerificationRequestedAt, record.VerifiedAt = "", time.Time{}, time.Time{}

						if tc.requestedAt != 0 {
							record.VerificationState, record.VerificationRequestedAt = "state-1", time.Now().Add(-tc.requestedAt).UTC()
						}

						if tc.verifiedAt != 0 {
							record.VerifiedAt = time.Now().Add(-tc.verifiedAt).UTC()
						}

						require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

						tx.answer(http.StatusNoContent, nil)

						err := receiver.RequestStreamVerification(t.Context(), tx.URL, testStreamID)

						if !tc.refused {
							require.NoError(t, err)
							assert.Len(t, tx.received(), 1)

							return
						}

						// SSF Section 8.1.1: the request is refused before it is made, and the pending one is kept.
						require.ErrorIs(t, err, ssfreceiver.ErrVerificationInterval)
						assert.Empty(t, tx.received())

						requireStreamRecord(t, receiver.Store, record)
					})
				}
			})

			t.Run("ShouldRefuseInsideMinVerificationIntervalBeforeDiscovery", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)
				record := newTestStreamRecord(tx.URL)

				record.MinVerificationInterval = 60
				record.VerificationState, record.VerificationRequestedAt, record.VerifiedAt = "", time.Time{}, time.Now().Add(-10*time.Second).UTC()

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

				// Metadata which is not valid fails a discovery, which is not made.
				tx.metadata = map[string]any{"issuer": "https://other.example.com"}

				require.ErrorIs(t, receiver.RequestStreamVerification(t.Context(), tx.URL, testStreamID), ssfreceiver.ErrVerificationInterval)
				assert.Empty(t, tx.received())
			})

			t.Run("ShouldReturnThrottledOn429", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)
				record := newTestStreamRecord(tx.URL)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

				tx.on(func(w http.ResponseWriter, _ testStreamCall) {
					w.Header().Set("Retry-After", "30")
					w.WriteHeader(http.StatusTooManyRequests)
				})

				err := receiver.RequestStreamVerification(t.Context(), tx.URL, testStreamID)

				require.ErrorIs(t, err, ssfreceiver.ErrTransmitterThrottled)

				var e *ssfreceiver.TransmitterError

				require.ErrorAs(t, err, &e)
				assert.Equal(t, http.StatusTooManyRequests, e.Status)
				assert.Equal(t, 30*time.Second, e.RetryAfter)

				require.Len(t, tx.received(), 1)

				requireVerificationRequested(t, receiver.Store, record, "")
			})

			t.Run("ShouldClearStateWhenRequestFails", func(t *testing.T) {
				testCases := []struct {
					name     string
					status   int
					expected error
				}{
					{"ShouldClearOn400", http.StatusBadRequest, nil},
					{"ShouldClearOn401", http.StatusUnauthorized, ssfreceiver.ErrTransmitterUnauthorized},
					{"ShouldClearOn404", http.StatusNotFound, ssfreceiver.ErrStreamNotFound},
					{"ShouldClearOn403", http.StatusForbidden, ssfreceiver.ErrTransmitterForbidden},
					{"ShouldClearOn302", http.StatusFound, nil},
				}

				for _, tc := range testCases {
					t.Run(tc.name, func(t *testing.T) {
						tx := newTestStreamTransmitter(t)
						receiver := tx.receiver(st)
						record := newTestStreamRecord(tx.URL)

						require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

						tx.answer(tc.status, nil)

						err := receiver.RequestStreamVerification(t.Context(), tx.URL, testStreamID)

						var e *ssfreceiver.TransmitterError

						require.ErrorAs(t, err, &e)
						assert.Equal(t, tc.status, e.Status)

						if tc.expected != nil {
							require.ErrorIs(t, err, tc.expected)
						}

						assert.NotErrorIs(t, err, ssfreceiver.ErrStreamUpdatePending)

						require.Len(t, tx.received(), 1)
						assert.NotContains(t, err.Error(), testVerificationBody(t, tx.received()[0]))

						// The time of the last verification is kept.
						requireVerificationRequested(t, receiver.Store, record, "")
					})
				}
			})

			t.Run("ShouldAcceptAny2xxAndKeepState", func(t *testing.T) {
				for _, status := range []int{http.StatusOK, http.StatusAccepted, http.StatusNoContent} {
					t.Run(http.StatusText(status), func(t *testing.T) {
						tx := newTestStreamTransmitter(t)
						receiver := tx.receiver(st)
						record := newTestStreamRecord(tx.URL)

						require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

						// A Transmitter which answers with another 2xx accepted the request, and sends the event.
						tx.on(func(w http.ResponseWriter, _ testStreamCall) {
							w.WriteHeader(status)

							if status != http.StatusNoContent {
								_, _ = w.Write([]byte("ok"))
							}
						})

						require.NoError(t, receiver.RequestStreamVerification(t.Context(), tx.URL, testStreamID))

						require.Len(t, tx.received(), 1)

						requireVerificationRequested(t, receiver.Store, record, testVerificationBody(t, tx.received()[0]))
					})
				}
			})

			t.Run("ShouldKeepStateWhenRequestMayBeProcessed", func(t *testing.T) {
				for _, status := range []int{http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
					t.Run(http.StatusText(status), func(t *testing.T) {
						tx := newTestStreamTransmitter(t)
						receiver := tx.receiver(st)
						record := newTestStreamRecord(tx.URL)

						require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

						// The server behind a gateway may have processed the request.
						tx.answer(status, nil)

						err := receiver.RequestStreamVerification(t.Context(), tx.URL, testStreamID)

						var e *ssfreceiver.TransmitterError

						require.ErrorAs(t, err, &e)
						assert.Equal(t, status, e.Status)

						// A POST is not sent again.
						require.Len(t, tx.received(), 1)

						state := testVerificationBody(t, tx.received()[0])

						assert.NotContains(t, err.Error(), state)

						requireVerificationRequested(t, receiver.Store, record, state)
					})
				}
			})

			t.Run("ShouldKeepStateWhenResponseIsNotRead", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)
				record := newTestStreamRecord(tx.URL)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

				// The metadata is read before the limit is lowered.
				_, err := receiver.Discover(t.Context(), tx.URL)
				require.NoError(t, err)

				receiver.Config.MaxResponseBytes = 8

				tx.on(func(w http.ResponseWriter, _ testStreamCall) {
					_, _ = w.Write([]byte("the request was accepted"))
				})

				require.Error(t, receiver.RequestStreamVerification(t.Context(), tx.URL, testStreamID))

				require.Len(t, tx.received(), 1)

				requireVerificationRequested(t, receiver.Store, record, testVerificationBody(t, tx.received()[0]))
			})

			t.Run("ShouldClearStateWhenRequestFailsThoughContextIsDone", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)
				record := newTestStreamRecord(tx.URL)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

				ctx := tx.cancelAfterResponse(t, receiver)

				receiver.Store = testVerificationStore{Storage: receiver.Store}

				tx.answer(http.StatusNotFound, nil)

				require.ErrorIs(t, receiver.RequestStreamVerification(ctx, tx.URL, testStreamID), ssfreceiver.ErrStreamNotFound)

				requireVerificationRequested(t, receiver.Store, record, "")
			})

			t.Run("ShouldClearStateWhenRequestIsNotSent", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)
				record := newTestStreamRecord(tx.URL)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

				// The metadata is read before the token is asked for.
				_, err := receiver.Discover(t.Context(), tx.URL)
				require.NoError(t, err)

				receiver.Config.Authorizer = &ssfreceiver.BearerAuthorizer{Token: func(context.Context, string, string) (token string, err error) {
					return "", errors.New("no token")
				}}

				require.ErrorContains(t, receiver.RequestStreamVerification(t.Context(), tx.URL, testStreamID), "no token")

				assert.Empty(t, tx.received())

				requireVerificationRequested(t, receiver.Store, record, "")
			})

			t.Run("ShouldKeepStateWhenRequestIsNotAnswered", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)
				record := newTestStreamRecord(tx.URL)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

				// The Transmitter has the request, and may send the verification event though it gave no response.
				tx.on(func(w http.ResponseWriter, _ testStreamCall) {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err == nil {
						_ = conn.Close()
					}
				})

				err := receiver.RequestStreamVerification(t.Context(), tx.URL, testStreamID)

				require.Error(t, err)

				var e *ssfreceiver.TransmitterError

				require.NotErrorAs(t, err, &e)

				// A POST is not sent again.
				require.Len(t, tx.received(), 1)

				state := testVerificationBody(t, tx.received()[0])

				assert.NotContains(t, err.Error(), state)

				requireVerificationRequested(t, receiver.Store, record, state)
			})

			t.Run("ShouldReturnNotSupportedWithoutEndpoint", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				tx.metadata = map[string]any{"verification_endpoint": nil}

				receiver := tx.receiver(st)
				record := newTestStreamRecord(tx.URL)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

				require.ErrorIs(t, receiver.RequestStreamVerification(t.Context(), tx.URL, testStreamID), ssfreceiver.ErrEndpointNotSupported)

				assert.Empty(t, tx.received())

				requireStreamRecord(t, receiver.Store, record)
			})

			t.Run("ShouldRefuseBeforeAnyRequest", func(t *testing.T) {
				testCases := []struct {
					name     string
					record   func(record *ssfreceiver.StreamRecord)
					streamID string
					expected error
				}{
					{"ShouldRequireStreamID", nil, "", ssfreceiver.ErrStreamRequest},
					{"ShouldRequireRecord", nil, "stream-2", oauth2.ErrNotFound},
					{
						"ShouldRequireActiveRecord",
						func(record *ssfreceiver.StreamRecord) { record.State = ssfreceiver.StreamRecordPending },
						testStreamID, ssfreceiver.ErrStreamRequest,
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

						require.ErrorIs(t, receiver.RequestStreamVerification(t.Context(), tx.URL, tc.streamID), tc.expected)

						assert.Empty(t, tx.received())

						requireStreamRecord(t, receiver.Store, record)
					})
				}
			})

			t.Run("ShouldNotRequestWhenStateIsNotStored", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)
				record := newTestStreamRecord(tx.URL)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

				receiver.Store = testVerificationStore{Storage: receiver.Store, failRequest: true}

				require.ErrorContains(t, receiver.RequestStreamVerification(t.Context(), tx.URL, testStreamID), "the store is not available")

				assert.Empty(t, tx.received())

				requireStreamRecord(t, receiver.Store, record)
			})

			t.Run("ShouldReturnBothErrorsWhenStateIsNotCleared", func(t *testing.T) {
				tx := newTestStreamTransmitter(t)
				receiver := tx.receiver(st)
				record := newTestStreamRecord(tx.URL)

				require.NoError(t, receiver.Store.CreateSSFReceiverStream(t.Context(), record))

				receiver.Store = testVerificationStore{Storage: receiver.Store, failWithdraw: true}

				tx.answer(http.StatusNotFound, nil)

				err := receiver.RequestStreamVerification(t.Context(), tx.URL, testStreamID)

				require.ErrorIs(t, err, ssfreceiver.ErrStreamNotFound)
				require.ErrorContains(t, err, "the store is not available")
			})
		})
	}
}
