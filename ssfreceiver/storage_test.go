// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/ssfreceiver"
	"authelia.com/provider/oauth2/storage"
)

const (
	testIssuer      = "https://tx.example.com"
	testOtherIssuer = "https://other.example.com"
	testPushURL     = "https://rx.example.com/push/1"
)

type testStore struct {
	name string
	new  func(clock func() time.Time) ssfreceiver.Storage
}

func testStores() []testStore {
	return []testStore{
		{
			name: "MemoryStore",
			new: func(clock func() time.Time) ssfreceiver.Storage {
				s := storage.NewMemoryStore()
				s.Clock = clock

				return s
			},
		},
		{
			name: "HydratingMemoryStore",
			new: func(clock func() time.Time) ssfreceiver.Storage {
				s := storage.NewHydratingMemoryStore()
				s.Clock = clock

				return s
			},
		},
	}
}

func newTestRecord(issuer, streamID, endpoint string) *ssfreceiver.StreamRecord {
	return &ssfreceiver.StreamRecord{
		Issuer:          issuer,
		StreamID:        streamID,
		Audience:        []string{"https://rx.example.com"},
		Delivery:        oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPush, EndpointURL: endpoint, AuthorizationHeader: "Bearer s"},
		EventsRequested: []string{"a", "b"},
		EventsDelivered: []string{"a"},
		Status:          oauth2.SSFStreamStatusEnabled,
		State:           ssfreceiver.StreamRecordActive,
	}
}

func mutateTestRecord(record *ssfreceiver.StreamRecord) {
	record.Audience[0] = "mutated"
	record.EventsRequested[0] = "mutated"
	record.EventsDelivered[0] = "mutated"
	record.Delivery.AuthorizationHeader = "mutated"
	record.Status = oauth2.SSFStreamStatusDisabled
	record.VerificationState = "mutated"
}

func TestStreamStorage(t *testing.T) {
	for _, st := range testStores() {
		t.Run(st.name, func(t *testing.T) {
			ctx := t.Context()

			t.Run("ShouldNotAliasStoredRecord", func(t *testing.T) {
				s := st.new(nil)

				expected := newTestRecord(testIssuer, "s1", testPushURL)
				record := newTestRecord(testIssuer, "s1", testPushURL)

				require.NoError(t, s.CreateSSFReceiverStream(ctx, record))

				mutateTestRecord(record)

				got, err := s.GetSSFReceiverStream(ctx, testIssuer, "s1")
				require.NoError(t, err)
				assert.Equal(t, expected, got)

				mutateTestRecord(got)

				got, err = s.GetSSFReceiverStream(ctx, testIssuer, "s1")
				require.NoError(t, err)
				assert.Equal(t, expected, got)

				got, err = s.GetSSFReceiverStreamByPushEndpoint(ctx, testPushURL)
				require.NoError(t, err)
				assert.Equal(t, expected, got)

				mutateTestRecord(got)

				got, err = s.GetSSFReceiverStreamByPushEndpoint(ctx, testPushURL)
				require.NoError(t, err)
				assert.Equal(t, expected, got)

				list, err := s.ListSSFReceiverStreams(ctx, testIssuer)
				require.NoError(t, err)
				require.Len(t, list, 1)
				assert.Equal(t, expected, list[0])

				mutateTestRecord(list[0])

				list, err = s.ListSSFReceiverStreams(ctx, testIssuer)
				require.NoError(t, err)
				require.Len(t, list, 1)
				assert.Equal(t, expected, list[0])

				update := newTestRecord(testIssuer, "s1", testPushURL)
				update.EventsDelivered = []string{"a", "b"}

				expected.EventsDelivered = []string{"a", "b"}

				require.NoError(t, s.UpdateSSFReceiverStream(ctx, testIssuer, "s1", update))

				mutateTestRecord(update)

				got, err = s.GetSSFReceiverStream(ctx, testIssuer, "s1")
				require.NoError(t, err)
				assert.Equal(t, expected, got)
			})

			t.Run("ShouldReturnNotFound", func(t *testing.T) {
				s := st.new(nil)

				require.NoError(t, s.CreateSSFReceiverStream(ctx, newTestRecord(testIssuer, "s1", testPushURL)))

				_, err := s.GetSSFReceiverStream(ctx, testIssuer, "nope")
				assert.ErrorIs(t, err, oauth2.ErrNotFound)

				_, err = s.GetSSFReceiverStream(ctx, testOtherIssuer, "s1")
				assert.ErrorIs(t, err, oauth2.ErrNotFound)

				_, err = s.GetSSFReceiverStreamByPushEndpoint(ctx, "https://rx.example.com/push/2")
				assert.ErrorIs(t, err, oauth2.ErrNotFound)

				_, err = s.GetSSFReceiverStreamByPushEndpoint(ctx, "")
				assert.ErrorIs(t, err, oauth2.ErrNotFound)

				assert.ErrorIs(t, s.UpdateSSFReceiverStream(ctx, testOtherIssuer, "s1", newTestRecord(testOtherIssuer, "s1", "")), oauth2.ErrNotFound)
				assert.ErrorIs(t, s.UpdateSSFReceiverStreamStatus(ctx, testOtherIssuer, "s1", oauth2.SSFStreamStatusPaused, ""), oauth2.ErrNotFound)
				assert.ErrorIs(t, s.SetSSFReceiverStreamVerificationState(ctx, testOtherIssuer, "s1", "state", time.Now()), oauth2.ErrNotFound)
				assert.ErrorIs(t, s.ConsumeSSFReceiverStreamVerificationState(ctx, testOtherIssuer, "s1", "state", time.Now()), oauth2.ErrNotFound)
				assert.ErrorIs(t, s.SetSSFReceiverStreamVerifiedAt(ctx, testOtherIssuer, "s1", time.Now()), oauth2.ErrNotFound)
				assert.ErrorIs(t, s.DeleteSSFReceiverStream(ctx, testOtherIssuer, "s1"), oauth2.ErrNotFound)

				list, err := s.ListSSFReceiverStreams(ctx, testOtherIssuer)
				require.NoError(t, err)
				assert.Empty(t, list)
			})

			t.Run("ShouldRejectInvalidRecord", func(t *testing.T) {
				unknownState := newTestRecord(testIssuer, "s1", testPushURL)
				unknownState.State = "unknown"

				noState := newTestRecord(testIssuer, "s1", testPushURL)
				noState.State = ""

				testCases := []struct {
					name   string
					record *ssfreceiver.StreamRecord
				}{
					{"ShouldRejectNil", nil},
					{"ShouldRejectEmptyIssuer", newTestRecord("", "s1", testPushURL)},
					{"ShouldRejectActiveWithoutStreamID", newTestRecord(testIssuer, "", testPushURL)},
					{"ShouldRejectUnknownState", unknownState},
					{"ShouldRejectEmptyState", noState},
				}

				for _, tc := range testCases {
					t.Run(tc.name, func(t *testing.T) {
						s := st.new(nil)

						assert.ErrorIs(t, s.CreateSSFReceiverStream(ctx, tc.record), oauth2.ErrServerError)

						require.NoError(t, s.CreateSSFReceiverStream(ctx, newTestRecord(testIssuer, "s1", testPushURL)))

						assert.ErrorIs(t, s.UpdateSSFReceiverStream(ctx, testIssuer, "s1", tc.record), oauth2.ErrServerError)

						got, err := s.GetSSFReceiverStream(ctx, testIssuer, "s1")
						require.NoError(t, err)
						assert.Equal(t, newTestRecord(testIssuer, "s1", testPushURL), got)
					})
				}

				t.Run("ShouldRejectChangedIssuerOnUpdate", func(t *testing.T) {
					s := st.new(nil)

					require.NoError(t, s.CreateSSFReceiverStream(ctx, newTestRecord(testIssuer, "s1", testPushURL)))

					assert.ErrorIs(t, s.UpdateSSFReceiverStream(ctx, testIssuer, "s1", newTestRecord(testOtherIssuer, "s1", testPushURL)), oauth2.ErrServerError)
				})
			})

			t.Run("ShouldConflictOnSameKeyOrPushEndpoint", func(t *testing.T) {
				s := st.new(nil)

				require.NoError(t, s.CreateSSFReceiverStream(ctx, newTestRecord(testIssuer, "s1", testPushURL)))

				assert.ErrorIs(t, s.CreateSSFReceiverStream(ctx, newTestRecord(testIssuer, "s1", "https://rx.example.com/push/2")), ssfreceiver.ErrStreamRecordConflict)
				assert.ErrorIs(t, s.CreateSSFReceiverStream(ctx, newTestRecord(testOtherIssuer, "s9", testPushURL)), ssfreceiver.ErrStreamRecordConflict)

				// The stream ID is unique per Transmitter only.
				require.NoError(t, s.CreateSSFReceiverStream(ctx, newTestRecord(testOtherIssuer, "s1", "https://rx.example.com/push/2")))

				// A poll record holds the Transmitter endpoint, which is not a push endpoint of this Receiver.
				poll := newTestRecord(testIssuer, "s2", testPushURL)
				poll.Delivery = oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPoll, EndpointURL: testPushURL}

				require.NoError(t, s.CreateSSFReceiverStream(ctx, poll))

				got, err := s.GetSSFReceiverStreamByPushEndpoint(ctx, testPushURL)
				require.NoError(t, err)
				assert.Equal(t, "s1", got.StreamID)

				assert.ErrorIs(t, s.UpdateSSFReceiverStream(ctx, testOtherIssuer, "s1", newTestRecord(testOtherIssuer, "s1", testPushURL)), ssfreceiver.ErrStreamRecordConflict)
			})

			t.Run("ShouldCreatePendingAndActivate", func(t *testing.T) {
				s := st.new(nil)

				pending := newTestRecord(testIssuer, "", testPushURL)
				pending.State = ssfreceiver.StreamRecordPending
				pending.EventsDelivered = nil

				require.NoError(t, s.CreateSSFReceiverStream(ctx, pending))

				// One pending record without a stream ID per Transmitter.
				second := newTestRecord(testIssuer, "", "https://rx.example.com/push/2")
				second.State = ssfreceiver.StreamRecordPending

				assert.ErrorIs(t, s.CreateSSFReceiverStream(ctx, second), ssfreceiver.ErrStreamRecordConflict)

				got, err := s.GetSSFReceiverStreamByPushEndpoint(ctx, testPushURL)
				require.NoError(t, err)
				assert.Equal(t, ssfreceiver.StreamRecordPending, got.State)

				require.NoError(t, s.CreateSSFReceiverStream(ctx, newTestRecord(testIssuer, "taken", "https://rx.example.com/push/3")))

				got.StreamID, got.State = "taken", ssfreceiver.StreamRecordActive

				assert.ErrorIs(t, s.UpdateSSFReceiverStream(ctx, testIssuer, "", got), ssfreceiver.ErrStreamRecordConflict)

				got.StreamID, got.EventsDelivered = "s1", []string{"a"}

				require.NoError(t, s.UpdateSSFReceiverStream(ctx, testIssuer, "", got))

				_, err = s.GetSSFReceiverStream(ctx, testIssuer, "")
				assert.ErrorIs(t, err, oauth2.ErrNotFound)

				got, err = s.GetSSFReceiverStream(ctx, testIssuer, "s1")
				require.NoError(t, err)
				assert.Equal(t, newTestRecord(testIssuer, "s1", testPushURL), got)

				list, err := s.ListSSFReceiverStreams(ctx, testIssuer)
				require.NoError(t, err)
				require.Len(t, list, 2)
				assert.Equal(t, "s1", list[0].StreamID)
				assert.Equal(t, "taken", list[1].StreamID)
			})

			t.Run("ShouldUpdateConfigurationOnly", func(t *testing.T) {
				s := st.new(nil)

				at := time.Unix(1700000000, 0).UTC()

				require.NoError(t, s.CreateSSFReceiverStream(ctx, newTestRecord(testIssuer, "s1", testPushURL)))
				require.NoError(t, s.UpdateSSFReceiverStreamStatus(ctx, testIssuer, "s1", oauth2.SSFStreamStatusPaused, "maintenance"))
				require.NoError(t, s.SetSSFReceiverStreamVerificationState(ctx, testIssuer, "s1", "state", at))
				require.NoError(t, s.SetSSFReceiverStreamVerifiedAt(ctx, testIssuer, "s1", at.Add(-time.Minute)))

				update := newTestRecord(testIssuer, "s1", "https://rx.example.com/push/2")
				update.Delivery.AuthorizationHeader = "Bearer n"
				update.MinVerificationInterval = 30
				update.InactivityTimeout = 600
				update.VerifiedAt = at.Add(-time.Hour)

				require.NoError(t, s.UpdateSSFReceiverStream(ctx, testIssuer, "s1", update))

				got, err := s.GetSSFReceiverStream(ctx, testIssuer, "s1")
				require.NoError(t, err)

				assert.Equal(t, "Bearer n", got.Delivery.AuthorizationHeader)
				assert.Equal(t, 30, got.MinVerificationInterval)
				assert.Equal(t, 600, got.InactivityTimeout)
				assert.Equal(t, at.Add(-time.Minute), got.VerifiedAt)
				assert.Equal(t, oauth2.SSFStreamStatusPaused, got.Status)
				assert.Equal(t, "maintenance", got.StatusReason)
				assert.Equal(t, "state", got.VerificationState)
				assert.Equal(t, at, got.VerificationRequestedAt)

				_, err = s.GetSSFReceiverStreamByPushEndpoint(ctx, testPushURL)
				assert.ErrorIs(t, err, oauth2.ErrNotFound)

				got, err = s.GetSSFReceiverStreamByPushEndpoint(ctx, "https://rx.example.com/push/2")
				require.NoError(t, err)
				assert.Equal(t, "s1", got.StreamID)
			})

			t.Run("ShouldSetPendingAuthorizationHeaderOnly", func(t *testing.T) {
				s := st.new(nil)

				created := newTestRecord(testIssuer, "s1", testPushURL)
				created.PendingAuthorizationHeader = "Bearer created"

				require.NoError(t, s.CreateSSFReceiverStream(ctx, created))

				expected := newTestRecord(testIssuer, "s1", testPushURL)
				expected.PendingAuthorizationHeader = "Bearer created"

				got, err := s.GetSSFReceiverStream(ctx, testIssuer, "s1")
				require.NoError(t, err)
				assert.Equal(t, expected, got)

				require.NoError(t, s.SetSSFReceiverStreamPendingAuthorizationHeader(ctx, testIssuer, "s1", "Bearer p"))

				expected.PendingAuthorizationHeader = "Bearer p"

				got, err = s.GetSSFReceiverStream(ctx, testIssuer, "s1")
				require.NoError(t, err)
				assert.Equal(t, expected, got)

				// The record which is read shares no memory with the stored one.
				got.PendingAuthorizationHeader = "mutated"

				got, err = s.GetSSFReceiverStreamByPushEndpoint(ctx, testPushURL)
				require.NoError(t, err)
				assert.Equal(t, expected, got)

				// An update of the record keeps the pending secret, whatever the record has.
				for _, pending := range []string{"", "Bearer other"} {
					update := newTestRecord(testIssuer, "s1", testPushURL)
					update.Delivery.AuthorizationHeader = "Bearer n"
					update.PendingAuthorizationHeader = pending

					require.NoError(t, s.UpdateSSFReceiverStream(ctx, testIssuer, "s1", update))
				}

				expected.Delivery.AuthorizationHeader = "Bearer n"

				got, err = s.GetSSFReceiverStream(ctx, testIssuer, "s1")
				require.NoError(t, err)
				assert.Equal(t, expected, got)

				require.NoError(t, s.SetSSFReceiverStreamPendingAuthorizationHeader(ctx, testIssuer, "s1", ""))

				expected.PendingAuthorizationHeader = ""

				got, err = s.GetSSFReceiverStream(ctx, testIssuer, "s1")
				require.NoError(t, err)
				assert.Equal(t, expected, got)

				assert.ErrorIs(t, s.SetSSFReceiverStreamPendingAuthorizationHeader(ctx, testIssuer, "missing", "Bearer p"), oauth2.ErrNotFound)
				assert.ErrorIs(t, s.SetSSFReceiverStreamPendingAuthorizationHeader(ctx, testOtherIssuer, "s1", "Bearer p"), oauth2.ErrNotFound)
			})

			t.Run("ShouldKeepVerifiedAtOnUpdate", func(t *testing.T) {
				s := st.new(nil)

				requested := time.Unix(1700000000, 0).UTC()
				verified := requested.Add(time.Minute)

				require.NoError(t, s.CreateSSFReceiverStream(ctx, newTestRecord(testIssuer, "s1", testPushURL)))
				require.NoError(t, s.SetSSFReceiverStreamVerificationState(ctx, testIssuer, "s1", "state", requested))
				require.NoError(t, s.ConsumeSSFReceiverStreamVerificationState(ctx, testIssuer, "s1", "state", verified))

				// A record built from a Transmitter response has no VerifiedAt.
				require.NoError(t, s.UpdateSSFReceiverStream(ctx, testIssuer, "s1", newTestRecord(testIssuer, "s1", testPushURL)))

				got, err := s.GetSSFReceiverStream(ctx, testIssuer, "s1")
				require.NoError(t, err)
				assert.Equal(t, verified, got.VerifiedAt)

				// A verification the Receiver did not request sets only VerifiedAt.
				require.NoError(t, s.SetSSFReceiverStreamVerificationState(ctx, testIssuer, "s1", "next", verified))
				require.NoError(t, s.SetSSFReceiverStreamVerifiedAt(ctx, testIssuer, "s1", verified.Add(time.Minute)))

				expected := newTestRecord(testIssuer, "s1", testPushURL)
				expected.VerificationState, expected.VerificationRequestedAt, expected.VerifiedAt = "next", verified, verified.Add(time.Minute)

				got, err = s.GetSSFReceiverStream(ctx, testIssuer, "s1")
				require.NoError(t, err)
				assert.Equal(t, expected, got)
			})

			t.Run("ShouldDelete", func(t *testing.T) {
				s := st.new(nil)

				require.NoError(t, s.CreateSSFReceiverStream(ctx, newTestRecord(testIssuer, "s1", testPushURL)))
				require.NoError(t, s.DeleteSSFReceiverStream(ctx, testIssuer, "s1"))

				_, err := s.GetSSFReceiverStream(ctx, testIssuer, "s1")
				assert.ErrorIs(t, err, oauth2.ErrNotFound)

				assert.ErrorIs(t, s.DeleteSSFReceiverStream(ctx, testIssuer, "s1"), oauth2.ErrNotFound)

				require.NoError(t, s.CreateSSFReceiverStream(ctx, newTestRecord(testIssuer, "s1", testPushURL)))
			})

			t.Run("ShouldConsumeVerificationStateOnce", func(t *testing.T) {
				s := st.new(nil)

				requested := time.Unix(1700000000, 0).UTC()
				verified := requested.Add(time.Minute)

				require.NoError(t, s.CreateSSFReceiverStream(ctx, newTestRecord(testIssuer, "s1", testPushURL)))

				// Nothing was requested.
				assert.ErrorIs(t, s.ConsumeSSFReceiverStreamVerificationState(ctx, testIssuer, "s1", "", verified), ssfreceiver.ErrVerificationStateMismatch)

				require.NoError(t, s.SetSSFReceiverStreamVerificationState(ctx, testIssuer, "s1", "state", requested))

				assert.ErrorIs(t, s.ConsumeSSFReceiverStreamVerificationState(ctx, testIssuer, "s1", "other", verified), ssfreceiver.ErrVerificationStateMismatch)
				assert.ErrorIs(t, s.ConsumeSSFReceiverStreamVerificationState(ctx, testIssuer, "s1", "", verified), ssfreceiver.ErrVerificationStateMismatch)

				got, err := s.GetSSFReceiverStream(ctx, testIssuer, "s1")
				require.NoError(t, err)
				assert.Equal(t, "state", got.VerificationState)
				assert.Equal(t, requested, got.VerificationRequestedAt)
				assert.True(t, got.VerifiedAt.IsZero())

				var (
					wg        sync.WaitGroup
					succeeded atomic.Int32
				)

				for range 16 {
					wg.Add(1)

					go func() {
						defer wg.Done()

						if s.ConsumeSSFReceiverStreamVerificationState(context.Background(), testIssuer, "s1", "state", verified) == nil {
							succeeded.Add(1)
						}
					}()
				}

				wg.Wait()

				assert.Equal(t, int32(1), succeeded.Load())

				assert.ErrorIs(t, s.ConsumeSSFReceiverStreamVerificationState(ctx, testIssuer, "s1", "state", verified), ssfreceiver.ErrVerificationStateMismatch)

				got, err = s.GetSSFReceiverStream(ctx, testIssuer, "s1")
				require.NoError(t, err)
				assert.Empty(t, got.VerificationState)
				assert.True(t, got.VerificationRequestedAt.IsZero())
				assert.Equal(t, verified, got.VerifiedAt)
			})

			t.Run("ShouldConsumeRequestedEmptyVerificationState", func(t *testing.T) {
				s := st.new(nil)

				at := time.Unix(1700000000, 0).UTC()

				require.NoError(t, s.CreateSSFReceiverStream(ctx, newTestRecord(testIssuer, "s1", testPushURL)))
				require.NoError(t, s.SetSSFReceiverStreamVerificationState(ctx, testIssuer, "s1", "", at))
				require.NoError(t, s.ConsumeSSFReceiverStreamVerificationState(ctx, testIssuer, "s1", "", at))

				assert.ErrorIs(t, s.ConsumeSSFReceiverStreamVerificationState(ctx, testIssuer, "s1", "", at), ssfreceiver.ErrVerificationStateMismatch)
			})

			t.Run("ShouldClearVerificationStateWithZeroTime", func(t *testing.T) {
				s := st.new(nil)

				at := time.Unix(1700000000, 0).UTC()

				require.NoError(t, s.CreateSSFReceiverStream(ctx, newTestRecord(testIssuer, "s1", testPushURL)))
				require.NoError(t, s.SetSSFReceiverStreamVerificationState(ctx, testIssuer, "s1", "state", at))
				require.NoError(t, s.SetSSFReceiverStreamVerificationState(ctx, testIssuer, "s1", "", time.Time{}))

				assert.ErrorIs(t, s.ConsumeSSFReceiverStreamVerificationState(ctx, testIssuer, "s1", "state", at), ssfreceiver.ErrVerificationStateMismatch)
				assert.ErrorIs(t, s.ConsumeSSFReceiverStreamVerificationState(ctx, testIssuer, "s1", "", at), ssfreceiver.ErrVerificationStateMismatch)
			})
		})
	}
}

func TestTokenStorage(t *testing.T) {
	for _, st := range testStores() {
		t.Run(st.name, func(t *testing.T) {
			ctx := t.Context()

			t.Run("ShouldScopeJTIToIssuerAndStream", func(t *testing.T) {
				now := time.Unix(1700000000, 0).UTC()
				s := st.new(func() time.Time { return now })

				exp := now.Add(time.Hour)

				known, err := s.IsSSFReceiverTokenKnown(ctx, testIssuer, "s1", "jti")
				require.NoError(t, err)
				assert.False(t, known)

				require.NoError(t, s.MarkSSFReceiverTokenReceived(ctx, testIssuer, "s1", "jti", exp))

				known, err = s.IsSSFReceiverTokenKnown(ctx, testIssuer, "s1", "jti")
				require.NoError(t, err)
				assert.True(t, known)

				assert.ErrorIs(t, s.MarkSSFReceiverTokenReceived(ctx, testIssuer, "s1", "jti", exp), oauth2.ErrJTIKnown)

				for _, other := range [][3]string{
					{testOtherIssuer, "s1", "jti"},
					{testIssuer, "s2", "jti"},
					{testIssuer, "s1", "other"},
				} {
					known, err = s.IsSSFReceiverTokenKnown(ctx, other[0], other[1], other[2])
					require.NoError(t, err)
					assert.False(t, known, other)

					require.NoError(t, s.MarkSSFReceiverTokenReceived(ctx, other[0], other[1], other[2], exp), other)
				}
			})

			t.Run("ShouldExpireJTI", func(t *testing.T) {
				now := time.Unix(1700000000, 0).UTC()
				s := st.new(func() time.Time { return now })

				require.NoError(t, s.MarkSSFReceiverTokenReceived(ctx, testIssuer, "s1", "jti", now.Add(time.Hour)))

				now = now.Add(time.Hour)

				known, err := s.IsSSFReceiverTokenKnown(ctx, testIssuer, "s1", "jti")
				require.NoError(t, err)
				assert.True(t, known)

				now = now.Add(time.Second)

				known, err = s.IsSSFReceiverTokenKnown(ctx, testIssuer, "s1", "jti")
				require.NoError(t, err)
				assert.False(t, known)

				require.NoError(t, s.MarkSSFReceiverTokenReceived(ctx, testIssuer, "s1", "jti", now.Add(time.Hour)))

				known, err = s.IsSSFReceiverTokenKnown(ctx, testIssuer, "s1", "jti")
				require.NoError(t, err)
				assert.True(t, known)
			})

			t.Run("ShouldPruneExpiredJTI", func(t *testing.T) {
				now := time.Unix(1700000000, 0).UTC()
				s := st.new(func() time.Time { return now })

				require.NoError(t, s.MarkSSFReceiverTokenReceived(ctx, testIssuer, "s1", "old", now.Add(time.Second)))

				now = now.Add(time.Hour)

				require.NoError(t, s.MarkSSFReceiverTokenReceived(ctx, testIssuer, "s1", "new", now.Add(time.Hour)))

				var tokens map[storage.SSFReceiverTokenMarker]time.Time

				switch store := s.(type) {
				case *storage.MemoryStore:
					tokens = store.SSFReceiverTokens
				case *storage.HydratingMemoryStore:
					tokens = store.SSFReceiverTokens
				}

				assert.Len(t, tokens, 1)
				assert.Contains(t, tokens, storage.SSFReceiverTokenMarker{Issuer: testIssuer, StreamID: "s1", JTI: "new"})
			})
		})
	}
}
