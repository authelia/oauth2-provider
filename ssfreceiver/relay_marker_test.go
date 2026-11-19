// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver_test

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/ssfreceiver"
	"authelia.com/provider/oauth2/token/jwt"
)

// testRelayClock is a clock the test moves.
type testRelayClock struct {
	now time.Time
}

func (c *testRelayClock) Now() time.Time {
	return c.now
}

// testRelayMarkerStore fails the MarkSSFRelayedEvent calls after the first failAfter.
type testRelayMarkerStore struct {
	ssfreceiver.RelayStorage

	failAfter int
	calls     int
}

func (s *testRelayMarkerStore) MarkSSFRelayedEvent(ctx context.Context, txn string, eventTypes []string, principalKey, origin string, expiry time.Time) (err error) {
	if s.calls++; s.calls > s.failAfter {
		return errTestRelay
	}

	return s.RelayStorage.MarkSSFRelayedEvent(ctx, txn, eventTypes, principalKey, origin, expiry)
}

// testRelayHookStore runs the hook once, after the first MarkSSFRelayedEvent call is stored.
type testRelayHookStore struct {
	ssfreceiver.RelayStorage

	hook func()
}

func (s *testRelayHookStore) MarkSSFRelayedEvent(ctx context.Context, txn string, eventTypes []string, principalKey, origin string, expiry time.Time) (err error) {
	err = s.RelayStorage.MarkSSFRelayedEvent(ctx, txn, eventTypes, principalKey, origin, expiry)

	if hook := s.hook; hook != nil {
		s.hook = nil

		hook()
	}

	return err
}

// newTestRelayOver returns a relay whose marker is kept by the store, with the clock of the test.
func newTestRelayOver(t *testing.T, st testStore) (x *testRelay, clock *testRelayClock) {
	t.Helper()

	clock = &testRelayClock{now: time.Unix(1700000000, 0).UTC()}

	store, ok := st.new(clock.Now).(ssfreceiver.RelayStorage)
	require.True(t, ok, "the store must implement ssfreceiver.RelayStorage")

	x = newTestRelay(t)
	x.relay.Store, x.relay.Clock = store, clock.Now

	return x, clock
}

// testRelayOther returns the event as it arrives in another SET: the same underlying event with another origin.
func testRelayOther(txn string) *ssfreceiver.RelayEvent {
	event := testRelayEvent()

	event.Transaction, event.OriginIssuer, event.OriginJTI = txn, "https://other.example.com", "other-jti-1"

	return event
}

// testRelayThird returns the event as it arrives in a third SET.
func testRelayThird(txn string) *ssfreceiver.RelayEvent {
	event := testRelayOther(txn)

	event.OriginJTI = "third-jti-1"

	return event
}

func testRelayNothing(t *testing.T, x *testRelay, event *ssfreceiver.RelayEvent) {
	t.Helper()

	calls := x.issuer.calls

	tokens, skipped, err := x.relay.Prepare(t.Context(), event)

	require.NoError(t, err)
	assert.Empty(t, tokens)
	assert.Empty(t, skipped)
	assert.Equal(t, calls, x.issuer.calls)
}

func testRelayBoth(t *testing.T, x *testRelay, event *ssfreceiver.RelayEvent) (byStream map[string]ssfreceiver.RelayToken) {
	t.Helper()

	tokens, skipped, err := x.relay.Prepare(t.Context(), event)

	require.NoError(t, err)
	assert.Empty(t, skipped)
	require.Len(t, tokens, 2)

	return testRelayTokens(t, tokens)
}

func TestRelayPrepareLoopPrevention(t *testing.T) {
	for _, st := range testStores() {
		t.Run(st.name, func(t *testing.T) {
			t.Run("ShouldRelayOnceForTheSameTxnTypeAndPrincipal", func(t *testing.T) {
				for _, mode := range []ssfreceiver.RelayTransactionMode{ssfreceiver.RelayTransactionPerStream, ssfreceiver.RelayTransactionPropagate} {
					x, _ := newTestRelayOver(t, st)
					x.relay.TransactionMode = mode

					testRelayBoth(t, x, testRelayEvent())

					// The same underlying event received in another SET, as on a second upstream stream.
					testRelayNothing(t, x, testRelayOther(testRelayTxn))
					testRelayNothing(t, x, testRelayThird(testRelayTxn))

					// SSF Section 4.1.9: the 'txn' is of one underlying event, which may be about many principals.
					other := testRelayOther(testRelayTxn)
					other.Principal = "user-2"

					testRelayBoth(t, x, other)

					third := testRelayThird(testRelayTxn)
					third.Principal = "user-2"

					testRelayNothing(t, x, third)

					// Another underlying event.
					testRelayBoth(t, x, testRelayOther("txn-upstream-2"))
				}
			})

			t.Run("ShouldIssueTheSameTokensForTheSameOrigin", func(t *testing.T) {
				for _, mode := range []ssfreceiver.RelayTransactionMode{ssfreceiver.RelayTransactionPerStream, ssfreceiver.RelayTransactionPropagate} {
					x, _ := newTestRelayOver(t, st)
					x.relay.TransactionMode = mode

					// The SET is delivered again when the application could not queue the tokens.
					first := testRelayBoth(t, x, testRelayEvent())
					second := testRelayBoth(t, x, testRelayEvent())

					for _, streamID := range []string{testRelayStreamA, testRelayStreamB} {
						_, a := testRelayDecode(t, first[streamID].Token)
						_, b := testRelayDecode(t, second[streamID].Token)

						assert.Equal(t, first[streamID].JTI, second[streamID].JTI)
						assert.Equal(t, a["jti"], b["jti"])
						assert.Equal(t, a["txn"], b["txn"])
						assert.Equal(t, a["sub_id"], b["sub_id"])
						assert.Equal(t, a["events"], b["events"])

						// It still returns from another party as another SET.
						testRelayNothing(t, x, testRelayOther(a["txn"].(string)))
					}

					testRelayNothing(t, x, testRelayOther(testRelayTxn))
				}
			})

			t.Run("ShouldIssueAgainAfterAStreamFailed", func(t *testing.T) {
				x, _ := newTestRelayOver(t, st)
				x.subjects.failing = map[string]bool{testRelayStreamB: true}

				tokens, skipped, err := x.relay.Prepare(t.Context(), testRelayEvent())

				require.NoError(t, err)
				require.Len(t, tokens, 1)
				require.ErrorIs(t, testRelaySkips(t, skipped)[testRelayStreamB], errTestRelay)

				x.subjects.failing = nil

				byStream := testRelayBoth(t, x, testRelayEvent())

				assert.Equal(t, tokens[0].JTI, byStream[testRelayStreamA].JTI)
			})

			t.Run("ShouldIssueAgainAfterAMarkFailed", func(t *testing.T) {
				x, _ := newTestRelayOver(t, st)

				for _, stream := range []*oauth2.SSFStream{x.a, x.b} {
					stream.EventsDelivered = append(stream.EventsDelivered, jwt.SecurityEventTypeRISCAccountDisabled)
				}

				x.relay.Policy = func(context.Context, *ssfreceiver.RelayEvent, map[string]string) (jwt.SecurityEvent, bool, error) {
					return &jwt.RISCAccountDisabled{}, true, nil
				}

				// The mark of the type of the event and of the type it is relayed as fails.
				store := &testRelayMarkerStore{RelayStorage: x.relay.Store, failAfter: 0}
				x.relay.Store = store

				_, _, err := x.relay.Prepare(t.Context(), testRelayEvent())

				require.ErrorIs(t, err, errTestRelay)
				assert.Zero(t, x.issuer.calls)

				store.failAfter = 100

				testRelayBoth(t, x, testRelayEvent())
			})

			t.Run("ShouldRelayDifferentEventTypeWithSameTxn", func(t *testing.T) {
				x, _ := newTestRelayOver(t, st)

				testRelayBoth(t, x, testRelayEvent())

				// SSF Section 4.1.9: the SETs of one cause share the 'txn'.
				change := testRelayOther(testRelayTxn)
				change.Event = &jwt.CAEPCredentialChange{CredentialType: "password", ChangeType: "revoke"}

				byStream := testRelayBoth(t, x, change)

				assert.Equal(t, jwt.SecurityEventTypeCAEPCredentialChange, byStream[testRelayStreamA].EventType)

				again := testRelayThird(testRelayTxn)
				again.Event = change.Event

				testRelayNothing(t, x, again)
			})

			t.Run("ShouldExcludeOriginClient", func(t *testing.T) {
				x, _ := newTestRelayOver(t, st)

				event := testRelayEvent()
				event.ExcludeClientIDs = []string{"rx-other", testRelayClientA}

				tokens, skipped, err := x.relay.Prepare(t.Context(), event)

				require.NoError(t, err)
				require.Len(t, tokens, 1)
				assert.Equal(t, testRelayStreamB, tokens[0].Stream.StreamID)
				require.ErrorIs(t, testRelaySkips(t, skipped)[testRelayStreamA], ssfreceiver.ErrRelayStreamExcluded)
				assert.Equal(t, []string{testRelayStreamB}, x.subjects.mapped)
				assert.Equal(t, 1, x.issuer.calls)
			})

			t.Run("ShouldRecognizeOwnEventReturning", func(t *testing.T) {
				for _, mode := range []ssfreceiver.RelayTransactionMode{ssfreceiver.RelayTransactionPerStream, ssfreceiver.RelayTransactionPropagate} {
					x, _ := newTestRelayOver(t, st)
					x.relay.TransactionMode = mode

					// An event the application originated, prepared as its own are.
					own := testRelayEvent()
					own.Transaction, own.OriginIssuer, own.OriginJTI = "txn-own-1", testRelayIssuerURL, "own-event-1"

					byStream := testRelayBoth(t, x, own)

					_, claims := testRelayDecode(t, byStream[testRelayStreamB].Token)

					txn, ok := claims["txn"].(string)
					require.True(t, ok)

					// It returns issued again by another party with the 'txn' it was given.
					testRelayNothing(t, x, testRelayOther(txn))
				}
			})

			t.Run("ShouldRecognizeReturningPerStreamTxn", func(t *testing.T) {
				x, _ := newTestRelayOver(t, st)

				assert.Equal(t, ssfreceiver.RelayTransactionPerStream, x.relay.TransactionMode)

				byStream := testRelayBoth(t, x, testRelayEvent())

				for _, streamID := range []string{testRelayStreamA, testRelayStreamB} {
					_, claims := testRelayDecode(t, byStream[streamID].Token)

					txn, ok := claims["txn"].(string)
					require.True(t, ok)
					require.NotEqual(t, testRelayTxn, txn)

					testRelayNothing(t, x, testRelayOther(txn))
				}
			})

			t.Run("ShouldRecognizeReturningEventOfThePolicyType", func(t *testing.T) {
				x, _ := newTestRelayOver(t, st)

				for _, stream := range []*oauth2.SSFStream{x.a, x.b} {
					stream.EventsDelivered = append(stream.EventsDelivered, jwt.SecurityEventTypeRISCAccountDisabled)
				}

				// The policy relays a session revoked event as an account disabled event, and that as it is.
				x.relay.Policy = func(context.Context, *ssfreceiver.RelayEvent, map[string]string) (jwt.SecurityEvent, bool, error) {
					return &jwt.RISCAccountDisabled{}, true, nil
				}

				byStream := testRelayBoth(t, x, testRelayEvent())

				_, claims := testRelayDecode(t, byStream[testRelayStreamA].Token)

				for _, txn := range []string{claims["txn"].(string), testRelayTxn} {
					returning := testRelayOther(txn)
					returning.Event = &jwt.RISCAccountDisabled{}

					testRelayNothing(t, x, returning)
				}
			})

			t.Run("ShouldRelayOnceWhenThePolicySwapsTheTypesConcurrently", func(t *testing.T) {
				x, _ := newTestRelayOver(t, st)

				for _, stream := range []*oauth2.SSFStream{x.a, x.b} {
					stream.EventsDelivered = append(stream.EventsDelivered, jwt.SecurityEventTypeRISCAccountDisabled)
				}

				// The policy relays each type as the other.
				x.relay.Policy = func(_ context.Context, event *ssfreceiver.RelayEvent, _ map[string]string) (jwt.SecurityEvent, bool, error) {
					if _, ok := event.Event.(*jwt.RISCAccountDisabled); ok {
						return &jwt.CAEPSessionRevoked{}, true, nil
					}

					return &jwt.RISCAccountDisabled{}, true, nil
				}

				other := testRelayOther(testRelayTxn)
				other.Event = &jwt.RISCAccountDisabled{}

				var (
					otherTokens []ssfreceiver.RelayToken
					otherErr    error
				)

				store := &testRelayHookStore{RelayStorage: x.relay.Store}
				store.hook = func() {
					otherTokens, _, otherErr = x.relay.Prepare(t.Context(), other)
				}

				x.relay.Store = store

				tokens, _, err := x.relay.Prepare(t.Context(), testRelayEvent())

				require.NoError(t, err)
				require.NoError(t, otherErr)
				assert.Len(t, tokens, 2)
				assert.Empty(t, otherTokens)
			})

			t.Run("ShouldNotSeeWhatThePolicyChanges", func(t *testing.T) {
				x, _ := newTestRelayOver(t, st)

				for _, stream := range []*oauth2.SSFStream{x.a, x.b} {
					stream.EventsDelivered = append(stream.EventsDelivered, jwt.SecurityEventTypeRISCAccountDisabled)
				}

				x.relay.ReasonAdmin = map[string]string{"en": "Relayed"}

				x.relay.Policy = func(_ context.Context, event *ssfreceiver.RelayEvent, reasonAdmin map[string]string) (jwt.SecurityEvent, bool, error) {
					event.Event, event.Transaction = nil, "changed"
					reasonAdmin["en"] = "changed"

					return &jwt.RISCAccountDisabled{}, true, nil
				}

				event := testRelayEvent()

				testRelayBoth(t, x, event)

				assert.IsType(t, &jwt.CAEPSessionRevoked{}, event.Event)
				assert.Equal(t, testRelayTxn, event.Transaction)
				assert.Equal(t, map[string]string{"en": "Relayed"}, x.relay.ReasonAdmin)

				// The type of the event as received is marked as well as the type it is relayed as.
				returning := testRelayOther(testRelayTxn)

				testRelayNothing(t, x, returning)
			})

			t.Run("ShouldExpireMarker", func(t *testing.T) {
				for _, retention := range []time.Duration{0, -time.Second, time.Hour} {
					x, clock := newTestRelayOver(t, st)
					x.relay.MarkerRetention = retention

					want := retention

					if want <= 0 {
						want = ssfreceiver.DefaultRelayMarkerRetention
					}

					first := testRelayBoth(t, x, testRelayEvent())

					_, claims := testRelayDecode(t, first[testRelayStreamA].Token)

					clock.now = clock.now.Add(want)

					testRelayNothing(t, x, testRelayOther(testRelayTxn))
					testRelayNothing(t, x, testRelayOther(claims["txn"].(string)))

					clock.now = clock.now.Add(time.Second)

					second := testRelayBoth(t, x, testRelayEvent())

					assert.Equal(t, first[testRelayStreamA].JTI, second[testRelayStreamA].JTI)

					testRelayNothing(t, x, testRelayOther(testRelayTxn))
				}

				assert.Equal(t, 30*24*time.Hour, ssfreceiver.DefaultRelayMarkerRetention)
			})

			t.Run("ShouldNotMarkAnEventThatIsNotRelayed", func(t *testing.T) {
				x, _ := newTestRelayOver(t, st)

				policy := x.relay.Policy

				x.relay.Policy = nil
				testRelayNothing(t, x, testRelayEvent())

				x.relay.Policy = policy
				x.streams.err = errTestRelay

				_, _, err := x.relay.Prepare(t.Context(), testRelayEvent())
				require.ErrorIs(t, err, errTestRelay)

				x.streams.err = nil

				// Another SET of the underlying event is relayed, as the first was not marked.
				testRelayBoth(t, x, testRelayOther(testRelayTxn))
				testRelayNothing(t, x, testRelayEvent())
			})

			t.Run("ShouldFailWhenStoreFails", func(t *testing.T) {
				x, _ := newTestRelayOver(t, st)
				x.relay.Store = &testRelayMarkerStore{RelayStorage: x.relay.Store}

				tokens, skipped, err := x.relay.Prepare(t.Context(), testRelayEvent())

				require.ErrorIs(t, err, errTestRelay)
				assert.Empty(t, tokens)
				assert.Empty(t, skipped)
				assert.Zero(t, x.issuer.calls)

				// The marker of the 'txn' of one stream fails: that stream is skipped.
				y, _ := newTestRelayOver(t, st)
				y.relay.Store = &testRelayMarkerStore{RelayStorage: y.relay.Store, failAfter: 2}

				tokens, skipped, err = y.relay.Prepare(t.Context(), testRelayEvent())

				require.NoError(t, err)
				require.Len(t, tokens, 1)
				assert.Equal(t, testRelayStreamA, tokens[0].Stream.StreamID)
				require.ErrorIs(t, testRelaySkips(t, skipped)[testRelayStreamB], errTestRelay)
				assert.Equal(t, 1, y.issuer.calls)
			})
		})
	}
}

func TestRelayPrepareMarkerConfiguration(t *testing.T) {
	t.Run("ShouldRefuseWithoutStore", func(t *testing.T) {
		x := newTestRelay(t)
		x.relay.Store = nil

		tokens, skipped, err := x.relay.Prepare(t.Context(), testRelayEvent())

		require.ErrorIs(t, err, ssfreceiver.ErrRelayConfiguration)
		assert.Empty(t, tokens)
		assert.Empty(t, skipped)
		assert.Zero(t, x.issuer.calls)
	})

	t.Run("ShouldRefusePrincipalWithoutKey", func(t *testing.T) {
		for _, principal := range []any{nil, "", 7, struct{ ID string }{ID: "user-1"}} {
			x := newTestRelay(t)

			event := testRelayEvent()
			event.Principal = principal

			tokens, skipped, err := x.relay.Prepare(t.Context(), event)

			require.ErrorIs(t, err, ssfreceiver.ErrRelayPrincipal)
			assert.Empty(t, tokens)
			assert.Empty(t, skipped)
			assert.Zero(t, x.issuer.calls)
			assert.Empty(t, x.streams.types)
		}
	})

	t.Run("ShouldUsePrincipalKeyFunction", func(t *testing.T) {
		type user struct{ ID string }

		x := newTestRelay(t)
		x.relay.TransactionMode = ssfreceiver.RelayTransactionPropagate
		x.relay.Subjects = &testRelayUserSubjects{}
		x.relay.PrincipalKey = func(principal any) string {
			if u, ok := principal.(user); ok {
				return u.ID
			}

			return ""
		}

		event := testRelayEvent()
		event.Principal = user{ID: "user-1"}

		tokens, _, err := x.relay.Prepare(t.Context(), event)

		require.NoError(t, err)
		assert.Len(t, tokens, 2)

		other := testRelayOther(testRelayTxn)
		other.Principal = user{ID: "user-1"}

		testRelayNothing(t, x, other)

		event.Principal = user{ID: "user-2"}

		tokens, _, err = x.relay.Prepare(t.Context(), event)

		require.NoError(t, err)
		assert.Len(t, tokens, 2)

		event.Principal = "user-3"

		_, _, err = x.relay.Prepare(t.Context(), event)

		require.ErrorIs(t, err, ssfreceiver.ErrRelayPrincipal)
	})
}

// testRelayUserSubjects maps any principal to the same opaque subject.
type testRelayUserSubjects struct{}

func (testRelayUserSubjects) MapRelaySubject(context.Context, *oauth2.SSFStream, *ssfreceiver.RelayEvent) (subject *jwt.SubjectIdentifier, err error) {
	return jwt.NewSubjectIdentifierOpaque("subject")
}

func TestRelayStorage(t *testing.T) {
	for _, st := range testStores() {
		t.Run(st.name, func(t *testing.T) {
			clock := &testRelayClock{now: time.Unix(1700000000, 0).UTC()}

			store, ok := st.new(clock.Now).(ssfreceiver.RelayStorage)
			require.True(t, ok)

			ctx := t.Context()
			expiry := clock.now.Add(time.Hour)

			t.Run("ShouldReturnKnownForAnotherOrigin", func(t *testing.T) {
				require.NoError(t, store.MarkSSFRelayedEvent(ctx, "txn-1", []string{"type-1"}, "user-1", "origin-1", expiry))
				require.ErrorIs(t, store.MarkSSFRelayedEvent(ctx, "txn-1", []string{"type-1"}, "user-1", "origin-2", expiry), ssfreceiver.ErrRelayKnown)
				require.ErrorIs(t, store.MarkSSFRelayedEvent(ctx, "txn-1", []string{"type-1"}, "user-1", "", expiry.Add(time.Hour)), ssfreceiver.ErrRelayKnown)
			})

			t.Run("ShouldAcceptTheSameOriginAgain", func(t *testing.T) {
				require.NoError(t, store.MarkSSFRelayedEvent(ctx, "txn-1", []string{"type-1"}, "user-1", "origin-1", expiry))
				require.NoError(t, store.MarkSSFRelayedEvent(ctx, "txn-1", []string{"type-1"}, "user-1", "origin-1", expiry.Add(-time.Minute)))
				require.ErrorIs(t, store.MarkSSFRelayedEvent(ctx, "txn-1", []string{"type-1"}, "user-1", "origin-2", expiry), ssfreceiver.ErrRelayKnown)
			})

			t.Run("ShouldKeyByTxnTypeAndPrincipal", func(t *testing.T) {
				require.NoError(t, store.MarkSSFRelayedEvent(ctx, "txn-2", []string{"type-1"}, "user-1", "origin-2", expiry))
				require.NoError(t, store.MarkSSFRelayedEvent(ctx, "txn-1", []string{"type-2"}, "user-1", "origin-2", expiry))
				require.NoError(t, store.MarkSSFRelayedEvent(ctx, "txn-1", []string{"type-1"}, "user-2", "origin-2", expiry))

				// The parts are not joined.
				require.NoError(t, store.MarkSSFRelayedEvent(ctx, "a", []string{"bc"}, "d", "origin-1", expiry))
				require.NoError(t, store.MarkSSFRelayedEvent(ctx, "ab", []string{"c"}, "d", "origin-2", expiry))
				require.NoError(t, store.MarkSSFRelayedEvent(ctx, "a", []string{"b"}, "cd", "origin-3", expiry))
			})

			t.Run("ShouldMarkEveryTypeOrNone", func(t *testing.T) {
				require.NoError(t, store.MarkSSFRelayedEvent(ctx, "txn-3", []string{"type-b"}, "user-1", "origin-1", expiry))

				// A conflict on one type leaves no mark of the other.
				require.ErrorIs(t, store.MarkSSFRelayedEvent(ctx, "txn-3", []string{"type-a", "type-b"}, "user-1", "origin-2", expiry), ssfreceiver.ErrRelayKnown)
				require.NoError(t, store.MarkSSFRelayedEvent(ctx, "txn-3", []string{"type-a"}, "user-1", "origin-3", expiry))

				// The same origin marks the types it holds and the ones nobody holds.
				require.NoError(t, store.MarkSSFRelayedEvent(ctx, "txn-3", []string{"type-a", "type-c"}, "user-1", "origin-3", expiry))
				require.ErrorIs(t, store.MarkSSFRelayedEvent(ctx, "txn-3", []string{"type-c"}, "user-1", "origin-1", expiry), ssfreceiver.ErrRelayKnown)
			})

			t.Run("ShouldMarkOnceConcurrently", func(t *testing.T) {
				var (
					group  sync.WaitGroup
					marked atomic.Int32
				)

				for i := range 32 {
					group.Go(func() {
						if store.MarkSSFRelayedEvent(ctx, "txn-concurrent", []string{"type-1"}, "user-1", "origin-"+strconv.Itoa(i), expiry) == nil {
							marked.Add(1)
						}
					})
				}

				group.Wait()

				assert.Equal(t, int32(1), marked.Load())
			})

			t.Run("ShouldForgetAfterExpiry", func(t *testing.T) {
				// The mark of the same origin at the earlier expiry did not shorten it.
				clock.now = expiry

				require.ErrorIs(t, store.MarkSSFRelayedEvent(ctx, "txn-1", []string{"type-1"}, "user-1", "origin-2", expiry.Add(time.Hour)), ssfreceiver.ErrRelayKnown)

				clock.now = expiry.Add(time.Second)

				require.NoError(t, store.MarkSSFRelayedEvent(ctx, "txn-1", []string{"type-1"}, "user-1", "origin-2", clock.now.Add(time.Minute)))
				require.ErrorIs(t, store.MarkSSFRelayedEvent(ctx, "txn-1", []string{"type-1"}, "user-1", "origin-1", clock.now.Add(time.Hour)), ssfreceiver.ErrRelayKnown)

				// The same origin extends the mark, and the expiry of a mark that was refused was not stored.
				require.NoError(t, store.MarkSSFRelayedEvent(ctx, "txn-1", []string{"type-1"}, "user-1", "origin-2", clock.now.Add(2*time.Minute)))

				clock.now = clock.now.Add(time.Minute + time.Second)

				require.ErrorIs(t, store.MarkSSFRelayedEvent(ctx, "txn-1", []string{"type-1"}, "user-1", "origin-1", clock.now.Add(time.Minute)), ssfreceiver.ErrRelayKnown)

				clock.now = clock.now.Add(time.Minute)

				require.NoError(t, store.MarkSSFRelayedEvent(ctx, "txn-1", []string{"type-1"}, "user-1", "origin-1", clock.now.Add(time.Minute)))
			})
		})
	}
}
