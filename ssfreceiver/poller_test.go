// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/ssfreceiver"
)

const (
	testPollerInterval   = 7 * time.Second
	testPollerBackoffMin = time.Second
	testPollerBackoffMax = 8 * time.Second
)

// testPollerRun is a Poller of the stream of a testStorePoll whose clock never waits, and what it reported.
type testPollerRun struct {
	poller *ssfreceiver.Poller
	cancel context.CancelFunc

	mu       sync.Mutex
	sleeps   []time.Duration
	results  []*ssfreceiver.PollResult
	failures []error
	delays   []time.Duration

	// onResult, onSleep and onFailure are called with the count of the results, sleeps and failures so far.
	onResult  func(n int)
	onSleep   func(n int)
	onFailure func(n int)
}

func newTestPollerRun(p *testStorePoll) *testPollerRun {
	run := &testPollerRun{}

	run.poller = &ssfreceiver.Poller{
		Receiver: p.receiver,
		Issuer:   p.server.URL,
		StreamID: testStreamID,
		Interval: testPollerInterval,
		Backoff:  ssfreceiver.PollBackoff{Min: testPollerBackoffMin, Max: testPollerBackoffMax},
		Sleep: func(_ context.Context, d time.Duration) {
			run.mu.Lock()
			run.sleeps = append(run.sleeps, d)
			n, hook := len(run.sleeps), run.onSleep
			run.mu.Unlock()

			if hook != nil {
				hook(n)
			}
		},
		Result: func(result *ssfreceiver.PollResult) {
			run.mu.Lock()
			run.results = append(run.results, result)
			n, hook := len(run.results), run.onResult
			run.mu.Unlock()

			if hook != nil {
				hook(n)
			}
		},
		Failure: func(err error, delay time.Duration) {
			run.mu.Lock()
			run.failures = append(run.failures, err)
			run.delays = append(run.delays, delay)
			n, hook := len(run.failures), run.onFailure
			run.mu.Unlock()

			if hook != nil {
				hook(n)
			}
		},
	}

	return run
}

// run runs the Poller until it returns, which a hook causes by calling cancel.
func (run *testPollerRun) run(t *testing.T) (err error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	ctx, run.cancel = context.WithCancel(ctx)
	defer run.cancel()

	done := make(chan error, 1)

	go func() { done <- run.poller.Run(ctx) }()

	select {
	case err = <-done:
		require.NotErrorIs(t, err, context.DeadlineExceeded)

		return err
	case <-time.After(time.Minute):
		require.FailNow(t, "the poller did not return")

		return nil
	}
}

func seconds(values ...int) (durations []time.Duration) {
	for _, value := range values {
		durations = append(durations, time.Duration(value)*time.Second)
	}

	return durations
}

// requireTestPollBodies requires the body of each poll request, where one which is expected without a 'maxEvents' has
// the default of the Poller.
func requireTestPollBodies(t *testing.T, calls []testPollCall, expected ...string) {
	t.Helper()

	require.Len(t, calls, len(expected))

	for i, call := range calls {
		var body map[string]any

		require.NoError(t, json.Unmarshal([]byte(expected[i]), &body))

		if _, ok := body["maxEvents"]; !ok {
			body["maxEvents"] = ssfreceiver.DefaultMaxPollSets
		}

		data, err := json.Marshal(body)
		require.NoError(t, err)

		assert.JSONEq(t, string(data), call.body, "the body of poll request %d", i+1)
	}
}

func TestPollerRun(t *testing.T) {
	for _, st := range testStores() {
		t.Run(st.name, func(t *testing.T) {
			t.Run("ShouldCarryAcksIntoTheNextRequest", func(t *testing.T) {
				p := newTestStorePoll(t, st)
				run := newTestPollerRun(p)

				run.poller.MaxEvents = 5

				p.respond(false, "jti-1", p.sessionRevoked(t, "jti-1"), "jti-2", p.set(t, p.key, "jti-2", map[string]any{"aud": "https://other.example.com"}))

				run.onResult = func(n int) {
					if n == 2 {
						run.cancel()
					}
				}

				assert.ErrorIs(t, run.run(t), context.Canceled)

				calls := p.received()

				// RFC 8936 Section 2.2: a long poll has no 'returnImmediately'. Nothing is left to flush.
				require.Len(t, calls, 2)
				assert.JSONEq(t, `{"maxEvents":5}`, calls[0].body)
				assert.Empty(t, calls[0].language)

				var body struct {
					MaxEvents         *int                              `json:"maxEvents"`
					ReturnImmediately bool                              `json:"returnImmediately"`
					Ack               []string                          `json:"ack"`
					SetErrs           map[string]oauth2.SSFPollSetError `json:"setErrs"`
				}

				require.NoError(t, json.Unmarshal([]byte(calls[1].body), &body))

				require.NotNil(t, body.MaxEvents)
				assert.Equal(t, 5, *body.MaxEvents)
				assert.False(t, body.ReturnImmediately)
				assert.Equal(t, []string{"jti-1"}, body.Ack)
				require.Len(t, body.SetErrs, 1)
				assert.Equal(t, ssfreceiver.SetErrorInvalidAudience, body.SetErrs["jti-2"].Err)
				assert.Equal(t, "en", calls[1].language)

				assert.Equal(t, []string{"jti-1"}, p.handler.handled())
				require.Len(t, run.results, 2)
				assert.Len(t, run.results[0].Received, 1)
				assert.Empty(t, run.failures)
				assert.Empty(t, run.sleeps)
			})

			t.Run("ShouldPollAgainWhenMoreAvailable", func(t *testing.T) {
				p := newTestStorePoll(t, st)
				run := newTestPollerRun(p)

				p.respond(true, "jti-1", p.sessionRevoked(t, "jti-1"))
				p.respond(false, "jti-2", p.sessionRevoked(t, "jti-2"))

				run.onResult = func(n int) {
					if n == 3 {
						run.cancel()
					}
				}

				assert.ErrorIs(t, run.run(t), context.Canceled)

				requireTestPollBodies(t, p.received(), `{}`, `{"ack":["jti-1"]}`, `{"ack":["jti-2"]}`)

				assert.Equal(t, []string{"jti-1", "jti-2"}, p.handler.handled())
				assert.Empty(t, run.sleeps)
				assert.Empty(t, run.failures)
			})

			t.Run("ShouldWaitTheIntervalAfterAResponseWithoutSETs", func(t *testing.T) {
				p := newTestStorePoll(t, st)
				run := newTestPollerRun(p)

				// A 'moreAvailable' without a SET is not polled again at once.
				p.respond(false)
				p.respond(true)

				run.onSleep = func(n int) {
					if n == 2 {
						run.cancel()
					}
				}

				assert.ErrorIs(t, run.run(t), context.Canceled)

				requireTestPollBodies(t, p.received(), `{}`, `{}`)

				assert.Equal(t, []time.Duration{testPollerInterval, testPollerInterval}, run.sleeps)
				assert.Empty(t, run.failures)
			})

			t.Run("ShouldBackOffOnFailure", func(t *testing.T) {
				p := newTestStorePoll(t, st)
				run := newTestPollerRun(p)

				p.hook = func(w http.ResponseWriter, _ *http.Request, n int) (handled bool) {
					switch n {
					case 1, 2, 3, 5, 7:
						w.WriteHeader(http.StatusServiceUnavailable)
					case 4:
						w.Header().Set("Retry-After", "120")
						w.WriteHeader(http.StatusTooManyRequests)
					default:
						return false
					}

					return true
				}

				run.onSleep = func(n int) {
					if n == 7 {
						run.cancel()
					}
				}

				assert.ErrorIs(t, run.run(t), context.Canceled)

				assert.Len(t, p.received(), 7)

				// The delay doubles to the most, a longer 'Retry-After' is honored, and a response starts it over.
				assert.Equal(t, seconds(1, 2, 4, 120, 8, 7, 1), run.sleeps)
				assert.Equal(t, seconds(1, 2, 4, 120, 8, 1), run.delays)

				require.Len(t, run.failures, 6)
				assert.ErrorIs(t, run.failures[3], ssfreceiver.ErrTransmitterThrottled)

				var terr *ssfreceiver.TransmitterError

				require.ErrorAs(t, run.failures[0], &terr)
				assert.Equal(t, http.StatusServiceUnavailable, terr.Status)
			})

			t.Run("ShouldSendTheAcksAgainAfterAFailure", func(t *testing.T) {
				p := newTestStorePoll(t, st)
				run := newTestPollerRun(p)

				p.respond(false, "jti-1", p.sessionRevoked(t, "jti-1"))

				p.hook = func(w http.ResponseWriter, _ *http.Request, n int) (handled bool) {
					if n == 2 {
						w.WriteHeader(http.StatusBadGateway)
					}

					return n == 2
				}

				run.onResult = func(n int) {
					if n == 2 {
						run.cancel()
					}
				}

				assert.ErrorIs(t, run.run(t), context.Canceled)

				requireTestPollBodies(t, p.received(), `{}`, `{"ack":["jti-1"]}`, `{"ack":["jti-1"]}`)

				assert.Equal(t, seconds(1), run.sleeps)
			})

			t.Run("ShouldBackOffWhenNoSETIsAcknowledged", func(t *testing.T) {
				p := newTestStorePoll(t, st)
				run := newTestPollerRun(p)

				p.handler.handle = map[string]error{"jti-1": errors.New("not persisted")}

				p.respond(true, "jti-1", p.sessionRevoked(t, "jti-1"), "jti-2", p.sessionRevoked(t, "jti-2"))
				p.respond(true, "jti-1", p.sessionRevoked(t, "jti-1"))
				p.respond(true, "jti-1", p.sessionRevoked(t, "jti-1"))

				run.onSleep = func(n int) {
					if n == 2 {
						run.cancel()
					}
				}

				assert.ErrorIs(t, run.run(t), context.Canceled)

				// The first response has a SET to acknowledge, so the next request follows at once. Each response
				// after it only has the SET which fails, whatever its 'moreAvailable'.
				requireTestPollBodies(t, p.received(), `{}`, `{"ack":["jti-2"]}`, `{}`)

				assert.Equal(t, seconds(1, 2), run.sleeps)
				assert.Empty(t, run.failures)

				require.Len(t, run.results, 3)
				assert.Contains(t, run.results[2].Unacknowledged, "jti-1")
			})

			t.Run("ShouldFlushAcksOnCancel", func(t *testing.T) {
				p := newTestStorePoll(t, st)
				run := newTestPollerRun(p)

				p.respond(false, "jti-1", p.sessionRevoked(t, "jti-1"), "jti-2", p.set(t, p.key, "jti-2", map[string]any{"aud": "https://other.example.com"}))

				run.onResult = func(n int) {
					if n == 1 {
						run.cancel()
					}
				}

				assert.ErrorIs(t, run.run(t), context.Canceled)

				calls := p.received()

				// RFC 8936 Section 2.4.2: the acknowledge-only request.
				require.Len(t, calls, 2)

				var body map[string]json.RawMessage

				require.NoError(t, json.Unmarshal([]byte(calls[1].body), &body))

				assert.JSONEq(t, `0`, string(body["maxEvents"]))
				assert.JSONEq(t, `true`, string(body["returnImmediately"]))
				assert.JSONEq(t, `["jti-1"]`, string(body["ack"]))
				assert.Contains(t, string(body["setErrs"]), `"jti-2"`)

				assert.Empty(t, run.failures)
				assert.Empty(t, run.sleeps)
			})

			t.Run("ShouldFlushAcksOnCancelDuringALongPoll", func(t *testing.T) {
				p := newTestStorePoll(t, st)
				run := newTestPollerRun(p)

				p.respond(false, "jti-1", p.sessionRevoked(t, "jti-1"))

				p.hook = func(_ http.ResponseWriter, r *http.Request, n int) (handled bool) {
					if n != 2 {
						return false
					}

					// The Transmitter holds the long poll until the Receiver gives up.
					run.cancel()

					<-r.Context().Done()

					return true
				}

				assert.ErrorIs(t, run.run(t), context.Canceled)

				requireTestPollBodies(t, p.received(), `{}`, `{"ack":["jti-1"]}`, `{"maxEvents":0,"returnImmediately":true,"ack":["jti-1"]}`)

				assert.Empty(t, run.failures)
				assert.Empty(t, run.sleeps)
			})

			t.Run("ShouldReportAFailedFlush", func(t *testing.T) {
				p := newTestStorePoll(t, st)
				run := newTestPollerRun(p)

				p.respond(false, "jti-1", p.sessionRevoked(t, "jti-1"))

				p.hook = func(w http.ResponseWriter, _ *http.Request, n int) (handled bool) {
					if n == 2 {
						w.WriteHeader(http.StatusServiceUnavailable)
					}

					return n == 2
				}

				run.onResult = func(int) { run.cancel() }

				assert.ErrorIs(t, run.run(t), context.Canceled)

				assert.Len(t, p.received(), 2)
				assert.Empty(t, run.sleeps)

				require.Len(t, run.failures, 1)
				assert.Equal(t, []time.Duration{0}, run.delays)
			})

			t.Run("ShouldKeepPollingWhilePaused", func(t *testing.T) {
				p := newTestStorePoll(t, st)
				run := newTestPollerRun(p)

				require.NoError(t, p.store.UpdateSSFReceiverStreamStatus(t.Context(), p.server.URL, testStreamID, oauth2.SSFStreamStatusPaused, "maintenance"))

				// A paused Transmitter answers without a SET, and delivers the held ones when it resumes.
				p.respond(false)
				p.respond(false)
				p.respond(false, "jti-1", p.sessionRevoked(t, "jti-1"))

				run.onResult = func(n int) {
					if n == 3 {
						run.cancel()
					}
				}

				assert.ErrorIs(t, run.run(t), context.Canceled)

				requireTestPollBodies(t, p.received(), `{}`, `{}`, `{}`, `{"maxEvents":0,"returnImmediately":true,"ack":["jti-1"]}`)

				assert.Equal(t, []time.Duration{testPollerInterval, testPollerInterval}, run.sleeps)
				assert.Equal(t, []string{"jti-1"}, p.handler.handled())
				assert.Equal(t, oauth2.SSFStreamStatusPaused, p.stored(t).Status)
				assert.Empty(t, run.failures)
			})

			t.Run("ShouldStopWhenTheTransmitterHasNoSuchStream", func(t *testing.T) {
				p := newTestStorePoll(t, st)
				run := newTestPollerRun(p)

				p.hook = func(w http.ResponseWriter, _ *http.Request, _ int) (handled bool) {
					w.WriteHeader(http.StatusNotFound)

					return true
				}

				assert.ErrorIs(t, run.run(t), ssfreceiver.ErrStreamNotFound)

				assert.Len(t, p.received(), 1)
				assert.Empty(t, run.sleeps)
				assert.Empty(t, run.failures)
			})

			t.Run("ShouldStopWhenTheStreamIsNotAPollStream", func(t *testing.T) {
				p := newTestStorePoll(t, st)
				run := newTestPollerRun(p)

				record := p.stored(t)

				record.Delivery = oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPush, EndpointURL: testPushURL, AuthorizationHeader: testPushSecret}

				require.NoError(t, p.store.UpdateSSFReceiverStream(t.Context(), p.server.URL, testStreamID, record))

				assert.ErrorIs(t, run.run(t), ssfreceiver.ErrStreamRequest)

				assert.Empty(t, p.received())
				assert.Empty(t, run.sleeps)
			})

			t.Run("ShouldStopWhenTheRecordIsDeleted", func(t *testing.T) {
				p := newTestStorePoll(t, st)
				run := newTestPollerRun(p)

				run.onResult = func(int) {
					assert.NoError(t, p.store.DeleteSSFReceiverStream(context.Background(), p.server.URL, testStreamID))
				}

				assert.ErrorIs(t, run.run(t), oauth2.ErrNotFound)

				assert.Len(t, p.received(), 1)
			})

			t.Run("ShouldNotPollWhenTheContextIsDone", func(t *testing.T) {
				p := newTestStorePoll(t, st)
				run := newTestPollerRun(p)

				ctx, cancel := context.WithCancel(t.Context())
				cancel()

				assert.ErrorIs(t, run.poller.Run(ctx), context.Canceled)
				assert.Empty(t, p.received())
			})
		})
	}

	t.Run("ShouldErrWithoutAReceiver", func(t *testing.T) {
		assert.ErrorIs(t, (&ssfreceiver.Poller{}).Run(t.Context()), ssfreceiver.ErrStreamRequest)

		var poller *ssfreceiver.Poller

		assert.ErrorIs(t, poller.Run(t.Context()), ssfreceiver.ErrStreamRequest)
	})

	t.Run("ShouldWaitInRealTimeAndStopWhenTheContextIsDone", func(t *testing.T) {
		p := newTestStorePoll(t, testStores()[0])
		run := newTestPollerRun(p)

		// The default clock: a long wait ends when the context does.
		run.poller.Sleep = nil
		run.poller.Interval = time.Hour

		run.onResult = func(int) {
			time.AfterFunc(20*time.Millisecond, run.cancel)
		}

		assert.ErrorIs(t, run.run(t), context.Canceled)
		assert.Len(t, p.received(), 1)
	})
}

func TestPollerRunAuthorizerNotFound(t *testing.T) {
	for _, st := range testStores() {
		t.Run(st.name, func(t *testing.T) {
			t.Run("ShouldRetryWhenTheAuthorizerReturnsNotFound", func(t *testing.T) {
				p := newTestStorePoll(t, st)
				run := newTestPollerRun(p)

				// Only a record which is not found stops the poller.
				p.receiver.Config.Authorizer = &ssfreceiver.BearerAuthorizer{Token: func(context.Context, string, string) (token string, err error) {
					return "", oauth2.ErrNotFound
				}}

				run.onSleep = func(n int) {
					if n == 2 {
						run.cancel()
					}
				}

				assert.ErrorIs(t, run.run(t), context.Canceled)

				require.Len(t, run.failures, 2)
				assert.ErrorIs(t, run.failures[0], oauth2.ErrNotFound)
				assert.Empty(t, p.received())
			})
		})
	}
}

func TestPollerRunPacing(t *testing.T) {
	for _, st := range testStores() {
		t.Run(st.name, func(t *testing.T) {
			t.Run("ShouldWaitTheIntervalWhenALongPollTimesOut", func(t *testing.T) {
				p := newTestStorePoll(t, st)
				run := newTestPollerRun(p)

				p.receiver.Config.LongPollTimeout = 50 * time.Millisecond

				p.respond(false, "jti-1", p.sessionRevoked(t, "jti-1"))

				p.hook = func(w http.ResponseWriter, r *http.Request, n int) (handled bool) {
					switch n {
					case 2, 3, 4:
						// The Transmitter holds the request longer than the Receiver waits.
						<-r.Context().Done()
					case 5:
						w.WriteHeader(http.StatusServiceUnavailable)
					default:
						return false
					}

					return true
				}

				run.onSleep = func(n int) {
					if n == 4 {
						run.cancel()
					}
				}

				assert.ErrorIs(t, run.run(t), context.Canceled)

				// The acknowledgement is not confirmed, and is in each request which follows.
				ack := `{"ack":["jti-1"]}`

				requireTestPollBodies(t, p.received(), `{}`, ack, ack, ack, ack, `{"maxEvents":0,"returnImmediately":true,"ack":["jti-1"]}`)

				// The end of a long poll is not a failure, and the failure after them starts from the least delay.
				assert.Equal(t, seconds(7, 7, 7, 1), run.sleeps)
				assert.Equal(t, seconds(1), run.delays)
				require.Len(t, run.failures, 1)
				assert.NotErrorIs(t, run.failures[0], context.DeadlineExceeded)
			})

			t.Run("ShouldWaitTheIntervalAfterAGatewayTimeout", func(t *testing.T) {
				p := newTestStorePoll(t, st)
				run := newTestPollerRun(p)

				p.respond(false, "jti-1", p.sessionRevoked(t, "jti-1"))

				p.hook = func(w http.ResponseWriter, _ *http.Request, n int) (handled bool) {
					switch n {
					case 2, 3, 4:
						w.WriteHeader(http.StatusGatewayTimeout)
					case 5:
						w.WriteHeader(http.StatusServiceUnavailable)
					default:
						return false
					}

					return true
				}

				run.onSleep = func(n int) {
					if n == 4 {
						run.cancel()
					}
				}

				assert.ErrorIs(t, run.run(t), context.Canceled)

				ack := `{"ack":["jti-1"]}`

				requireTestPollBodies(t, p.received(), `{}`, ack, ack, ack, ack, `{"maxEvents":0,"returnImmediately":true,"ack":["jti-1"]}`)

				assert.Equal(t, seconds(7, 7, 7, 1), run.sleeps)
				assert.Equal(t, seconds(1), run.delays)
				require.Len(t, run.failures, 1)
			})

			t.Run("ShouldWaitTheIntervalWhenNoSETIsNew", func(t *testing.T) {
				p := newTestStorePoll(t, st)
				run := newTestPollerRun(p)

				// The Transmitter delivers the same SET again whatever is acknowledged.
				for range 4 {
					p.respond(false, "jti-1", p.sessionRevoked(t, "jti-1"))
				}

				run.onSleep = func(n int) {
					if n == 2 {
						run.cancel()
					}
				}

				assert.ErrorIs(t, run.run(t), context.Canceled)

				ack := `{"ack":["jti-1"]}`

				// The first repeat is followed at once to acknowledge it, and each one after it waits.
				requireTestPollBodies(t, p.received(), `{}`, ack, ack, ack, `{"maxEvents":0,"returnImmediately":true,"ack":["jti-1"]}`)

				assert.Equal(t, []time.Duration{testPollerInterval, testPollerInterval}, run.sleeps)
				assert.Equal(t, []string{"jti-1"}, p.handler.handled())
				assert.Empty(t, run.failures)
			})

			t.Run("ShouldNotOverflowTheBackoff", func(t *testing.T) {
				p := newTestStorePoll(t, st)
				run := newTestPollerRun(p)

				run.poller.Backoff.Max = math.MaxInt64

				p.hook = func(w http.ResponseWriter, _ *http.Request, _ int) (handled bool) {
					w.WriteHeader(http.StatusServiceUnavailable)

					return true
				}

				run.onSleep = func(n int) {
					if n == 70 {
						run.cancel()
					}
				}

				assert.ErrorIs(t, run.run(t), context.Canceled)

				require.Len(t, run.sleeps, 70)

				for i := 1; i < len(run.sleeps); i++ {
					require.GreaterOrEqual(t, run.sleeps[i], run.sleeps[i-1], "the delay of failure %d", i+1)
				}

				assert.Equal(t, time.Second, run.sleeps[0])
				assert.Equal(t, time.Duration(math.MaxInt64), run.sleeps[69])
			})

			t.Run("ShouldNotFlushAcksOnAPermanentError", func(t *testing.T) {
				p := newTestStorePoll(t, st)
				run := newTestPollerRun(p)

				p.respond(false, "jti-1", p.sessionRevoked(t, "jti-1"))

				p.hook = func(w http.ResponseWriter, _ *http.Request, n int) (handled bool) {
					if n == 2 {
						w.WriteHeader(http.StatusNotFound)
					}

					return n == 2
				}

				assert.ErrorIs(t, run.run(t), ssfreceiver.ErrStreamNotFound)

				requireTestPollBodies(t, p.received(), `{}`, `{"ack":["jti-1"]}`)

				assert.Empty(t, run.failures)
				assert.Empty(t, run.sleeps)
			})

			t.Run("ShouldFlushAcksOnCancelDuringTheBackoff", func(t *testing.T) {
				p := newTestStorePoll(t, st)
				run := newTestPollerRun(p)

				p.respond(false, "jti-1", p.sessionRevoked(t, "jti-1"))

				p.hook = func(w http.ResponseWriter, _ *http.Request, n int) (handled bool) {
					if n == 2 {
						w.WriteHeader(http.StatusServiceUnavailable)
					}

					return n == 2
				}

				run.onSleep = func(int) { run.cancel() }

				assert.ErrorIs(t, run.run(t), context.Canceled)

				requireTestPollBodies(t, p.received(), `{}`, `{"ack":["jti-1"]}`, `{"maxEvents":0,"returnImmediately":true,"ack":["jti-1"]}`)

				assert.Equal(t, seconds(1), run.sleeps)
				assert.Len(t, run.failures, 1)
			})

			t.Run("ShouldStopWithoutAnAuthorizer", func(t *testing.T) {
				p := newTestStorePoll(t, st)
				run := newTestPollerRun(p)

				p.receiver.Config.Authorizer = nil

				assert.ErrorContains(t, run.run(t), "no authorizer is configured")

				assert.Empty(t, p.received())
				assert.Empty(t, run.sleeps)
				assert.Empty(t, run.failures)
			})
		})
	}
}

func TestPollerRunLongPollEnd(t *testing.T) {
	for _, st := range testStores() {
		t.Run(st.name, func(t *testing.T) {
			t.Run("ShouldBackOffWhenTheAuthorizerTimesOut", func(t *testing.T) {
				p := newTestStorePoll(t, st)
				run := newTestPollerRun(p)

				// A deadline which is not the one of the long poll request is a failure.
				p.receiver.Config.Authorizer = &ssfreceiver.BearerAuthorizer{Token: func(context.Context, string, string) (token string, err error) {
					return "", fmt.Errorf("the token endpoint did not answer: %w", context.DeadlineExceeded)
				}}

				run.onSleep = func(n int) {
					if n == 3 {
						run.cancel()
					}
				}

				assert.ErrorIs(t, run.run(t), context.Canceled)

				assert.Empty(t, p.received())
				assert.Equal(t, seconds(1, 2, 4), run.sleeps)
				assert.Equal(t, seconds(1, 2, 4), run.delays)

				require.Len(t, run.failures, 3)
				assert.ErrorIs(t, run.failures[0], context.DeadlineExceeded)
			})

			t.Run("ShouldBackOffWhenTheHTTPClientTimesOut", func(t *testing.T) {
				p := newTestStorePoll(t, st)
				run := newTestPollerRun(p)

				// The timeout of the HTTP client is shorter than the one of the long poll.
				p.receiver.Config.HTTPClient.HTTPClient.Timeout = 50 * time.Millisecond

				p.hook = func(_ http.ResponseWriter, r *http.Request, _ int) (handled bool) {
					<-r.Context().Done()

					return true
				}

				run.onSleep = func(n int) {
					if n == 2 {
						run.cancel()
					}
				}

				assert.ErrorIs(t, run.run(t), context.Canceled)

				assert.Len(t, p.received(), 2)
				assert.Equal(t, seconds(1, 2), run.sleeps)
				assert.Len(t, run.failures, 2)
			})

			t.Run("ShouldWaitTheRetryAfterOfAGatewayTimeout", func(t *testing.T) {
				p := newTestStorePoll(t, st)
				run := newTestPollerRun(p)

				p.hook = func(w http.ResponseWriter, _ *http.Request, n int) (handled bool) {
					switch n {
					case 1:
						w.Header().Set("Retry-After", "60")
					case 2:
						w.Header().Set("Retry-After", "2")
					}

					w.WriteHeader(http.StatusGatewayTimeout)

					return true
				}

				run.onSleep = func(n int) {
					if n == 3 {
						run.cancel()
					}
				}

				assert.ErrorIs(t, run.run(t), context.Canceled)

				// The longer of the interval and the 'Retry-After'.
				assert.Equal(t, seconds(60, 7, 7), run.sleeps)
				assert.Empty(t, run.failures)
			})

			t.Run("ShouldAcknowledgeARepeatAtOnceAfterALongPollEnds", func(t *testing.T) {
				p := newTestStorePoll(t, st)
				run := newTestPollerRun(p)

				for range 4 {
					p.respond(false, "jti-1", p.sessionRevoked(t, "jti-1"))
				}

				p.hook = func(w http.ResponseWriter, _ *http.Request, n int) (handled bool) {
					if n == 3 {
						w.WriteHeader(http.StatusGatewayTimeout)
					}

					return n == 3
				}

				run.onSleep = func(n int) {
					if n == 2 {
						run.cancel()
					}
				}

				assert.ErrorIs(t, run.run(t), context.Canceled)

				ack := `{"ack":["jti-1"]}`

				// The repeat after the long poll which ended is followed at once, and the one after it waits.
				requireTestPollBodies(t, p.received(), `{}`, ack, ack, ack, ack, `{"maxEvents":0,"returnImmediately":true,"ack":["jti-1"]}`)

				assert.Equal(t, []time.Duration{testPollerInterval, testPollerInterval}, run.sleeps)
			})
		})
	}
}

// TestPollerRunMaxEvents has the 'maxEvents' of the requests of the loop.
func TestPollerRunMaxEvents(t *testing.T) {
	for _, st := range testStores() {
		t.Run(st.name, func(t *testing.T) {
			t.Run("ShouldSendTheMaxPollSetsAsMaxEventsByDefault", func(t *testing.T) {
				testCases := []struct {
					name        string
					maxEvents   int
					maxPollSets int
					expected    string
				}{
					{name: "ShouldSendTheDefaultMaxPollSets", expected: `{"maxEvents":100}`},
					{name: "ShouldSendTheConfiguredMaxPollSets", maxPollSets: 3, expected: `{"maxEvents":3}`},
					{name: "ShouldSendTheMaxPollSetsWhenMaxEventsIsNegative", maxEvents: -1, maxPollSets: 3, expected: `{"maxEvents":3}`},
					{name: "ShouldSendTheMaxEventsOfThePoller", maxEvents: 5, maxPollSets: 3, expected: `{"maxEvents":5}`},
				}

				for _, tc := range testCases {
					t.Run(tc.name, func(t *testing.T) {
						p := newTestStorePoll(t, st)
						run := newTestPollerRun(p)

						p.receiver.Config.MaxPollSets = tc.maxPollSets
						run.poller.MaxEvents = tc.maxEvents

						run.onResult = func(int) { run.cancel() }

						assert.ErrorIs(t, run.run(t), context.Canceled)

						// RFC 8936 Section 2.2: the Transmitter returns no more SETs than the 'maxEvents'.
						calls := p.received()

						require.Len(t, calls, 1)
						assert.JSONEq(t, tc.expected, calls[0].body)
					})
				}
			})
		})
	}
}

// TestPollerRunRepeats has the pacing of the loop when the Transmitter delivers SETs received before.
func TestPollerRunRepeats(t *testing.T) {
	for _, st := range testStores() {
		t.Run(st.name, func(t *testing.T) {
			t.Run("ShouldWaitTheIntervalWhenNoSETIsNewAndMoreAreAvailable", func(t *testing.T) {
				p := newTestStorePoll(t, st)
				run := newTestPollerRun(p)

				// The Transmitter delivers the same SET again whatever is acknowledged, and says it has more.
				for range 6 {
					p.respond(true, "jti-1", p.sessionRevoked(t, "jti-1"))
				}

				run.onSleep = func(n int) {
					if n == 2 {
						run.cancel()
					}
				}

				assert.ErrorIs(t, run.run(t), context.Canceled)

				ack := `{"ack":["jti-1"]}`

				// The first repeat is followed at once to acknowledge it, and each one after it waits.
				requireTestPollBodies(t, p.received(), `{}`, ack, ack, ack, `{"maxEvents":0,"returnImmediately":true,"ack":["jti-1"]}`)

				assert.Equal(t, []time.Duration{testPollerInterval, testPollerInterval}, run.sleeps)
				assert.Equal(t, []string{"jti-1"}, p.handler.handled())
				assert.Empty(t, run.failures)
			})

			t.Run("ShouldNotWaitWhileSETsAreNewAndMoreAreAvailable", func(t *testing.T) {
				p := newTestStorePoll(t, st)
				run := newTestPollerRun(p)

				// A repeat between two SETs which are new does not make the Poller wait.
				p.respond(true, "jti-1", p.sessionRevoked(t, "jti-1"))
				p.respond(true, "jti-1", p.sessionRevoked(t, "jti-1"))
				p.respond(true, "jti-2", p.sessionRevoked(t, "jti-2"))
				p.respond(true, "jti-2", p.sessionRevoked(t, "jti-2"))
				p.respond(true, "jti-3", p.sessionRevoked(t, "jti-3"))

				run.onResult = func(n int) {
					if n == 5 {
						run.cancel()
					}
				}

				assert.ErrorIs(t, run.run(t), context.Canceled)

				assert.Equal(t, []string{"jti-1", "jti-2", "jti-3"}, p.handler.handled())
				assert.Empty(t, run.sleeps)
				assert.Empty(t, run.failures)
			})
		})
	}
}

// TestPollerRunUnheldLongPoll has the long polls a 504 ends without the request having been held.
func TestPollerRunUnheldLongPoll(t *testing.T) {
	for _, st := range testStores() {
		t.Run(st.name, func(t *testing.T) {
			t.Run("ShouldReportAGatewayTimeoutWhichIsNeverHeld", func(t *testing.T) {
				p := newTestStorePoll(t, st)
				run := newTestPollerRun(p)

				p.respond(false, "jti-1", p.sessionRevoked(t, "jti-1"))

				// The 504 is answered at once, time after time, so the request is not held as a long poll is.
				p.hook = func(w http.ResponseWriter, _ *http.Request, n int) (handled bool) {
					if n >= 2 && n <= 8 {
						w.WriteHeader(http.StatusGatewayTimeout)
					}

					return n >= 2 && n <= 8
				}

				run.onSleep = func(n int) {
					if n == 10 {
						run.cancel()
					}
				}

				assert.ErrorIs(t, run.run(t), context.Canceled)

				// The first three are the end of a long poll. Each one after them is a failure, which waits the
				// longer of the interval and the backoff, and the response which follows starts over.
				assert.Equal(t, seconds(7, 7, 7, 7, 7, 7, 8, 7, 7, 7), run.sleeps)
				assert.Equal(t, seconds(7, 7, 7, 8), run.delays)
				require.Len(t, run.failures, 4)

				var terr *ssfreceiver.TransmitterError

				require.ErrorAs(t, run.failures[0], &terr)
				assert.Equal(t, http.StatusGatewayTimeout, terr.Status)

				// The Ack is sent again with each request until one is answered.
				calls := p.received()

				require.GreaterOrEqual(t, len(calls), 9)

				for _, call := range calls[1:9] {
					assert.JSONEq(t, `{"maxEvents":100,"ack":["jti-1"]}`, call.body)
				}
			})

			t.Run("ShouldNotReportAGatewayTimeoutWhichIsHeld", func(t *testing.T) {
				p := newTestStorePoll(t, st)
				run := newTestPollerRun(p)

				run.poller.Interval = 20 * time.Millisecond

				// Every third 504 is answered after the request was held for longer than the interval.
				p.hook = func(w http.ResponseWriter, _ *http.Request, n int) (handled bool) {
					if n%3 == 0 {
						time.Sleep(60 * time.Millisecond)
					}

					w.WriteHeader(http.StatusGatewayTimeout)

					return true
				}

				run.onSleep = func(n int) {
					if n == 9 {
						run.cancel()
					}
				}

				assert.ErrorIs(t, run.run(t), context.Canceled)

				assert.Len(t, run.sleeps, 9)
				assert.Empty(t, run.failures)
			})
		})
	}
}
