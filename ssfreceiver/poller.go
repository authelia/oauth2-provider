// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver

import (
	"context"
	"errors"
	"net/http"
	"time"

	"authelia.com/provider/oauth2"
)

const (
	// DefaultPollInterval is the wait after a poll response without a SET when Poller.Interval is not positive.
	DefaultPollInterval = time.Second

	// DefaultPollBackoffMin is the first delay after a failure when PollBackoff.Min is not positive.
	DefaultPollBackoffMin = time.Second

	// DefaultPollBackoffMax is the most the delay after a failure doubles to when PollBackoff.Max is not positive.
	DefaultPollBackoffMax = 5 * time.Minute

	// pollUnheldEnds is how many long polls in a row may end with a 504 which was not held before each one after
	// them is a failure.
	pollUnheldEnds = 3

	// pollHeld is the least time a request is held for its 504 to be the end of a long poll, when the Interval is
	// not shorter.
	pollHeld = time.Second
)

// PollBackoff is the delay of a Poller after a failure: Min after the first, doubled by each one which follows it up
// to Max, and started over by a poll which did not fail.
type PollBackoff struct {
	// Min is the first delay. DefaultPollBackoffMin is used when it is not positive.
	Min time.Duration

	// Max is the most the delay doubles to, and is not less than Min. DefaultPollBackoffMax is used when it is not
	// positive.
	Max time.Duration
}

// Poller polls one poll stream with Receiver.Poll until its context is done. Every field is read by Run only, and a
// Poller runs once at a time.
//
// See: https://www.rfc-editor.org/rfc/rfc8936#section-2
type Poller struct {
	// Receiver makes each poll request, and its Config.Handler is handed the events.
	Receiver *Receiver

	// Issuer and StreamID identify the record of the stream, which is read from the store for each request.
	Issuer   string
	StreamID string

	// MaxEvents is the 'maxEvents' of each request. The Config.MaxPollSets of the Receiver is used when it is not
	// positive, which is DefaultMaxPollSets by default, so the Transmitter is always given a limit: a backlog it
	// returned whole could be larger than Config.MaxResponseBytes, and no poll would then succeed. A value larger
	// than Config.MaxPollSets has the SETs after those processed delivered again.
	//
	// See: https://www.rfc-editor.org/rfc/rfc8936#section-2.2
	MaxEvents int

	// Interval is the wait after a response without a SET, which is one of a Transmitter that does not hold the
	// request or the end of a long poll, and after a long poll which ended without a response. DefaultPollInterval
	// is used when it is not positive.
	Interval time.Duration

	// Backoff is the delay after a failure.
	Backoff PollBackoff

	// Result is optional and is called with the result of each poll request of the loop, for the caller to log the
	// Unacknowledged. It must not retain the Ack or the SetErrs to change them.
	Result func(result *PollResult)

	// Failure is optional and is called with each error of a poll request which Run does not return, and the delay
	// before the next request, which is zero for the final acknowledge-only request. It is the only sight of an
	// error which is retried for as long as it lasts, with a delay which backs off up to Backoff.Max, such as a 401,
	// a 403, or a 400 or a 413 the request itself causes. It is not called for a long poll which ended without a
	// response, other than a 504 which Run counts as a failure.
	Failure func(err error, delay time.Duration)

	// Sleep is optional and replaces the clock: it returns when the duration has passed or the context is done.
	Sleep func(ctx context.Context, d time.Duration)
}

// Run polls the stream until the context is done, then sends what is not yet acknowledged and returns the error of
// the context. That final request is bounded by oauth2.FetchTimeout, which Run may take to return. Each request of
// the loop is a long poll which has the Ack and the SetErrs of the result before it, and the same ones again when it
// had no response. Its 'maxEvents' is the MaxEvents, or the Config.MaxPollSets of the Receiver. The next request
// follows at once, except that it waits:
//
//   - the Interval after a response without a SET, whatever its 'moreAvailable';
//   - the Interval after a long poll which ended without a response, which is one that was sent and that
//     Config.LongPollTimeout ended, or one answered with a 504 (then its 'Retry-After' when that is longer): it is
//     the end of a long poll and not a failure, unlike a timeout of the Authorizer, the store or the HTTP client;
//   - the Interval after the second response in a row with SETs of which none is handed to the EventHandler,
//     whatever its 'moreAvailable', such as SETs received before: the first is followed at once so they are
//     acknowledged, and a Transmitter which delivers the same SETs time after time is not polled without a wait;
//   - the Backoff after any other error, or the 'Retry-After' of the response when that is longer;
//   - the Backoff after a result with Unacknowledged SETs and none that is acknowledged or reported, as the
//     Transmitter delivers the same SETs again.
//
// A 504 which is answered sooner than the Interval, or than a second when the Interval is longer, was not held as a
// long poll is. The first three in a row are still the end of a long poll. Each one after them is a failure: it is
// reported to Failure and waits the longer of the Interval and the Backoff, until a request is held or answered.
//
// The status of the stream does not stop the loop: a paused or disabled Transmitter may answer without a SET. Run
// returns an error other than the one of the context, without the final request, when the stream cannot be polled
// again as it is: an error matching ErrStreamRequest (such as a record which is not active or not of a poll stream),
// ErrStreamNotFound, ErrEndpointNotSupported, ErrEndpointNotHTTPS or oauth2.ErrNotFound (the record is gone), or the
// one of a Receiver without a store or an Authorizer. Any other error, such as a 401 or a 403, is retried.
//
// See: https://www.rfc-editor.org/rfc/rfc8936#section-2.2
// See: https://www.rfc-editor.org/rfc/rfc8936#section-2.4
func (p *Poller) Run(ctx context.Context) (err error) {
	if p == nil || p.Receiver == nil {
		return streamRequestError("the poller has no receiver")
	}

	var (
		request PollRequest
		result  *PollResult
		state   pollerState
	)

	// RFC 8936 Section 2.2: the Transmitter returns no more SETs than the 'maxEvents'.
	limit := p.MaxEvents

	if limit <= 0 {
		limit = p.Receiver.maxPollSets()
	}

	request.MaxEvents = &limit

	for {
		if ctx.Err() != nil {
			p.flush(ctx, request)

			return ctx.Err()
		}

		var delay time.Duration

		// RFC 8936 Section 2.2: a request without 'returnImmediately' is a long poll.
		if result, err = p.Receiver.Poll(ctx, p.Issuer, p.StreamID, request); err != nil {
			switch {
			case ctx.Err() != nil:
				continue
			case isPollPermanent(err):
				return err
			case isLongPollEnd(err):
				// The Ack and the SetErrs were not confirmed, and are sent again.
				p.wait(ctx, p.ended(err, &state))

				continue
			}

			state.failures++
			state.idle = false

			delay = p.backoff(state.failures, err)

			if p.Failure != nil {
				p.Failure(err, delay)
			}
		} else {
			// RFC 8936 Section 2.4: the SETs of a response are acknowledged in the next request.
			request.Ack, request.SetErrs = result.Ack, result.SetErrs

			if p.Result != nil {
				p.Result(result)
			}

			delay = p.pace(result, &state)
		}

		p.wait(ctx, delay)
	}
}

// pollerState is what Run keeps from one poll request to the next.
type pollerState struct {
	// failures is the count of the failures in a row.
	failures int

	// unheld is the count of the long polls in a row which ended with a 504 that was not held.
	unheld int

	// idle is true after a response with SETs of which none was handed to the EventHandler.
	idle bool
}

// ended returns the wait after a long poll which ended without a response. A 504 which was not held, timed from the
// sending of the request to the response, is counted, and is a failure once it is one of more than pollUnheldEnds in
// a row.
//
// See: https://www.rfc-editor.org/rfc/rfc9110.html#section-15.6.5
func (p *Poller) ended(err error, state *pollerState) (delay time.Duration) {
	state.idle = false

	delay = max(p.interval(), retryAfter(err))

	var terr *TransmitterError

	if !errors.As(err, &terr) || terr.held >= min(p.interval(), pollHeld) {
		state.unheld = 0

		return delay
	}

	if state.unheld++; state.unheld <= pollUnheldEnds {
		return delay
	}

	state.failures++

	delay = max(delay, p.backoff(state.failures, err))

	if p.Failure != nil {
		p.Failure(err, delay)
	}

	return delay
}

// pace returns the wait after the result, and counts it as a failure when no SET of it is settled.
func (p *Poller) pace(result *PollResult, state *pollerState) (delay time.Duration) {
	settled := len(result.Ack)+len(result.SetErrs) != 0

	state.unheld = 0

	switch {
	case !settled && len(result.Unacknowledged) != 0:
		state.failures++
		state.idle = false

		return p.backoff(state.failures, nil)
	case !settled:
		state.failures, state.idle = 0, false

		return p.interval()
	case len(result.Received) == 0:
		// The request which follows at once acknowledges the SETs, and the one after it waits, whether or not
		// the Transmitter has more: one which delivers the same SETs again would be polled without a wait.
		if state.idle {
			delay = p.interval()
		}

		state.failures, state.idle = 0, true

		return delay
	default:
		state.failures, state.idle = 0, false

		return 0
	}
}

// flush sends the acknowledge-only request for what is not yet acknowledged, when the context of the loop is done.
//
// See: https://www.rfc-editor.org/rfc/rfc8936#section-2.4.2
func (p *Poller) flush(ctx context.Context, request PollRequest) {
	if len(request.Ack) == 0 && len(request.SetErrs) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), oauth2.FetchTimeout)
	defer cancel()

	none := 0

	request.MaxEvents, request.ReturnImmediately = &none, true

	if _, err := p.Receiver.Poll(ctx, p.Issuer, p.StreamID, request); err != nil && p.Failure != nil {
		p.Failure(err, 0)
	}
}

// backoff returns the delay after the given number of failures in a row, the last with the error.
//
// See: https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.3
func (p *Poller) backoff(failures int, err error) (delay time.Duration) {
	delay = p.Backoff.Min

	if delay <= 0 {
		delay = DefaultPollBackoffMin
	}

	limit := p.Backoff.Max

	if limit <= 0 {
		limit = DefaultPollBackoffMax
	}

	limit = max(limit, delay)

	for i := 1; i < failures && delay < limit; i++ {
		if delay > limit/2 {
			delay = limit
		} else {
			delay *= 2
		}
	}

	return max(delay, retryAfter(err))
}

// retryAfter returns the delay the 'Retry-After' of the response the error is of asks for, or zero.
//
// See: https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.3
func retryAfter(err error) (delay time.Duration) {
	var terr *TransmitterError

	if errors.As(err, &terr) {
		return terr.RetryAfter
	}

	return 0
}

func (p *Poller) interval() (interval time.Duration) {
	if p.Interval > 0 {
		return p.Interval
	}

	return DefaultPollInterval
}

// wait returns when the duration has passed or the context is done.
func (p *Poller) wait(ctx context.Context, d time.Duration) {
	if d <= 0 || ctx.Err() != nil {
		return
	}

	if p.Sleep != nil {
		p.Sleep(ctx, d)

		return
	}

	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}

// isPollPermanent reports whether the error is one the same poll request fails with again. A record which is not
// found is one, and an oauth2.ErrNotFound of the Authorizer is not.
func isPollPermanent(err error) (ok bool) {
	for _, target := range []error{ErrStreamRequest, ErrStreamNotFound, ErrEndpointNotSupported, ErrEndpointNotHTTPS, errStreamRecordGone, errNoStore, errNoAuthorizer} {
		if errors.Is(err, target) {
			return true
		}
	}

	return false
}

// isLongPollEnd reports whether the error of a long poll is the end of the wait for a SET and not a failure: the
// timeout of the request which was sent, or the one of an intermediary. A timeout of the Authorizer, the store or the
// HTTP client is a failure.
//
// See: https://www.rfc-editor.org/rfc/rfc8936#section-2.2
// See: https://www.rfc-editor.org/rfc/rfc9110.html#section-15.6.5
func isLongPollEnd(err error) (ok bool) {
	var terr *TransmitterError

	if errors.As(err, &terr) {
		return terr.Status == http.StatusGatewayTimeout
	}

	var timeout *timeoutError

	return errors.As(err, &timeout)
}
