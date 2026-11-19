// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPollerEnded(t *testing.T) {
	gatewayTimeout := func(held time.Duration) error {
		return &TransmitterError{Status: http.StatusGatewayTimeout, held: held}
	}

	t.Run("ShouldCountOnlyAGatewayTimeoutWhichWasNotHeld", func(t *testing.T) {
		testCases := []struct {
			name     string
			interval time.Duration
			held     time.Duration
			unheld   bool
		}{
			{"ShouldCountBelowTheInterval", 20 * time.Millisecond, 19 * time.Millisecond, true},
			{"ShouldNotCountAtTheInterval", 20 * time.Millisecond, 20 * time.Millisecond, false},
			{"ShouldCountBelowTheHeldTimeOfALongInterval", time.Minute, pollHeld - time.Millisecond, true},
			{"ShouldNotCountAtTheHeldTimeOfALongInterval", time.Minute, pollHeld, false},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				p := &Poller{Interval: tc.interval}
				state := &pollerState{unheld: 1}

				p.ended(gatewayTimeout(tc.held), state)

				if tc.unheld {
					assert.Equal(t, 2, state.unheld)
				} else {
					assert.Zero(t, state.unheld)
				}
			})
		}
	})

	t.Run("ShouldReportAFailureAfterTheUnheldEnds", func(t *testing.T) {
		var failures []error

		p := &Poller{Interval: time.Minute, Failure: func(err error, _ time.Duration) { failures = append(failures, err) }}
		state := &pollerState{}

		for range pollUnheldEnds {
			p.ended(gatewayTimeout(0), state)
		}

		assert.Empty(t, failures)

		p.ended(gatewayTimeout(0), state)

		require.Len(t, failures, 1)
		assert.Equal(t, 1, state.failures)
	})

	t.Run("ShouldNotCountAnEndWhichIsNotAGatewayTimeout", func(t *testing.T) {
		p := &Poller{Interval: time.Minute}
		state := &pollerState{unheld: 2}

		p.ended(&timeoutError{err: errors.New("timeout")}, state)

		assert.Zero(t, state.unheld)
	})
}
