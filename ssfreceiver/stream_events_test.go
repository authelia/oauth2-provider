// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/token/jwt"
)

// testStreamStore is the StreamStorage of a Receiver under test, holding one record.
type testStreamStore struct {
	StreamStorage

	record *StreamRecord
	err    error

	// consumeErr is returned in place of consuming the requested verification.
	consumeErr error
}

func (s *testStreamStore) GetSSFReceiverStream(_ context.Context, issuer, streamID string) (record *StreamRecord, err error) {
	if err = s.find(issuer, streamID); err != nil {
		return nil, err
	}

	return s.record.Clone(), nil
}

func (s *testStreamStore) find(issuer, streamID string) (err error) {
	switch {
	case s.err != nil:
		return s.err
	case s.record.Issuer != issuer || s.record.StreamID != streamID:
		return oauth2.ErrNotFound
	default:
		return nil
	}
}

func (s *testStreamStore) UpdateSSFReceiverStreamStatus(_ context.Context, issuer, streamID, status, reason string) (err error) {
	if err = s.find(issuer, streamID); err != nil {
		return err
	}

	s.record.Status, s.record.StatusReason = status, reason

	return nil
}

func (s *testStreamStore) ConsumeSSFReceiverStreamVerificationState(_ context.Context, issuer, streamID, state string, verifiedAt time.Time) (err error) {
	if err = s.find(issuer, streamID); err != nil {
		return err
	}

	if s.consumeErr != nil {
		return s.consumeErr
	}

	if s.record.VerificationRequestedAt.IsZero() || s.record.VerificationState != state {
		return ErrVerificationStateMismatch
	}

	s.record.VerificationState, s.record.VerificationRequestedAt, s.record.VerifiedAt = "", time.Time{}, verifiedAt

	return nil
}

func (s *testStreamStore) SetSSFReceiverStreamVerifiedAt(_ context.Context, issuer, streamID string, verifiedAt time.Time) (err error) {
	if err = s.find(issuer, streamID); err != nil {
		return err
	}

	s.record.VerifiedAt = verifiedAt

	return nil
}

// testStreamEventHandler is the StreamEventHandler of a Receiver under test.
type testStreamEventHandler struct {
	events []*ReceivedEvent
	stored []*StreamRecord
	store  *testStreamStore
	err    error
}

func (h *testStreamEventHandler) HandleStreamEvent(_ context.Context, event *ReceivedEvent) (err error) {
	h.events = append(h.events, event)
	h.stored = append(h.stored, h.store.record.Clone())

	return h.err
}

type testStreamPush struct {
	*testPush

	streams  *testStreamStore
	handler  *testStreamEventHandler
	resolver *testSubjectResolver
}

// newTestStreamPush returns a push stream whose record is stored, and for which a verification with the 'state' was
// requested when requested is true.
func newTestStreamPush(t *testing.T, requested bool, state string) *testStreamPush {
	p := &testStreamPush{testPush: newTestPush(t)}

	p.x.record.Status = oauth2.SSFStreamStatusEnabled

	if requested {
		p.x.record.VerificationState, p.x.record.VerificationRequestedAt = state, p.x.now.Add(-time.Minute)
	}

	p.streams = &testStreamStore{record: p.x.record.Clone()}
	p.store.StreamStorage = p.streams

	p.handler = &testStreamEventHandler{store: p.streams}
	p.x.receiver.Config.StreamHandler = p.handler

	p.resolver = p.testPush.resolver("principal-1", nil)

	return p
}

func (p *testStreamPush) event(jti string, subject map[string]any, eventType string, payload map[string]any) map[string]any {
	claims := p.x.claims()

	claims["jti"] = jti
	claims["sub_id"] = subject
	claims["events"] = map[string]any{eventType: payload}

	return claims
}

func (p *testStreamPush) verification(jti string, state any) map[string]any {
	payload := map[string]any{}

	if state != nil {
		payload["state"] = state
	}

	return p.event(jti, testStreamSubject("s1"), jwt.SecurityEventTypeSSFVerification, payload)
}

func (p *testStreamPush) updated(jti, status, reason string) map[string]any {
	payload := map[string]any{"status": status}

	if reason != "" {
		payload["reason"] = reason
	}

	return p.event(jti, testStreamSubject("s1"), jwt.SecurityEventTypeSSFStreamUpdated, payload)
}

func (p *testStreamPush) requireSetError(t *testing.T, claims map[string]any, code string) {
	t.Helper()

	rw, err := p.do(t, p.request(strings.NewReader(p.x.set().sign(t, claims))))

	require.NoError(t, err)
	requireSetError(t, rw, code)
}

func testStreamSubject(id string) map[string]any {
	return map[string]any{"format": "opaque", "id": id}
}

func TestReceiverStreamEvents(t *testing.T) {
	t.Run("ShouldMarkVerifiedOnExpectedState", func(t *testing.T) {
		p := newTestStreamPush(t, true, "VGhpcyBpcyBhbiBleGFtcGxl")

		code, body, err := p.push(t, p.verification("jti-1", "VGhpcyBpcyBhbiBleGFtcGxl"))

		require.NoError(t, err)
		assert.Equal(t, http.StatusAccepted, code)
		assert.Empty(t, body)

		assert.Equal(t, p.x.now, p.streams.record.VerifiedAt)
		assert.Empty(t, p.streams.record.VerificationState)
		assert.True(t, p.streams.record.VerificationRequestedAt.IsZero())
		assert.Contains(t, p.store.marks, testTokenMark{p.x.record.Issuer, "s1", "jti-1"})
	})

	t.Run("ShouldReturnInvalidStateOnMismatch", func(t *testing.T) {
		testCases := []struct {
			name      string
			requested bool
			expected  string
			have      string
		}{
			{name: "ShouldRejectOtherState", requested: true, expected: "expected", have: "other"},
			{name: "ShouldRejectPrefix", requested: true, expected: "expected", have: "expect"},
			{name: "ShouldRejectEmptyStateWhenStateRequested", requested: true, expected: "expected", have: ""},
			{name: "ShouldRejectStateWhenEmptyStateRequested", requested: true, expected: "", have: "other"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				p := newTestStreamPush(t, tc.requested, tc.expected)

				before := p.streams.record.Clone()

				p.requireSetError(t, p.verification("jti-1", tc.have), SetErrorInvalidState)

				assert.Equal(t, before, p.streams.record)
				assert.Empty(t, p.store.marks)
				assert.Empty(t, p.handler.events)
			})
		}
	})

	t.Run("ShouldAcknowledgeStateWhenNoVerificationIsRequested", func(t *testing.T) {
		for _, state := range []string{"other", ""} {
			p := newTestStreamPush(t, false, "")

			verified := p.x.now.Add(-time.Hour)
			p.streams.record.VerifiedAt = verified

			before := p.streams.record.Clone()

			code, body, err := p.push(t, p.verification("jti-1", state))

			// It was consumed by a delivery before, or is stale, and is not a failure to verify.
			require.NoError(t, err)
			assert.Equal(t, http.StatusAccepted, code)
			assert.Empty(t, body)
			assert.Equal(t, before, p.streams.record)
			assert.Equal(t, verified, p.streams.record.VerifiedAt)
			assert.Empty(t, p.handler.events)
			assert.Len(t, p.store.marks, 1)
		}
	})

	t.Run("ShouldVerifyOnRedeliveryAfterStreamEventHandlerError", func(t *testing.T) {
		p := newTestStreamPush(t, true, "expected")

		cause := errors.New("the queue is full")
		p.handler.err = cause

		code, _, err := p.push(t, p.verification("jti-1", "expected"))

		require.ErrorIs(t, err, cause)
		assert.Equal(t, http.StatusServiceUnavailable, code)

		// The requested verification is still pending.
		assert.Equal(t, "expected", p.streams.record.VerificationState)
		assert.False(t, p.streams.record.VerificationRequestedAt.IsZero())
		assert.True(t, p.streams.record.VerifiedAt.IsZero())
		assert.Empty(t, p.store.marks)

		p.handler.err = nil

		code, _, err = p.push(t, p.verification("jti-1", "expected"))

		require.NoError(t, err)
		assert.Equal(t, http.StatusAccepted, code)
		assert.Equal(t, p.x.now, p.streams.record.VerifiedAt)
		assert.True(t, p.streams.record.VerificationRequestedAt.IsZero())
		assert.Len(t, p.handler.events, 2)
		assert.Len(t, p.store.marks, 1)
	})

	t.Run("ShouldAcknowledgeRedeliveryAfterMarkFailure", func(t *testing.T) {
		p := newTestStreamPush(t, true, "expected")

		cause := errors.New("the database is unreachable")
		p.store.markErr = cause

		code, _, err := p.push(t, p.verification("jti-1", "expected"))

		require.ErrorIs(t, err, cause)
		assert.Equal(t, http.StatusServiceUnavailable, code)

		// The state was consumed, and the SET is not remembered.
		assert.Equal(t, p.x.now, p.streams.record.VerifiedAt)
		assert.True(t, p.streams.record.VerificationRequestedAt.IsZero())
		assert.Empty(t, p.store.marks)

		p.store.markErr = nil

		verified := p.x.now
		p.x.now = p.x.now.Add(time.Minute)

		code, body, err := p.push(t, p.verification("jti-1", "expected"))

		require.NoError(t, err)
		assert.Equal(t, http.StatusAccepted, code)
		assert.Empty(t, body)
		assert.Equal(t, verified, p.streams.record.VerifiedAt)
		assert.Len(t, p.handler.events, 1)
		assert.Len(t, p.store.marks, 1)
	})

	t.Run("ShouldAcknowledgeWhenConcurrentDeliveryConsumedTheState", func(t *testing.T) {
		p := newTestStreamPush(t, true, "expected")

		p.streams.consumeErr = ErrVerificationStateMismatch

		code, body, err := p.push(t, p.verification("jti-1", "expected"))

		require.NoError(t, err)
		assert.Equal(t, http.StatusAccepted, code)
		assert.Empty(t, body)
		assert.Len(t, p.store.marks, 1)
	})

	t.Run("ShouldAcceptVerificationWithoutState", func(t *testing.T) {
		t.Run("ShouldRecordVerifiedAt", func(t *testing.T) {
			p := newTestStreamPush(t, false, "")

			code, _, err := p.push(t, p.verification("jti-1", nil))

			require.NoError(t, err)
			assert.Equal(t, http.StatusAccepted, code)
			assert.Equal(t, p.x.now, p.streams.record.VerifiedAt)
			assert.Len(t, p.store.marks, 1)
		})

		t.Run("ShouldKeepRequestedVerification", func(t *testing.T) {
			p := newTestStreamPush(t, true, "expected")

			code, _, err := p.push(t, p.verification("jti-1", nil))

			require.NoError(t, err)
			assert.Equal(t, http.StatusAccepted, code)
			assert.Equal(t, p.x.now, p.streams.record.VerifiedAt)
			assert.Equal(t, "expected", p.streams.record.VerificationState)
			assert.False(t, p.streams.record.VerificationRequestedAt.IsZero())
		})
	})

	t.Run("ShouldAcceptEmptyStringStateWhenRequested", func(t *testing.T) {
		p := newTestStreamPush(t, true, "")

		code, _, err := p.push(t, p.verification("jti-1", ""))

		require.NoError(t, err)
		assert.Equal(t, http.StatusAccepted, code)
		assert.Equal(t, p.x.now, p.streams.record.VerifiedAt)
		assert.True(t, p.streams.record.VerificationRequestedAt.IsZero())
	})

	t.Run("ShouldRejectSubjectThatIsNotTheStream", func(t *testing.T) {
		subjects := []struct {
			name    string
			subject map[string]any
		}{
			{name: "ShouldRejectOtherStream", subject: testStreamSubject("s2")},
			{name: "ShouldRejectStreamIDOfOtherCase", subject: testStreamSubject("S1")},
			{name: "ShouldRejectOtherFormat", subject: map[string]any{"format": "email", "email": "user@example.com"}},
			{name: "ShouldRejectComplex", subject: map[string]any{"format": "complex", "tenant": testStreamSubject("s1")}},
			{name: "ShouldRejectUnknownFormatWithID", subject: map[string]any{"format": "stream", "id": "s1"}},
		}

		events := []struct {
			name      string
			eventType string
			payload   map[string]any
		}{
			{name: "Verification", eventType: jwt.SecurityEventTypeSSFVerification, payload: map[string]any{"state": "expected"}},
			{name: "StreamUpdated", eventType: jwt.SecurityEventTypeSSFStreamUpdated, payload: map[string]any{"status": oauth2.SSFStreamStatusDisabled}},
		}

		for _, event := range events {
			for _, tc := range subjects {
				t.Run(event.name+"/"+tc.name, func(t *testing.T) {
					p := newTestStreamPush(t, true, "expected")

					before := p.streams.record.Clone()

					p.requireSetError(t, p.event("jti-1", tc.subject, event.eventType, event.payload), SetErrorInvalidRequest)

					assert.Equal(t, before, p.streams.record)
					assert.Empty(t, p.store.marks)
					assert.Empty(t, p.handler.events)
				})
			}
		}
	})

	t.Run("ShouldAcceptStreamEventsOutsideEventsDelivered", func(t *testing.T) {
		for _, delivered := range [][]string{nil, {jwt.SecurityEventTypeCAEPSessionRevoked}} {
			p := newTestStreamPush(t, true, "expected")

			p.x.record.EventsDelivered = delivered

			code, _, err := p.push(t, p.verification("jti-1", "expected"))

			require.NoError(t, err)
			assert.Equal(t, http.StatusAccepted, code)
			assert.Equal(t, p.x.now, p.streams.record.VerifiedAt)

			code, _, err = p.push(t, p.updated("jti-2", oauth2.SSFStreamStatusPaused, ""))

			require.NoError(t, err)
			assert.Equal(t, http.StatusAccepted, code)
			assert.Equal(t, oauth2.SSFStreamStatusPaused, p.streams.record.Status)
			assert.Len(t, p.handler.events, 2)
		}
	})

	t.Run("ShouldStoreStatusAndReason", func(t *testing.T) {
		p := newTestStreamPush(t, true, "expected")

		code, body, err := p.push(t, p.updated("jti-1", oauth2.SSFStreamStatusPaused, "License is not valid"))

		require.NoError(t, err)
		assert.Equal(t, http.StatusAccepted, code)
		assert.Empty(t, body)
		assert.Equal(t, oauth2.SSFStreamStatusPaused, p.streams.record.Status)
		assert.Equal(t, "License is not valid", p.streams.record.StatusReason)

		// The requested verification is not changed by a status.
		assert.Equal(t, "expected", p.streams.record.VerificationState)
		assert.True(t, p.streams.record.VerifiedAt.IsZero())

		// A status without a reason clears the reason.
		code, _, err = p.push(t, p.updated("jti-2", oauth2.SSFStreamStatusEnabled, ""))

		require.NoError(t, err)
		assert.Equal(t, http.StatusAccepted, code)
		assert.Equal(t, oauth2.SSFStreamStatusEnabled, p.streams.record.Status)
		assert.Empty(t, p.streams.record.StatusReason)
		assert.Len(t, p.store.marks, 2)
	})

	t.Run("ShouldRejectStreamUpdatedWithoutValidStatus", func(t *testing.T) {
		for _, payload := range []map[string]any{{}, {"status": "unknown"}, {"reason": "License is not valid"}} {
			p := newTestStreamPush(t, false, "")

			p.requireSetError(t, p.event("jti-1", testStreamSubject("s1"), jwt.SecurityEventTypeSSFStreamUpdated, payload), SetErrorInvalidRequest)

			assert.Equal(t, oauth2.SSFStreamStatusEnabled, p.streams.record.Status)
		}
	})

	t.Run("ShouldNotCallEventHandler", func(t *testing.T) {
		p := newTestStreamPush(t, true, "expected")

		p.x.record.EventsDelivered = []string{jwt.SecurityEventTypeSSFVerification, jwt.SecurityEventTypeSSFStreamUpdated}

		for i, claims := range []map[string]any{p.verification("jti-1", "expected"), p.verification("jti-2", nil), p.updated("jti-3", oauth2.SSFStreamStatusDisabled, "")} {
			code, _, err := p.push(t, claims)

			require.NoError(t, err)
			assert.Equal(t, http.StatusAccepted, code)
			assert.Len(t, p.handler.events, i+1)
		}

		assert.Empty(t, p.testPush.handler.events)
		assert.Empty(t, p.resolver.subjects)

		// They need no EventHandler.
		p.x.receiver.Config.Handler = nil

		code, _, err := p.push(t, p.updated("jti-4", oauth2.SSFStreamStatusEnabled, ""))

		require.NoError(t, err)
		assert.Equal(t, http.StatusAccepted, code)
	})

	t.Run("ShouldCallStreamEventHandler", func(t *testing.T) {
		t.Run("ShouldCallAfterRecordIsUpdated", func(t *testing.T) {
			p := newTestStreamPush(t, true, "expected")

			code, _, err := p.push(t, p.verification("jti-1", "expected"))

			require.NoError(t, err)
			assert.Equal(t, http.StatusAccepted, code)

			code, _, err = p.push(t, p.updated("jti-2", oauth2.SSFStreamStatusPaused, "License is not valid"))

			require.NoError(t, err)
			assert.Equal(t, http.StatusAccepted, code)

			require.Len(t, p.handler.events, 2)

			verification, updated := p.handler.events[0], p.handler.events[1]

			state := "expected"

			assert.Equal(t, jwt.SecurityEventTypeSSFVerification, verification.Type)
			assert.Equal(t, &jwt.SSFVerification{State: &state}, verification.Event)
			assert.Equal(t, "jti-1", verification.Claims.JTI)
			assert.Nil(t, verification.Principal)

			// The 'state' is consumed after the handler was called, and the handler is handed the verified record.
			assert.True(t, p.handler.stored[0].VerifiedAt.IsZero())
			assert.Equal(t, "expected", p.handler.stored[0].VerificationState)
			assert.Equal(t, p.x.now, p.streams.record.VerifiedAt)
			assert.Equal(t, p.x.now, verification.Stream.VerifiedAt)
			assert.Empty(t, verification.Stream.VerificationState)
			assert.True(t, verification.Stream.VerificationRequestedAt.IsZero())
			assert.Empty(t, verification.Stream.Delivery.AuthorizationHeader)

			assert.Equal(t, jwt.SecurityEventTypeSSFStreamUpdated, updated.Type)
			assert.Equal(t, &jwt.SSFStreamUpdated{Status: oauth2.SSFStreamStatusPaused, Reason: "License is not valid"}, updated.Event)
			assert.Equal(t, oauth2.SSFStreamStatusPaused, p.handler.stored[1].Status)
			assert.Equal(t, oauth2.SSFStreamStatusPaused, updated.Stream.Status)
			assert.Equal(t, "License is not valid", updated.Stream.StatusReason)

			// The handler is handed a copy.
			updated.Stream.Status, updated.Stream.StreamID, updated.Claims.JTI = "changed", "changed", "changed"

			assert.Equal(t, oauth2.SSFStreamStatusPaused, p.streams.record.Status)
			assert.Contains(t, p.store.marks, testTokenMark{p.x.record.Issuer, "s1", "jti-2"})
		})

		t.Run("ShouldBeOptional", func(t *testing.T) {
			p := newTestStreamPush(t, false, "")

			p.x.receiver.Config.StreamHandler = nil

			code, _, err := p.push(t, p.updated("jti-1", oauth2.SSFStreamStatusDisabled, ""))

			require.NoError(t, err)
			assert.Equal(t, http.StatusAccepted, code)
			assert.Equal(t, oauth2.SSFStreamStatusDisabled, p.streams.record.Status)
		})

		t.Run("ShouldAnswer503AndNotMarkOnError", func(t *testing.T) {
			for _, cause := range []error{errors.New("the queue is full"), &SetError{Description: "The code was forgotten."}} {
				p := newTestStreamPush(t, false, "")

				p.handler.err = cause

				code, _, err := p.push(t, p.updated("jti-1", oauth2.SSFStreamStatusDisabled, ""))

				require.Error(t, err)
				assert.Equal(t, http.StatusServiceUnavailable, code)
				assert.Empty(t, p.store.marks)

				// The status is stored again when the Transmitter delivers the SET again.
				p.handler.err = nil

				code, _, err = p.push(t, p.updated("jti-1", oauth2.SSFStreamStatusDisabled, ""))

				require.NoError(t, err)
				assert.Equal(t, http.StatusAccepted, code)
				assert.Len(t, p.handler.events, 2)
				assert.Len(t, p.store.marks, 1)
			}
		})

		t.Run("ShouldReportSetError", func(t *testing.T) {
			p := newTestStreamPush(t, false, "")

			p.handler.err = &SetError{Code: SetErrorAccessDenied, Description: "The Transmitter may not send this event."}

			p.requireSetError(t, p.updated("jti-1", oauth2.SSFStreamStatusDisabled, ""), SetErrorAccessDenied)

			assert.Empty(t, p.store.marks)
		})
	})

	t.Run("ShouldConsumeStateOnce", func(t *testing.T) {
		p := newTestStreamPush(t, true, "expected")

		code, _, err := p.push(t, p.verification("jti-1", "expected"))

		require.NoError(t, err)
		assert.Equal(t, http.StatusAccepted, code)

		// RFC 8935 Section 2: the same SET is acknowledged again, and not handled again.
		code, _, err = p.push(t, p.verification("jti-1", "expected"))

		require.NoError(t, err)
		assert.Equal(t, http.StatusAccepted, code)
		assert.Len(t, p.handler.events, 1)

		// Another SET with the 'state' verifies nothing, and is not a failure to verify.
		p.x.now = p.x.now.Add(time.Minute)

		code, _, err = p.push(t, p.verification("jti-2", "expected"))

		require.NoError(t, err)
		assert.Equal(t, http.StatusAccepted, code)
		assert.Equal(t, p.x.now.Add(-time.Minute), p.streams.record.VerifiedAt)
		assert.Len(t, p.handler.events, 1)
		assert.Len(t, p.store.marks, 2)
	})

	t.Run("ShouldAnswer503AndNotMarkOnStorageError", func(t *testing.T) {
		cause := errors.New("the database is unreachable")

		for _, missing := range []error{cause, oauth2.ErrNotFound} {
			p := newTestStreamPush(t, true, "expected")

			p.streams.err = missing

			for _, claims := range []map[string]any{p.verification("jti-1", "expected"), p.verification("jti-2", nil), p.updated("jti-3", oauth2.SSFStreamStatusPaused, "")} {
				code, body, err := p.push(t, claims)

				require.ErrorIs(t, err, missing)
				assert.Equal(t, http.StatusServiceUnavailable, code)
				assert.Empty(t, body)
			}

			assert.Empty(t, p.store.marks)
			assert.Empty(t, p.handler.events)
		}
	})
}
