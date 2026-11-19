// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/token/jwt"
)

const testUnknownType = "https://events.example.com/unknown"

// testSubjectResolver is the SubjectResolver of a Receiver under test.
type testSubjectResolver struct {
	records   []*StreamRecord
	subjects  []*jwt.SubjectIdentifier
	principal any
	err       error
}

func (s *testSubjectResolver) ResolveSubject(_ context.Context, record *StreamRecord, subject *jwt.SubjectIdentifier) (principal any, err error) {
	s.records = append(s.records, record)
	s.subjects = append(s.subjects, subject)

	return s.principal, s.err
}

func (p *testPush) resolver(principal any, err error) *testSubjectResolver {
	resolver := &testSubjectResolver{principal: principal, err: err}

	p.x.receiver.Config.Subjects = resolver

	return resolver
}

func (p *testPush) push(t *testing.T, claims map[string]any) (code int, body string, err error) {
	rw, err := p.do(t, p.request(strings.NewReader(p.x.set().sign(t, claims))))

	return rw.Code, rw.Body.String(), err
}

func testComplexSubject(members ...string) map[string]any {
	subject := map[string]any{"format": "complex"}

	for _, member := range members {
		subject[member] = map[string]any{"format": "opaque", "id": member + "-1"}
	}

	return subject
}

func TestReceiverDispatch(t *testing.T) {
	t.Run("ShouldDispatchTypedEventAndPrincipal", func(t *testing.T) {
		p := newTestPush(t)
		resolver := p.resolver("principal-1", nil)

		code, body, err := p.push(t, p.x.claims())

		require.NoError(t, err)
		assert.Equal(t, http.StatusAccepted, code)
		assert.Empty(t, body)

		require.Len(t, resolver.subjects, 1)
		assert.Equal(t, jwt.SubjectIdentifierFormatEmail, resolver.subjects[0].Format)
		assert.Equal(t, "user@example.com", resolver.subjects[0].Email)

		require.Len(t, p.handler.events, 1)

		event := p.handler.events[0]

		assert.Equal(t, jwt.SecurityEventTypeCAEPSessionRevoked, event.Type)
		assert.IsType(t, &jwt.CAEPSessionRevoked{}, event.Event)
		assert.Equal(t, "kept", event.Payload["vendor_member"])
		assert.Equal(t, "principal-1", event.Principal)
		assert.Equal(t, testJTI, event.Claims.JTI)
		assert.Equal(t, p.x.record.StreamID, event.Stream.StreamID)
		assert.True(t, jwt.IsSignedJWT(event.Token))
		assert.False(t, event.Encrypted)
		assert.Len(t, p.store.marks, 1)
	})

	t.Run("ShouldDispatchRawEventForUnknownType", func(t *testing.T) {
		p := newTestPush(t)

		p.x.record.EventsDelivered = []string{testUnknownType}

		claims := p.x.claims()
		claims["events"] = map[string]any{testUnknownType: map[string]any{"member": "value"}}

		code, _, err := p.push(t, claims)

		require.NoError(t, err)
		assert.Equal(t, http.StatusAccepted, code)

		require.Len(t, p.handler.events, 1)

		event := p.handler.events[0]

		assert.Equal(t, testUnknownType, event.Type)
		assert.Equal(t, jwt.RawSecurityEvent{URI: testUnknownType, Claims: map[string]any{"member": "value"}}, event.Event)
		assert.Equal(t, map[string]any{"member": "value"}, event.Payload)
		assert.Nil(t, event.Principal)
	})

	t.Run("ShouldAnswer503AndNotMarkOnHandlerError", func(t *testing.T) {
		p := newTestPush(t)

		cause := errors.New("the queue is full")
		p.handler.err = cause

		code, body, err := p.push(t, p.x.claims())

		require.ErrorIs(t, err, cause)
		assert.Equal(t, http.StatusServiceUnavailable, code)
		assert.Empty(t, body)
		assert.Empty(t, p.store.marks)

		// The Transmitter delivers the SET again, and it is dispatched again.
		p.handler.err = nil

		code, _, err = p.push(t, p.x.claims())

		require.NoError(t, err)
		assert.Equal(t, http.StatusAccepted, code)
		assert.Len(t, p.handler.events, 2)
		assert.Len(t, p.store.marks, 1)
	})

	t.Run("ShouldReportSetErrorFromHandler", func(t *testing.T) {
		denied := &SetError{Code: SetErrorAccessDenied, Description: "The Transmitter may not send this event."}

		var missing *SetError

		testCases := []struct {
			name     string
			err      error
			expected string
		}{
			{name: "ShouldReportSetError", err: denied, expected: SetErrorAccessDenied},
			{name: "ShouldReportWrappedSetError", err: fmt.Errorf("refused: %w", denied), expected: SetErrorAccessDenied},
			{name: "ShouldAnswer503ForSetErrorWithoutCode", err: &SetError{Description: "The code was forgotten."}},
			{name: "ShouldAnswer503ForWrappedSetErrorWithoutCode", err: fmt.Errorf("refused: %w", &SetError{})},
			{name: "ShouldAnswer503ForNilSetError", err: missing},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				p := newTestPush(t)

				p.handler.err = tc.err

				rw, err := p.do(t, p.request(strings.NewReader(p.token(t))))

				assert.Len(t, p.handler.events, 1)
				assert.Empty(t, p.store.marks)

				if tc.expected == "" {
					require.Error(t, err)
					assert.Equal(t, http.StatusServiceUnavailable, rw.Code)
					assert.Empty(t, rw.Body.Bytes())

					return
				}

				require.NoError(t, err)
				assert.Equal(t, "The Transmitter may not send this event.", requireSetError(t, rw, tc.expected))
			})
		}
	})

	t.Run("ShouldAcknowledgeUnknownSubjectWithoutError", func(t *testing.T) {
		testCases := []struct {
			name string
			err  error
		}{
			{name: "ShouldAcknowledgeUnknown", err: ErrSubjectUnknown},
			{name: "ShouldAcknowledgeWrappedUnknown", err: fmt.Errorf("no such user: %w", ErrSubjectUnknown)},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				p := newTestPush(t)
				resolver := p.resolver(nil, tc.err)

				code, body, err := p.push(t, p.x.claims())

				require.NoError(t, err)
				assert.Equal(t, http.StatusAccepted, code)
				assert.Empty(t, body)
				assert.Len(t, resolver.subjects, 1)
				assert.Empty(t, p.handler.events)
				assert.Len(t, p.store.marks, 1)
			})
		}
	})

	t.Run("ShouldAnswer503AndNotMarkOnResolverError", func(t *testing.T) {
		cause := errors.New("the directory is unreachable")

		testCases := []struct {
			name string
			err  error
		}{
			{name: "ShouldNotReportError", err: cause},
			{name: "ShouldNotReportSetError", err: &SetError{Code: SetErrorAccessDenied, Description: "The subject is not known."}},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				p := newTestPush(t)

				p.resolver(nil, tc.err)

				code, body, err := p.push(t, p.x.claims())

				require.Error(t, err)
				assert.Equal(t, http.StatusServiceUnavailable, code)
				assert.Empty(t, body)
				assert.Empty(t, p.handler.events)
				assert.Empty(t, p.store.marks)
			})
		}

		t.Run("ShouldKeepCauseForCaller", func(t *testing.T) {
			p := newTestPush(t)

			p.resolver(nil, cause)

			_, _, err := p.push(t, p.x.claims())

			assert.ErrorIs(t, err, cause)
		})
	})

	t.Run("ShouldDiscardUnprocessedCriticalMember", func(t *testing.T) {
		testCases := []struct {
			name      string
			critical  []string
			processed []string
			subject   map[string]any
		}{
			{name: "ShouldDiscardDefinedMember", critical: []string{"tenant", "user"}, processed: []string{"user"}, subject: testComplexSubject("user", "tenant")},
			{name: "ShouldDiscardAdditionalMemberByDefault", critical: []string{"catalog"}, subject: testComplexSubject("user", "catalog")},
			{name: "ShouldDiscardAdditionalMember", critical: []string{"catalog"}, processed: []string{"user", "tenant"}, subject: testComplexSubject("catalog")},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				p := newTestPush(t)
				resolver := p.resolver("principal-1", nil)

				p.x.server.critical.Store(&tc.critical)
				p.x.receiver.Config.ProcessedSubjectMembers = tc.processed

				claims := p.x.claims()
				claims["sub_id"] = tc.subject

				code, body, err := p.push(t, claims)

				// SSF Section 3.6 with RFC 8936 Section 2: discarded, and not reported as an error.
				require.NoError(t, err)
				assert.Equal(t, http.StatusAccepted, code)
				assert.Empty(t, body)
				assert.Empty(t, resolver.subjects)
				assert.Empty(t, p.handler.events)
				assert.Len(t, p.store.marks, 1)
			})
		}
	})

	t.Run("ShouldDispatchWhenCriticalMemberIsProcessed", func(t *testing.T) {
		testCases := []struct {
			name      string
			critical  []string
			processed []string
			subject   map[string]any
		}{
			{name: "ShouldProcessTheSevenByDefault", critical: []string{"user", "device", "session", "application", "tenant", "org_unit", "group"}, subject: testComplexSubject("user", "device", "session", "application", "tenant", "org_unit", "group")},
			{name: "ShouldProcessConfiguredMember", critical: []string{"tenant", "user"}, processed: []string{"user", "tenant"}, subject: testComplexSubject("user", "tenant")},
			{name: "ShouldProcessConfiguredAdditionalMember", critical: []string{"catalog"}, processed: []string{"catalog"}, subject: testComplexSubject("catalog")},
			{name: "ShouldIgnoreCriticalMemberNotInSubject", critical: []string{"tenant"}, processed: []string{"user"}, subject: testComplexSubject("user")},
			{name: "ShouldIgnoreUnprocessedMemberNotCritical", critical: []string{"user"}, processed: []string{"user"}, subject: testComplexSubject("user", "tenant", "catalog")},
			{name: "ShouldIgnoreUnprocessedMemberWithoutCriticalMembers", processed: []string{"user"}, subject: testComplexSubject("tenant")},
			{name: "ShouldIgnoreCriticalMembersForSimpleSubject", critical: []string{"email"}, processed: []string{"user"}, subject: map[string]any{"format": "email", "email": "user@example.com"}},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				p := newTestPush(t)

				if tc.critical != nil {
					p.x.server.critical.Store(&tc.critical)
				}

				p.x.receiver.Config.ProcessedSubjectMembers = tc.processed

				claims := p.x.claims()
				claims["sub_id"] = tc.subject

				code, _, err := p.push(t, claims)

				require.NoError(t, err)
				assert.Equal(t, http.StatusAccepted, code)
				assert.Len(t, p.handler.events, 1)
				assert.Len(t, p.store.marks, 1)
			})
		}
	})

	t.Run("ShouldSkipTypeOutsideEventsDelivered", func(t *testing.T) {
		testCases := []struct {
			name      string
			delivered []string
		}{
			{name: "ShouldSkipOtherType", delivered: []string{jwt.SecurityEventTypeCAEPCredentialChange}},
			{name: "ShouldSkipWithoutEventsDelivered"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				p := newTestPush(t)
				resolver := p.resolver("principal-1", nil)

				p.x.record.EventsDelivered = tc.delivered

				code, body, err := p.push(t, p.x.claims())

				require.NoError(t, err)
				assert.Equal(t, http.StatusAccepted, code)
				assert.Empty(t, body)
				assert.Empty(t, resolver.subjects)
				assert.Empty(t, p.handler.events)
				assert.Len(t, p.store.marks, 1)
			})
		}
	})

	t.Run("ShouldHandResolverTheCloneNotTheStoredRecord", func(t *testing.T) {
		p := newTestPush(t)
		resolver := p.resolver("principal-1", nil)

		p.x.record.PendingAuthorizationHeader = testPendingPushSecret

		expected := p.x.record.Clone()

		code, _, err := p.push(t, p.x.claims())

		require.NoError(t, err)
		assert.Equal(t, http.StatusAccepted, code)

		require.Len(t, resolver.records, 1)
		require.Len(t, p.handler.events, 1)

		resolved, handled := resolver.records[0], p.handler.events[0].Stream

		assert.NotSame(t, p.x.record, resolved)
		assert.NotSame(t, p.x.record, handled)
		assert.NotSame(t, resolved, handled)

		// The secrets of the stream are not handed to the application.
		assert.Empty(t, resolved.Delivery.AuthorizationHeader)
		assert.Empty(t, handled.Delivery.AuthorizationHeader)
		assert.Empty(t, resolved.PendingAuthorizationHeader)
		assert.Empty(t, handled.PendingAuthorizationHeader)

		expected.Delivery.AuthorizationHeader, expected.PendingAuthorizationHeader = "", ""

		assert.Equal(t, expected, resolved)
		assert.Equal(t, expected, handled)

		for _, record := range []*StreamRecord{resolved, handled} {
			record.StreamID = "changed"
			record.Audience[0] = "changed"
			record.EventsDelivered[0] = "changed"
			record.Delivery.AuthorizationHeader = "changed"
			record.PendingAuthorizationHeader = "changed"
		}

		expected.Delivery.AuthorizationHeader, expected.PendingAuthorizationHeader = testPushSecret, testPendingPushSecret

		assert.Equal(t, expected, p.x.record)
	})

	t.Run("ShouldMarkTheReceivedTokenWhenHandlerChangesTheEvent", func(t *testing.T) {
		p := newTestPush(t)

		p.x.receiver.Config.Handler = testEventHandlerFunc(func(event *ReceivedEvent) error {
			event.Stream.Issuer, event.Stream.StreamID, event.Claims.JTI = "changed", "changed", "changed"

			return nil
		})

		code, _, err := p.push(t, p.x.claims())

		require.NoError(t, err)
		assert.Equal(t, http.StatusAccepted, code)
		assert.Contains(t, p.store.marks, testTokenMark{p.x.record.Issuer, p.x.record.StreamID, testJTI})
		assert.Len(t, p.store.marks, 1)
	})

	t.Run("ShouldAnswer503WithoutHandler", func(t *testing.T) {
		p := newTestPush(t)

		p.x.receiver.Config.Handler = nil

		code, _, err := p.push(t, p.x.claims())

		require.Error(t, err)
		assert.Equal(t, http.StatusServiceUnavailable, code)
		assert.Empty(t, p.store.marks)
	})

	t.Run("ShouldAcknowledgeEventNotDeliveredWithoutHandler", func(t *testing.T) {
		p := newTestPush(t)

		p.x.receiver.Config.Handler = nil
		p.x.record.EventsDelivered = nil

		code, _, err := p.push(t, p.x.claims())

		require.NoError(t, err)
		assert.Equal(t, http.StatusAccepted, code)
		assert.Len(t, p.store.marks, 1)
	})
}

type testEventHandlerFunc func(event *ReceivedEvent) error

func (f testEventHandlerFunc) HandleSecurityEvent(_ context.Context, event *ReceivedEvent) (err error) {
	return f(event)
}
