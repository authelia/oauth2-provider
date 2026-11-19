// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/token/jwt"
)

// The member names of a Complex Subject.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.3
const (
	subjectMemberUser        = "user"
	subjectMemberDevice      = "device"
	subjectMemberSession     = "session"
	subjectMemberApplication = "application"
	subjectMemberTenant      = "tenant"
	subjectMemberOrgUnit     = "org_unit"
	subjectMemberGroup       = "group"
)

var (
	errHandler         = errors.New("ssfreceiver: the event handler is not configured")
	errHandlerSetError = errors.New("ssfreceiver: the event handler returned a *SetError without a code")
)

// resolveError is a failure of the SubjectResolver. It does not unwrap, so a *SetError of the resolver is never
// reported to the Transmitter.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-9.3
type resolveError struct {
	cause error
}

// Error implements error.
func (e *resolveError) Error() string {
	return "ssfreceiver: the subject could not be resolved: " + e.cause.Error()
}

// Is returns true when the cause is the target.
func (e *resolveError) Is(target error) bool {
	return errors.Is(e.cause, target)
}

// process handles a validated event whose SET was not received before. A nil error acknowledges the SET, a *SetError
// is reported to the Transmitter, and any other error means the event was not persisted. The handed is the copy of the
// event the EventHandler accepted, and nil for an event it was not handed.
func (r *Receiver) process(ctx context.Context, event *ReceivedEvent) (handed *ReceivedEvent, err error) {
	if isStreamEvent(event.Type) {
		return nil, r.processStreamEvent(ctx, event)
	}

	return r.dispatch(ctx, event)
}

// dispatch hands the event to the application. An event the application is not to receive is acknowledged and not
// dispatched, as only a SET that could not be parsed or validated is reported as an error.
//
// See: https://www.rfc-editor.org/rfc/rfc8935#section-2
// See: https://www.rfc-editor.org/rfc/rfc8936#section-2
func (r *Receiver) dispatch(ctx context.Context, event *ReceivedEvent) (handed *ReceivedEvent, err error) {
	// SSF Section 8.1.1: the 'events_delivered' are the event types of the stream.
	if !slices.Contains(event.Stream.EventsDelivered, event.Type) {
		return nil, nil
	}

	if r.Config.Handler == nil {
		return nil, errHandler
	}

	var discard bool

	// SSF Section 3.6.
	if discard, err = r.hasUnprocessedCriticalMember(ctx, event); err != nil || discard {
		return nil, err
	}

	handed = event.handed()

	if r.Config.Subjects != nil {
		if handed.Principal, err = r.Config.Subjects.ResolveSubject(ctx, event.Stream.Clone(), handed.Claims.SubjectIdentifier); err != nil {
			// SSF Section 9.3: a subject that is not known is not reported as an error.
			if errors.Is(err, ErrSubjectUnknown) {
				return nil, nil
			}

			return nil, &resolveError{cause: err}
		}
	}

	if err = handlerFault(r.Config.Handler.HandleSecurityEvent(ctx, handed)); err != nil {
		return nil, err
	}

	return handed, nil
}

// handed returns the copy of the event the application is handed, with its own Stream and Claims, so the SET that is
// remembered is the one that was received.
func (e *ReceivedEvent) handed() (event *ReceivedEvent) {
	c, claims := *e, *e.Claims

	c.Stream, c.Claims = e.Stream.Clone(), &claims

	return &c
}

// handlerFault returns the error of a handler, or errHandlerSetError for a *SetError that has no 'err' value to
// report, which is a fault of the handler and not of the SET.
//
// See: https://www.rfc-editor.org/rfc/rfc8935#section-2.3
func handlerFault(cause error) (err error) {
	if serr := new(SetError); errors.As(cause, &serr) && (serr == nil || serr.Code == "") {
		return errHandlerSetError
	}

	return cause
}

// hasUnprocessedCriticalMember returns true when the subject of the event is a Complex Subject with a member the
// Transmitter Configuration Metadata names in 'critical_subject_members' and Config.ProcessedSubjectMembers does not.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.6
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.1
func (r *Receiver) hasUnprocessedCriticalMember(ctx context.Context, event *ReceivedEvent) (unprocessed bool, err error) {
	subject := event.Claims.SubjectIdentifier

	if subject == nil || subject.Format != jwt.SubjectIdentifierFormatComplex {
		return false, nil
	}

	var configuration *oauth2.SSFConfiguration

	if configuration, err = r.Discover(ctx, event.Stream.Issuer); err != nil {
		return false, fmt.Errorf("ssfreceiver: the critical subject members of the transmitter could not be resolved: %w", err)
	}

	processed := r.processedSubjectMembers()

	for _, member := range configuration.CriticalSubjectMembers {
		if hasComplexSubjectMember(subject, member) && !slices.Contains(processed, member) {
			return true, nil
		}
	}

	return false, nil
}

// processedSubjectMembers returns Config.ProcessedSubjectMembers, or the member names of a Complex Subject.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.3
func (r *Receiver) processedSubjectMembers() (members []string) {
	if len(r.Config.ProcessedSubjectMembers) != 0 {
		return r.Config.ProcessedSubjectMembers
	}

	return []string{
		subjectMemberUser, subjectMemberDevice, subjectMemberSession, subjectMemberApplication,
		subjectMemberTenant, subjectMemberOrgUnit, subjectMemberGroup,
	}
}

// hasComplexSubjectMember returns true when the Complex Subject has the member, defined or additional.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.3
func hasComplexSubjectMember(subject *jwt.SubjectIdentifier, name string) bool {
	switch name {
	case subjectMemberUser:
		return subject.User != nil
	case subjectMemberDevice:
		return subject.Device != nil
	case subjectMemberSession:
		return subject.Session != nil
	case subjectMemberApplication:
		return subject.Application != nil
	case subjectMemberTenant:
		return subject.Tenant != nil
	case subjectMemberOrgUnit:
		return subject.OrgUnit != nil
	case subjectMemberGroup:
		return subject.Group != nil
	default:
		_, ok := subject.Additional[name]

		return ok
	}
}
