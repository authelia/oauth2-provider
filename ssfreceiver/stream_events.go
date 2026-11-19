// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"authelia.com/provider/oauth2/token/jwt"
)

// The descriptions of a SetError are fixed, and never hold a value of the SET.
//
// See: https://www.rfc-editor.org/rfc/rfc8935#section-2.4
var (
	errStreamEventSubject = &SetError{Code: SetErrorInvalidRequest, Description: "The subject of the event is not the stream it was received on."}
	errVerificationState  = &SetError{Code: SetErrorInvalidState, Description: "The state of the verification event is not the requested one."}
)

// isStreamEvent returns true for the verification and stream updated event types, which the Receiver handles itself
// and a stream delivers whatever its 'events_delivered'.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.4
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.5
func isStreamEvent(eventType string) bool {
	return eventType == jwt.SecurityEventTypeSSFVerification || eventType == jwt.SecurityEventTypeSSFStreamUpdated
}

// processStreamEvent updates the record of the stream from a verification or stream updated event, and calls the
// optional Config.StreamHandler. The event is never handed to Config.Handler.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.4.1
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.5
func (r *Receiver) processStreamEvent(ctx context.Context, event *ReceivedEvent) (err error) {
	// SSF Section 8.1.4.1, Section 8.1.5: the subject is the opaque identifier of the stream.
	if subject := event.Claims.SubjectIdentifier; subject == nil || subject.Format != jwt.SubjectIdentifierFormatOpaque || subject.ID != event.Stream.StreamID {
		serr := *errStreamEventSubject

		return &serr
	}

	handed := event.handed()

	switch typed := event.Event.(type) {
	case *jwt.SSFVerification:
		if typed.State != nil {
			return r.verifyRequested(ctx, handed, *typed.State)
		}

		err = r.verified(ctx, handed.Stream)
	case *jwt.SSFStreamUpdated:
		err = r.statusUpdated(ctx, handed.Stream, typed)
	default:
		err = errors.New("ssfreceiver: the stream event has no typed payload")
	}

	if err != nil {
		return err
	}

	return r.handleStreamEvent(ctx, handed)
}

// handleStreamEvent calls the optional Config.StreamHandler.
func (r *Receiver) handleStreamEvent(ctx context.Context, handed *ReceivedEvent) (err error) {
	if r.Config.StreamHandler == nil {
		return nil
	}

	return handlerFault(r.Config.StreamHandler.HandleStreamEvent(ctx, handed))
}

// verifyRequested handles a verification event with a 'state'. A 'state' that is not the one of the requested
// verification is refused. The requested verification is consumed only after the optional Config.StreamHandler
// accepted the event, so the stream still verifies when the SET is delivered again after a failure. A 'state' when no
// verification is requested was consumed by a delivery before, or is stale, and is acknowledged without changing the
// record, as a Transmitter may disable a stream it is told failed to verify.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.4.1
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.4.2
func (r *Receiver) verifyRequested(ctx context.Context, handed *ReceivedEvent, state string) (err error) {
	record := handed.Stream

	var stored *StreamRecord

	if stored, err = r.Store.GetSSFReceiverStream(ctx, record.Issuer, record.StreamID); err != nil {
		return fmt.Errorf("ssfreceiver: the requested verification of the stream could not be read: %w", err)
	}

	if stored.VerificationRequestedAt.IsZero() {
		return nil
	}

	if subtle.ConstantTimeCompare([]byte(stored.VerificationState), []byte(state)) != 1 {
		serr := *errVerificationState

		return &serr
	}

	at := r.time()

	record.VerificationState, record.VerificationRequestedAt, record.VerifiedAt = "", time.Time{}, at

	if err = r.handleStreamEvent(ctx, handed); err != nil {
		return err
	}

	// A concurrent delivery that consumed the requested verification first verified the stream.
	if err = r.Store.ConsumeSSFReceiverStreamVerificationState(ctx, record.Issuer, record.StreamID, state, at); err != nil && !errors.Is(err, ErrVerificationStateMismatch) {
		return fmt.Errorf("ssfreceiver: the verification of the stream could not be stored: %w", err)
	}

	return nil
}

// verified records a verification the Receiver did not request, which has no 'state', in the store and in the record,
// which is a copy.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.4
func (r *Receiver) verified(ctx context.Context, record *StreamRecord) (err error) {
	at := r.time()

	if err = r.Store.SetSSFReceiverStreamVerifiedAt(ctx, record.Issuer, record.StreamID, at); err != nil {
		return fmt.Errorf("ssfreceiver: the verification of the stream could not be stored: %w", err)
	}

	record.VerifiedAt = at

	return nil
}

// statusUpdated records the status of the stream in the store and in the record, which is a copy.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.5
func (r *Receiver) statusUpdated(ctx context.Context, record *StreamRecord, event *jwt.SSFStreamUpdated) (err error) {
	if err = r.Store.UpdateSSFReceiverStreamStatus(ctx, record.Issuer, record.StreamID, event.Status, event.Reason); err != nil {
		return fmt.Errorf("ssfreceiver: the status of the stream could not be stored: %w", err)
	}

	record.Status, record.StatusReason = event.Status, event.Reason

	return nil
}
