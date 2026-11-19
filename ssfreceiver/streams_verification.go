// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"authelia.com/provider/oauth2"
)

// verificationStateBytes is the number of random bytes of a verification 'state'.
const verificationStateBytes = 32

// streamVerificationRequest is the body of a verification request.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.4.2
type streamVerificationRequest struct {
	StreamID string `json:"stream_id"`
	State    string `json:"state"`
}

// RequestStreamVerification asks the Transmitter to send a verification event on the stream, which must have an
// active record. A new random 'state' is stored on the record before the request is made, as the event may be
// delivered before the response, and replaces the one of an earlier request, whose event is then refused. The
// response is an empty 204, and any 2xx is a success.
//
// A nil error means only that the Transmitter has sent the event or will. The event may arrive late, or never, and in
// any order relative to the other events of the stream, so the caller must not wait for it: the stream is verified
// when the VerifiedAt of its record changes, and the request is pending while its VerificationRequestedAt is set.
//
// It returns ErrVerificationInterval, before any request, when the MinVerificationInterval of the record has not
// passed since the later of its VerificationRequestedAt and VerifiedAt. The check and the stored 'state' are not
// atomic, so the application serializes the requests for one stream: an overlapping request replaces the 'state' of
// the other, whose event is then refused. A Transmitter which answers with a 429 gives
// an error matching ErrTransmitterThrottled, whose RetryAfter is the delay it asked for.
//
// The requested verification is withdrawn from the record when the request was not sent, or the Transmitter refused
// it with a 3xx or a 4xx. It is kept, and the error returned, when the request may have been sent and has no
// response, or the response is a 5xx, as the Transmitter or a server behind a gateway may have the request: a POST is
// not sent again, and a late event with the 'state' still verifies the stream. The interval then applies to the next
// request.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.4.2
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1
// See: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html#section-2.7.3
func (r *Receiver) RequestStreamVerification(ctx context.Context, issuer, streamID string) (err error) {
	var record *StreamRecord

	if record, err = r.activeStream(ctx, issuer, streamID); err != nil {
		return err
	}

	now := r.time()

	// SSF Section 8.1.1: the minimum time between verification requests, which is of the record.
	if isInsideVerificationInterval(record, now) {
		return ErrVerificationInterval
	}

	var configuration *oauth2.SSFConfiguration

	if configuration, err = r.Discover(ctx, issuer); err != nil {
		return err
	}

	// The transport refuses the endpoint too, which here would be after the state is stored.
	if _, err = transmitterLocation(configuration.VerificationEndpoint, nil); err != nil {
		return err
	}

	var state string

	if state, err = newVerificationState(); err != nil {
		return err
	}

	if err = r.Store.SetSSFReceiverStreamVerificationState(ctx, issuer, streamID, state, now); err != nil {
		return fmt.Errorf("ssfreceiver: the requested verification of the stream could not be stored: %w", err)
	}

	// SSF Section 8.1.4.2: the response is an empty 204. Any 2xx is one the Transmitter accepted the request with.
	if _, err = r.transmit(ctx, issuer, transmitterRequest{
		method:   http.MethodPost,
		endpoint: configuration.VerificationEndpoint,
		scope:    oauth2.ScopeSSFManage,
		body:     streamVerificationRequest{StreamID: streamID, State: state},
	}); err == nil || !isVerificationRefused(err) {
		return err
	}

	// The context of a failed request may be done.
	if werr := r.Store.SetSSFReceiverStreamVerificationState(context.WithoutCancel(ctx), issuer, streamID, "", time.Time{}); werr != nil {
		err = errors.Join(err, fmt.Errorf("ssfreceiver: the requested verification of the stream could not be withdrawn: %w", werr))
	}

	return err
}

// isVerificationRefused reports whether the error is of a verification request the Transmitter does not have: one
// that was not sent, or one it answered with a 3xx or a 4xx. After any other response, or none, it may have it.
func isVerificationRefused(err error) (refused bool) {
	var e *TransmitterError

	if errors.As(err, &e) {
		return e.Status >= 300 && e.Status <= 499
	}

	return !isUnconfirmed(err)
}

// isInsideVerificationInterval reports whether the 'min_verification_interval' of the stream has not passed since
// the last verification request, which a verification event clears, or the last verification event.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1
func isInsideVerificationInterval(record *StreamRecord, now time.Time) (inside bool) {
	last := record.VerificationRequestedAt

	if record.VerifiedAt.After(last) {
		last = record.VerifiedAt
	}

	if record.MinVerificationInterval <= 0 || last.IsZero() {
		return false
	}

	// The seconds are compared, as the interval may be longer than a time.Duration.
	return int64(now.Sub(last)/time.Second) < int64(record.MinVerificationInterval)
}

// newVerificationState returns a 'state' which can not be guessed.
func newVerificationState() (state string, err error) {
	data := make([]byte, verificationStateBytes)

	if _, err = rand.Read(data); err != nil {
		return "", fmt.Errorf("ssfreceiver: the verification state could not be generated: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(data), nil
}
