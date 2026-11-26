// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"
	"time"

	"authelia.com/provider/oauth2/internal/ssfjson"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

const ssfVerificationAllowedMethods = http.MethodPost

// SSFVerificationRequestBody is the decoded body of a verification request.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.4.2
type SSFVerificationRequestBody struct {
	StreamID string `json:"stream_id"`

	// State is the 'state' member, or nil when it is absent or null. An empty string is a value.
	State *string `json:"state"`
}

// UnmarshalJSON decodes the body. A member is matched by its exact name, and a repeated member name is an error (RFC
// 8259 Section 4).
func (b *SSFVerificationRequestBody) UnmarshalJSON(data []byte) (err error) {
	return ssfjson.UnmarshalMembers(data, map[string]any{
		ssfStreamQueryStreamID: &b.StreamID,
		"state":                &b.State,
	})
}

// HandleSSFVerificationRequest authorizes a verification request, which needs 'ssf.manage', and calls the configured
// SSFVerificationHandler for the stream of the requesting client. The application writes 204 on nil and uses
// WriteSSFError otherwise. A Content-Type header is not required, and one that is present must be 'application/json'.
//
// An unknown stream and another client's stream give the same 404. A policy error gives 403, and a stored push endpoint
// the SSFEndpointValidator no longer permits gives 400. A request inside the configured MinVerificationInterval gives
// ErrSSFVerificationThrottled and does not call the handler. The time is recorded before the handler is called, so a
// failed delivery counts towards the interval and a failure to save the time fails the request; concurrent requests may
// both pass.
//
// Nothing is transmitted on a stream that is not enabled (SSF Section 8.1.2.1), which takes precedence over a
// Transmitter being free to send a verification event at any time (SSF Section 8.1.4):
//
//   - A paused stream reaches the handler and the request is answered with 204, as the event will be transmitted at
//     some point in the future. The application holds the event with the others of the stream until it is enabled.
//   - A disabled stream gives 400 and does not call the handler or record the time, as its events are not held and so
//     the event would never be transmitted.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.2.1
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.4.2
func (f *Fosite) HandleSSFVerificationRequest(ctx context.Context, r *http.Request, session Session) (err error) {
	if r.Method != http.MethodPost {
		return &ssfMethodNotAllowedError{
			error: errorsx.WithStack(ErrInvalidRequest.WithHintf("HTTP method is '%s', expected '%s'.", r.Method, ssfVerificationAllowedMethods).WithCode(http.StatusMethodNotAllowed)),
			allow: ssfVerificationAllowedMethods,
		}
	}

	var (
		ar      AccessRequester
		storage SSFStreamStorage
		body    *SSFVerificationRequestBody
	)

	if ar, storage, err = f.authorizeSSFRequest(ctx, r, session, true); err != nil {
		return err
	}

	config := f.getSSFConfig(ctx)

	if config.VerificationHandler == nil {
		return errorsx.WithStack(ErrServerError.WithDebug("The Shared Signals Framework transmitter has no verification handler."))
	}

	if body, err = decodeSSFRequestBody[SSFVerificationRequestBody](f, ctx, r); err != nil {
		return err
	}

	if body.StreamID == "" {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("The 'stream_id' is required in the request body."))
	}

	clientID := ar.GetClient().GetID()

	var stream *SSFStream

	if stream, err = ownedSSFStream(ctx, storage, clientID, body.StreamID); err != nil {
		return ssfStreamStorageError(err)
	}

	client := ar.GetClient()

	if _, err = f.resolveSSFClientPolicy(ctx, config, client); err != nil {
		return err
	}

	// SSF Section 8.1.2.1: a disabled stream neither transmits nor holds events, so the event can never be sent.
	if stream.Status == SSFStreamStatusDisabled {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("The stream is disabled, so a verification event cannot be transmitted on it."))
	}

	if err = f.validateSSFStoredDelivery(ctx, config, client, stream.Delivery); err != nil {
		return err
	}

	stream = f.currentSSFStream(ctx, config, stream)

	now := time.Now().UTC()

	if config.isVerificationThrottled(stream, now) {
		return errorsx.WithStack(ErrSSFVerificationThrottled.WithHintf("A verification event may be requested once every %d seconds.", stream.MinVerificationInterval))
	}

	if err = storage.UpdateSSFStreamLastVerification(ctx, clientID, body.StreamID, now); err != nil {
		return ssfStreamStorageError(err)
	}

	return config.VerificationHandler.HandleSSFVerification(ctx, stream, body.State)
}

// NewSSFVerificationSubject returns the sub_id of a verification event, an opaque identifier holding the stream ID. A
// stream updated event has the same sub_id.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.4.1
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.5
func NewSSFVerificationSubject(streamID string) (subject *jwt.SubjectIdentifier, err error) {
	return jwt.NewSubjectIdentifierOpaque(streamID)
}
