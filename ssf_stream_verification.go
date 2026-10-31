// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"
	"time"

	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

const ssfVerificationAllowedMethods = http.MethodPost

// SSFVerificationRequestBody is the decoded body of a verification request.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.4.2
type SSFVerificationRequestBody struct {
	StreamID string `json:"stream_id"`
	State    string `json:"state"`
}

// HandleSSFVerificationRequest authorizes a verification request, which needs 'ssf.manage', and calls the configured
// SSFVerificationHandler for the stream of the requesting client. The application writes 204 on nil and uses
// WriteSSFError otherwise.
//
// An unknown stream and another client's stream give the same 404. A request inside the stream's
// MinVerificationInterval gives ErrSSFVerificationThrottled and does not call the handler; the time is recorded only
// after the handler succeeds, and concurrent requests may both pass. The specification does not restrict verification
// by stream status, so a paused or disabled stream reaches the handler, which must refuse or not transmit on a disabled
// stream.
//
// Once the handler has succeeded the event is accepted, so a failure to save the time returns nil rather than an error
// that would make the receiver retry and duplicate the event; the throttle may then not be recorded.
//
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

	if stream, err = storage.GetSSFStream(ctx, clientID, body.StreamID); err != nil {
		return ssfStreamStorageError(err)
	}

	if stream == nil || stream.ClientID != clientID {
		return ssfStreamStorageError(ErrNotFound)
	}

	now := time.Now().UTC()

	if interval := time.Duration(stream.MinVerificationInterval) * time.Second; interval > 0 && !stream.LastVerificationAt.IsZero() && now.Sub(stream.LastVerificationAt) < interval {
		return errorsx.WithStack(ErrSSFVerificationThrottled.WithHintf("A verification event may be requested once every %d seconds.", stream.MinVerificationInterval))
	}

	if err = config.VerificationHandler.HandleSSFVerification(ctx, stream.Clone(), body.State); err != nil {
		return err
	}

	_ = storage.UpdateSSFStreamLastVerification(ctx, clientID, body.StreamID, now)

	return nil
}

// NewSSFVerificationSubject returns the sub_id of a verification event, an opaque identifier holding the stream ID.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.4.1
func NewSSFVerificationSubject(streamID string) (subject *jwt.SubjectIdentifier, err error) {
	return jwt.NewSubjectIdentifierOpaque(streamID)
}
