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
// An unknown stream and another client's stream give the same 404. A policy error gives 403, and a stored push endpoint
// the SSFEndpointValidator no longer permits gives 400. A request inside the configured MinVerificationInterval gives
// ErrSSFVerificationThrottled and does not call the handler. The time is recorded before the handler is called, so a
// failed delivery counts towards the interval and a failure to save the time fails the request; concurrent requests may
// both pass. The specification does not restrict verification by stream status, so a paused or disabled stream reaches
// the handler, which must refuse or not transmit on a disabled stream.
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

	client := ar.GetClient()

	if _, err = f.resolveSSFClientPolicy(ctx, config, client); err != nil {
		return err
	}

	if err = f.validateSSFStoredDelivery(ctx, config, client, stream.Delivery); err != nil {
		return err
	}

	stream = config.currentSSFStream(stream)

	now := time.Now().UTC()

	if config.MinVerificationInterval > 0 && !stream.LastVerificationAt.IsZero() && now.Sub(stream.LastVerificationAt) < config.MinVerificationInterval {
		return errorsx.WithStack(ErrSSFVerificationThrottled.WithHintf("A verification event may be requested once every %d seconds.", stream.MinVerificationInterval))
	}

	if err = storage.UpdateSSFStreamLastVerification(ctx, clientID, body.StreamID, now); err != nil {
		return ssfStreamStorageError(err)
	}

	return config.VerificationHandler.HandleSSFVerification(ctx, stream, body.State)
}

// NewSSFVerificationSubject returns the sub_id of a verification event, an opaque identifier holding the stream ID.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.4.1
func NewSSFVerificationSubject(streamID string) (subject *jwt.SubjectIdentifier, err error) {
	return jwt.NewSubjectIdentifierOpaque(streamID)
}
