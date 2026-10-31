// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"
	"slices"

	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

const ssfStatusAllowedMethods = http.MethodGet + ", " + http.MethodPost

// SSFStreamStatusRequester is a validated and authorized request to the SSF stream status endpoint.
type SSFStreamStatusRequester interface {
	// GetMethod returns the HTTP method of the request.
	GetMethod() (method string)

	// GetClient returns the client that owns the Access Token, which is the stream owner.
	GetClient() (client Client)

	// GetStreamID returns the 'stream_id' query parameter, or empty. It is only read for GET.
	GetStreamID() (id string)

	// GetBody returns the decoded request body. It is nil unless the method is POST.
	GetBody() (body *SSFStreamStatusRequestBody)
}

// SSFStreamStatusRequestBody is the decoded body of a stream status update.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.2.2
type SSFStreamStatusRequestBody struct {
	StreamID string  `json:"stream_id"`
	Status   string  `json:"status"`
	Reason   *string `json:"reason"`
}

// SSFStreamStatus is the stream status resource.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.2.1
type SSFStreamStatus struct {
	StreamID string `json:"stream_id"`
	Status   string `json:"status"`
	Reason   string `json:"reason,omitempty"`
}

// SSFStreamStatusRequest is the default SSFStreamStatusRequester.
type SSFStreamStatusRequest struct {
	Method   string
	Client   Client
	StreamID string
	Body     *SSFStreamStatusRequestBody
}

func (r *SSFStreamStatusRequest) GetMethod() (method string) { return r.Method }
func (r *SSFStreamStatusRequest) GetClient() (client Client) { return r.Client }
func (r *SSFStreamStatusRequest) GetStreamID() (id string)   { return r.StreamID }
func (r *SSFStreamStatusRequest) GetBody() (body *SSFStreamStatusRequestBody) {
	return r.Body
}

// NewSSFStreamStatusRequest authorizes the request and decodes its body. Only GET and POST are served; a read needs
// 'ssf.read' and an update 'ssf.manage'.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.2
func (f *Fosite) NewSSFStreamStatusRequest(ctx context.Context, r *http.Request, session Session) (requester SSFStreamStatusRequester, err error) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		return nil, &ssfMethodNotAllowedError{
			error: errorsx.WithStack(ErrInvalidRequest.WithHintf("HTTP method is '%s', expected one of '%s'.", r.Method, ssfStatusAllowedMethods).WithCode(http.StatusMethodNotAllowed)),
			allow: ssfStatusAllowedMethods,
		}
	}

	var ar AccessRequester

	if ar, _, err = f.authorizeSSFRequest(ctx, r, session, r.Method == http.MethodPost); err != nil {
		return nil, err
	}

	request := &SSFStreamStatusRequest{Method: r.Method, Client: ar.GetClient()}

	if r.Method == http.MethodGet {
		request.StreamID = r.URL.Query().Get(ssfStreamQueryStreamID)

		return request, nil
	}

	if request.Body, err = decodeSSFRequestBody[SSFStreamStatusRequestBody](f, ctx, r); err != nil {
		return nil, err
	}

	return request, nil
}

// NewSSFStreamStatusResponse reads or updates the status of a stream of the requesting client. An unknown stream and
// another client's stream give the same 404. A status change does not touch the other stream properties, and an omitted
// reason clears the stored one. An update resolves the stream policy, and a policy error gives 403.
//
// An application refusing a re-enable, for example of an operator-disabled stream, inspects the requester before
// calling this.
//
// The application must send a stream-updated event (NewSSFStreamUpdatedEvent) before a Transmitter-initiated stop of
// a stream, as it does not follow from a status change made here.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.2
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.5
func (f *Fosite) NewSSFStreamStatusResponse(ctx context.Context, requester SSFStreamStatusRequester) (responder SSFStreamResponder, err error) {
	var (
		config  *SSFConfig
		storage SSFStreamStorage
		ok      bool
	)

	if config = f.getSSFConfig(ctx); config == nil {
		return nil, errorsx.WithStack(ErrServerError.WithDebug("The Shared Signals Framework transmitter is not configured."))
	}

	if storage, ok = f.Store.(SSFStreamStorage); !ok {
		return nil, errorsx.WithStack(ErrServerError.WithDebug("The storage does not implement SSFStreamStorage."))
	}

	clientID := requester.GetClient().GetID()

	var streamID string

	switch requester.GetMethod() {
	case http.MethodGet:
		streamID = requester.GetStreamID()
	case http.MethodPost:
		body := requester.GetBody()

		if body == nil {
			body = &SSFStreamStatusRequestBody{}
		}

		streamID = body.StreamID

		if streamID == "" {
			return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The 'stream_id' is required in the request body."))
		}

		if !slices.Contains([]string{SSFStreamStatusEnabled, SSFStreamStatusPaused, SSFStreamStatusDisabled}, body.Status) {
			return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The 'status' must be one of 'enabled', 'paused' or 'disabled'."))
		}
	default:
		return nil, &ssfMethodNotAllowedError{
			error: errorsx.WithStack(ErrInvalidRequest.WithHintf("HTTP method is '%s', expected one of '%s'.", requester.GetMethod(), ssfStatusAllowedMethods).WithCode(http.StatusMethodNotAllowed)),
			allow: ssfStatusAllowedMethods,
		}
	}

	if streamID == "" {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The 'stream_id' query parameter is required."))
	}

	var stream *SSFStream

	if stream, err = storage.GetSSFStream(ctx, clientID, streamID); err != nil {
		return nil, ssfStreamStorageError(err)
	}

	if stream == nil || stream.ClientID != clientID {
		return nil, ssfStreamStorageError(ErrNotFound)
	}

	if requester.GetMethod() == http.MethodPost {
		if _, err = f.resolveSSFClientPolicy(ctx, config, requester.GetClient()); err != nil {
			return nil, err
		}

		body := requester.GetBody()

		stream = stream.Clone()
		stream.Status = body.Status
		stream.StatusReason = ptrString(body.Reason)

		if err = storage.UpdateSSFStreamStatus(ctx, clientID, streamID, stream.Status, stream.StatusReason); err != nil {
			return nil, ssfStreamStorageError(err)
		}
	}

	return &SSFStreamResponse{StatusCode: http.StatusOK, Body: &SSFStreamStatus{StreamID: stream.StreamID, Status: stream.Status, Reason: stream.StatusReason}}, nil
}

// WriteSSFStreamStatusResponse writes the stream status response with 'Cache-Control: no-store'.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.2.1
func (f *Fosite) WriteSSFStreamStatusResponse(ctx context.Context, rw http.ResponseWriter, requester SSFStreamStatusRequester, responder SSFStreamResponder) {
	f.writeSSFResponse(ctx, rw, responder)
}

// NewSSFStreamUpdatedEvent returns the stream-updated event for a status change, with 'reason' omitted when empty. Send
// it before a Transmitter-initiated stop of a stream and upon re-enabling it.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.5
func NewSSFStreamUpdatedEvent(status, reason string) (event *jwt.SSFStreamUpdated) {
	return &jwt.SSFStreamUpdated{Status: status, Reason: reason}
}
