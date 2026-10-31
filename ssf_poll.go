// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"authelia.com/provider/oauth2/i18n"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

const ssfPollAllowedMethods = http.MethodPost

// RFC 8935 Section 2.4 Security Event Token Error Codes used by WriteSSFPollError.
const (
	ssfPollErrInvalidRequest       = "invalid_request"
	ssfPollErrAuthenticationFailed = "authentication_failed"
	ssfPollErrAccessDenied         = "access_denied"
)

// SSFPollRequest is a validated and authorized RFC 8936 poll request.
//
// See: https://www.rfc-editor.org/rfc/rfc8936.html#section-2.2
type SSFPollRequest struct {
	// Stream is the poll stream of the requesting client.
	Stream *SSFStream

	// MaxEvents is the 'maxEvents' member, or nil when absent. Zero is an acknowledge-only request. The application must
	// cap it.
	MaxEvents *int

	// ReturnImmediately is the 'returnImmediately' member.
	ReturnImmediately bool

	// Ack holds the 'jti' of the acknowledged SETs. It is unverified receiver input and must be scoped to Stream.
	Ack []string

	// SetErrs holds the errors reported for invalid SETs, keyed by 'jti'. It is unverified receiver input and must be
	// scoped to Stream.
	SetErrs map[string]SSFPollSetError
}

// SSFPollSetError is the error a Receiver reports for a SET.
//
// See: https://www.rfc-editor.org/rfc/rfc8936.html#section-2.6
type SSFPollSetError struct {
	Err         string `json:"err"`
	Description string `json:"description"`
}

type ssfPollRequestBody struct {
	MaxEvents         *int                       `json:"maxEvents"`
	ReturnImmediately bool                       `json:"returnImmediately"`
	Ack               []string                   `json:"ack"`
	SetErrs           map[string]SSFPollSetError `json:"setErrs"`
}

// NewSSFPollRequest authorizes a poll request, which needs 'ssf.manage', and parses its body. The stream ID is the one
// the application took from its route. Only POST is served. An empty body is a default poll request; a body present
// must be 'application/json'.
//
// An unknown stream and another client's stream give the same 404, a policy error gives 403, and a push stream is a
// 400. The stream status is not checked, as SSF Section 8.1.2.1 defines no error for polling, so the application returns
// no SETs on a paused or disabled stream.
//
// See: https://www.rfc-editor.org/rfc/rfc8936.html#section-2.2
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.2.1
func (f *Fosite) NewSSFPollRequest(ctx context.Context, r *http.Request, session Session, streamID string) (request *SSFPollRequest, err error) {
	if r.Method != http.MethodPost {
		return nil, &ssfMethodNotAllowedError{
			error: errorsx.WithStack(ErrInvalidRequest.WithHintf("HTTP method is '%s', expected '%s'.", r.Method, ssfPollAllowedMethods).WithCode(http.StatusMethodNotAllowed)),
			allow: ssfPollAllowedMethods,
		}
	}

	var (
		ar      AccessRequester
		storage SSFStreamStorage
	)

	if ar, storage, err = f.authorizeSSFRequest(ctx, r, session, true); err != nil {
		return nil, err
	}

	clientID := ar.GetClient().GetID()

	var stream *SSFStream

	if stream, err = storage.GetSSFStream(ctx, clientID, streamID); err != nil {
		return nil, ssfStreamStorageError(err)
	}

	if stream == nil || stream.ClientID != clientID {
		return nil, ssfStreamStorageError(ErrNotFound)
	}

	if _, err = f.resolveSSFClientPolicy(ctx, f.getSSFConfig(ctx), ar.GetClient()); err != nil {
		return nil, err
	}

	if stream.Delivery.Method != SSFDeliveryMethodPoll {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The stream does not use the poll delivery method."))
	}

	var data []byte

	if data, err = readSSFRequestBody(f, ctx, r); err != nil {
		return nil, err
	}

	request = &SSFPollRequest{Stream: stream}

	if len(data) == 0 && (r.Header.Get(consts.HeaderContentType) == "" || hasJSONContentType(r)) {
		return request, nil
	}

	if !hasJSONContentType(r) {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The Content-Type header must be 'application/json'."))
	}

	var body *ssfPollRequestBody

	if body, err = parseSSFRequestBody[ssfPollRequestBody](data); err != nil {
		return nil, err
	}

	if body.MaxEvents != nil && *body.MaxEvents < 0 {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The 'maxEvents' member must not be negative."))
	}

	request.MaxEvents = body.MaxEvents
	request.ReturnImmediately = body.ReturnImmediately
	request.Ack = body.Ack
	request.SetErrs = body.SetErrs

	return request, nil
}

// WriteSSFPollResponse writes the poll response with 'Cache-Control: no-store'. The sets are keyed by 'jti'; a nil map
// is written as an empty object, and 'moreAvailable' is omitted when false.
//
// See: https://www.rfc-editor.org/rfc/rfc8936.html#section-2.3
func (f *Fosite) WriteSSFPollResponse(ctx context.Context, rw http.ResponseWriter, sets map[string]string, moreAvailable bool) {
	if sets == nil {
		sets = map[string]string{}
	}

	f.writeSSFResponse(ctx, rw, &SSFStreamResponse{StatusCode: http.StatusOK, Body: struct {
		Sets          map[string]string `json:"sets"`
		MoreAvailable bool              `json:"moreAvailable,omitempty"`
	}{sets, moreAvailable}})
}

// WriteSSFPollError writes a poll endpoint error with 'Cache-Control: no-store'. The body carries the 'err' and
// 'description' members of RFC 8936 Section 2.6. A status of 401 gives 'authentication_failed', 403 'access_denied' and
// every other status 'invalid_request', which is a registered code. A rejected bearer credential is answered with the
// RFC 6750 and RFC 9449 challenge.
//
// See: https://www.rfc-editor.org/rfc/rfc8936.html#section-2.5.1
// See: https://www.rfc-editor.org/rfc/rfc8936.html#section-2.6
func (f *Fosite) WriteSSFPollError(ctx context.Context, rw http.ResponseWriter, r *http.Request, err error) {
	rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)
	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)

	var rfc *RFC6749Error

	if IsBearerCredentialError(err) {
		rfc = f.WriteBearerAuthorizationChallenge(ctx, rw, r, err)
	} else {
		rfc = ErrorToRFC6749Error(err)
	}

	if rfc.CodeField == http.StatusMethodNotAllowed {
		allow := ssfPollAllowedMethods

		var methodErr *ssfMethodNotAllowedError

		if errors.As(err, &methodErr) {
			allow = methodErr.allow
		}

		rw.Header().Set(consts.HeaderAllow, allow)
	}

	catalog := f.Config.GetMessageCatalog(ctx)

	rfc = rfc.WithExposeDebug(f.Config.GetSendDebugMessagesToClients(ctx))

	if r != nil {
		rfc = rfc.WithLocalizer(catalog, i18n.GetLangFromRequest(catalog, r))
	}

	code := ssfPollErrInvalidRequest

	switch rfc.CodeField {
	case http.StatusUnauthorized:
		code = ssfPollErrAuthenticationFailed
	case http.StatusForbidden:
		code = ssfPollErrAccessDenied
	}

	data, merr := json.Marshal(SSFPollSetError{Err: code, Description: rfc.GetDescription()})
	if merr != nil {
		f.writeFallbackJSONError(ctx, rw, merr)

		return
	}

	rw.WriteHeader(rfc.CodeField)
	_, _ = rw.Write(data)
}
