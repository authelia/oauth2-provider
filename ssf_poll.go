// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/ssfjson"
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

	// ReturnImmediately is the 'returnImmediately' member, which is false when absent. When it is false and no SET is
	// available, the application SHALL delay its response until one is, or until its timeout elapses (RFC 8936 Section
	// 2.5). The provider does not wait.
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

const (
	ssfPollMemberMaxEvents         = "maxEvents"
	ssfPollMemberReturnImmediately = "returnImmediately"
	ssfPollMemberAck               = "ack"
	ssfPollMemberSetErrs           = "setErrs"
	ssfPollMemberErr               = "err"
	ssfPollMemberDescription       = "description"
)

// NewSSFPollRequest authorizes a poll request, which needs 'ssf.manage', and parses its body. The stream ID is the one
// the application took from its route. Only POST is served. An empty body is a default poll request; a body present
// must be 'application/json'.
//
// An invalid poll request gives 400 (RFC 8936 Section 2.5.1). The body is a single JSON object with no repeated member
// name, and member names are matched exactly. 'maxEvents' is a non-negative integer, 'returnImmediately' a boolean,
// 'ack' an array of non-empty strings, and 'setErrs' an object whose member names are not empty and whose values are
// objects with a non-empty string 'err' and, when present, a string 'description'. A member that is null is absent, and
// an unknown member is ignored. The 'err' values are not compared with the Security Event Token Error Codes registry.
//
// The request is a long poll unless 'returnImmediately' is true: when no SET is available the application SHALL delay
// its response until one is, or until its timeout elapses (RFC 8936 Section 2.5). This method returns at once and the
// waiting is the application's.
//
// An unknown stream and another client's stream give the same 404, a policy error gives 403, and a push stream is a
// 400. The stream status is not checked, as SSF Section 8.1.2.1 defines no error for polling, so the application returns
// no SETs on a paused or disabled stream.
//
// See: https://www.rfc-editor.org/rfc/rfc8936.html#section-2.2
// See: https://www.rfc-editor.org/rfc/rfc8936.html#section-2.5
// See: https://www.rfc-editor.org/rfc/rfc8936.html#section-2.5.1
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

	if stream, err = ownedSSFStream(ctx, storage, clientID, streamID); err != nil {
		return nil, ssfStreamStorageError(err)
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

	request = &SSFPollRequest{Stream: f.currentSSFStream(ctx, f.getSSFConfig(ctx), stream)}

	if len(data) == 0 && (r.Header.Get(consts.HeaderContentType) == "" || hasJSONContentType(r)) {
		return request, nil
	}

	if !hasJSONContentType(r) {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The Content-Type header must be 'application/json'."))
	}

	if err = parseSSFPollRequestBody(data, request); err != nil {
		return nil, err
	}

	return request, nil
}

//nolint:gocyclo
func parseSSFPollRequestBody(data []byte, request *SSFPollRequest) (err error) {
	var members map[string]json.RawMessage

	if members, err = ssfjson.ParseObject(data); err != nil {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("The request body must be a single JSON object with no repeated member names.").WithWrap(err).WithDebugError(err))
	}

	if raw, ok := ssfjson.Member(members, ssfPollMemberMaxEvents); ok {
		var maxEvents int

		if !ssfjson.IsNumber(raw) || json.Unmarshal(raw, &maxEvents) != nil || maxEvents < 0 {
			return errorsx.WithStack(ErrInvalidRequest.WithHint("The 'maxEvents' member must be a non-negative integer."))
		}

		request.MaxEvents = &maxEvents
	}

	if raw, ok := ssfjson.Member(members, ssfPollMemberReturnImmediately); ok {
		switch string(raw) {
		case "true":
			request.ReturnImmediately = true
		case "false":
		default:
			return errorsx.WithStack(ErrInvalidRequest.WithHint("The 'returnImmediately' member must be a boolean."))
		}
	}

	if raw, ok := ssfjson.Member(members, ssfPollMemberAck); ok {
		var values []json.RawMessage

		if json.Unmarshal(raw, &values) != nil {
			return errorsx.WithStack(ErrInvalidRequest.WithHint("The 'ack' member must be an array of non-empty strings."))
		}

		request.Ack = make([]string, 0, len(values))

		for _, value := range values {
			var jti string

			if jti, ok = ssfjson.ParseString(value); !ok || jti == "" {
				return errorsx.WithStack(ErrInvalidRequest.WithHint("The 'ack' member must be an array of non-empty strings."))
			}

			request.Ack = append(request.Ack, jti)
		}
	}

	if raw, ok := ssfjson.Member(members, ssfPollMemberSetErrs); ok {
		if request.SetErrs, err = parseSSFPollSetErrs(raw); err != nil {
			return errorsx.WithStack(ErrInvalidRequest.WithHint("The 'setErrs' member must be an object of objects, each named by a 'jti' and holding a non-empty string 'err' and an optional string 'description'.").WithWrap(err).WithDebugError(err))
		}
	}

	return nil
}

func parseSSFPollSetErrs(data json.RawMessage) (setErrs map[string]SSFPollSetError, err error) {
	var members map[string]json.RawMessage

	if members, err = ssfjson.ParseObject(data); err != nil {
		return nil, err
	}

	setErrs = make(map[string]SSFPollSetError, len(members))

	for jti, raw := range members {
		if jti == "" {
			return nil, errors.New("a member name is empty")
		}

		var fields map[string]json.RawMessage

		if fields, err = ssfjson.ParseObject(raw); err != nil {
			return nil, err
		}

		var (
			setErr SSFPollSetError
			ok     bool
		)

		if setErr.Err, ok = ssfjson.ParseString(fields[ssfPollMemberErr]); !ok || setErr.Err == "" {
			return nil, errors.New("the 'err' member is not a non-empty string")
		}

		if description, present := ssfjson.Member(fields, ssfPollMemberDescription); present {
			if setErr.Description, ok = ssfjson.ParseString(description); !ok {
				return nil, errors.New("the 'description' member is not a string")
			}
		}

		setErrs[jti] = setErr
	}

	return setErrs, nil
}

// WriteSSFPollResponse writes the poll response with 'Cache-Control: no-store'. The sets are keyed by 'jti'; a nil map
// is written as an empty object, and 'moreAvailable' is omitted when false.
//
// It writes at once. For a request whose ReturnImmediately is false, the application calls it with no sets only after
// it has waited for one until its timeout (RFC 8936 Section 2.5).
//
// The sets are not counted, so the application should give no more than the MaxEvents of the request, and none for a
// MaxEvents of zero (RFC 8936 Section 2.2). Sets held while the stream was paused are given under the rule
// Provider.PushSecurityEventTokenToStream describes for held events.
//
// See: https://www.rfc-editor.org/rfc/rfc8936.html#section-2.2
// See: https://www.rfc-editor.org/rfc/rfc8936.html#section-2.3
// See: https://www.rfc-editor.org/rfc/rfc8936.html#section-2.5
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
	rfc := f.prepareSSFError(ctx, rw, r, err, ssfPollAllowedMethods)

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
