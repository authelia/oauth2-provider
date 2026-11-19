// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"authelia.com/provider/oauth2"
)

const (
	// DefaultMaxRequestBytes limits the body of a push delivery request when Config.MaxRequestBytes is not positive.
	DefaultMaxRequestBytes = 1 << 20

	mediaTypeSET  = "application/secevent+jwt"
	mediaTypeJSON = "application/json"
)

// The descriptions of a SetError are fixed, and never hold a value of the request.
//
// See: https://www.rfc-editor.org/rfc/rfc8935#section-2.4
var (
	errPushUnauthorized = &SetError{Code: SetErrorAuthenticationFailed, Description: "The request is not authorized to deliver on the stream."}
	errPushContentType  = &SetError{Code: SetErrorInvalidRequest, Description: "The Content-Type of the request is not 'application/secevent+jwt'."}
	errPushBody         = &SetError{Code: SetErrorInvalidRequest, Description: "The body of the request could not be read."}
)

var (
	errPushRecord        = errors.New("ssfreceiver: the push delivery request has no stream record")
	errPushRecordPending = errors.New("ssfreceiver: the stream of the record is pending")
	errPushSecret        = errors.New("ssfreceiver: the Authorization header is not a secret of the stream record")
)

// HandlePush answers a push delivery request of the stream of the record, which the caller looked up from the request
// URL and never from the SET. It always writes the response. The err is for the caller to log, and is not nil when the
// response is a 503, which is the failure that is not a fault of the SET, and when the request is not authorized,
// which is the error of the PushAuthorizer. One matching ErrPushAuthorizerUnavailable is answered with a 503.
//
// See: https://www.rfc-editor.org/rfc/rfc8935#section-2
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-6.1.1
func (r *Receiver) HandlePush(ctx context.Context, rw http.ResponseWriter, request *http.Request, record *StreamRecord) (err error) {
	// RFC 8935 Section 2.1: the SET is delivered with a POST.
	if request.Method != http.MethodPost {
		rw.Header().Set("Allow", http.MethodPost)
		rw.WriteHeader(http.StatusMethodNotAllowed)

		return nil
	}

	if record == nil {
		return writeUnavailable(rw, errPushRecord)
	}

	// RFC 8935 Section 2.3 Figure 4, Section 2.4: a request that is not authorized is an 'authentication_failed'
	// error, and is refused before the body is read. Nothing is authorized to deliver on a stream that is not a push
	// stream, whose Delivery is not of this Receiver.
	if !isPushDelivery(record) {
		writeSetError(rw, errPushUnauthorized)

		return nil
	}

	if err = r.authorizePush(ctx, record, request); err != nil {
		// The authorizer could not decide, so the Transmitter delivers the SET again.
		if errors.Is(err, ErrPushAuthorizerUnavailable) {
			return writeUnavailable(rw, err)
		}

		writeSetError(rw, errPushUnauthorized)

		return err
	}

	// The Transmitter delivers again once the stream is known.
	if record.State == StreamRecordPending {
		return writeUnavailable(rw, errPushRecordPending)
	}

	// RFC 8935 Section 2.1.
	if !isSETContentType(request.Header) {
		writeSetError(rw, errPushContentType)

		return nil
	}

	var token string

	if token, err = r.readPush(rw, request); err != nil {
		if tooLarge := new(http.MaxBytesError); errors.As(err, &tooLarge) {
			rw.WriteHeader(http.StatusRequestEntityTooLarge)
		} else {
			writeSetError(rw, errPushBody)
		}

		return nil
	}

	var (
		event *ReceivedEvent
		serr  *SetError
	)

	if event, serr, err = r.validate(ctx, record, token); err != nil {
		return writeUnavailable(rw, err)
	} else if serr != nil {
		writeSetError(rw, serr)

		return nil
	}

	// RFC 8935 Section 2: a SET received before is answered as if it was not.
	if _, serr, err = r.accept(ctx, event); err != nil {
		return writeUnavailable(rw, err)
	} else if serr != nil {
		writeSetError(rw, serr)

		return nil
	}

	writeAccepted(rw)

	return nil
}

// isPushDelivery returns true when the stream of the record is delivered with the RFC 8935 push method, which is also
// the method of a Delivery without one.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-6.1.1
func isPushDelivery(record *StreamRecord) bool {
	return record.Delivery.Method == "" || record.Delivery.Method == oauth2.SSFDeliveryMethodPush
}

// authorizePush returns an error when the request is not authorized to deliver on the stream of the record.
//
// See: https://www.rfc-editor.org/rfc/rfc8935#section-3
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-6.1.1
func (r *Receiver) authorizePush(ctx context.Context, record *StreamRecord, request *http.Request) (err error) {
	if r.Config.PushAuthorizer != nil {
		return r.Config.PushAuthorizer.AuthorizePush(ctx, record, request)
	}

	// SSF Section 6.1.1: the Transmitter sends the 'authorization_header' of the stream as the Authorization header.
	values := request.Header.Values("Authorization")

	if len(values) != 1 {
		return errPushSecret
	}

	// The digests are compared so the time taken does not depend on the length of a secret.
	have := sha256.Sum256([]byte(values[0]))

	// SSF Sections 8.1.1.3 and 8.1.1.4: while a change of the secret is pending the Transmitter may send either.
	// Both are compared whatever the first comparison gives, and one that is empty authorizes no request.
	authorized := 0

	for _, secret := range []string{record.Delivery.AuthorizationHeader, record.PendingAuthorizationHeader} {
		if secret == "" {
			continue
		}

		expected := sha256.Sum256([]byte(secret))

		authorized |= subtle.ConstantTimeCompare(have[:], expected[:])
	}

	if authorized != 1 {
		return errPushSecret
	}

	return nil
}

// readPush returns the body of the request, or an [http.MaxBytesError] when it is larger than Config.MaxRequestBytes.
func (r *Receiver) readPush(rw http.ResponseWriter, request *http.Request) (token string, err error) {
	limit := r.maxRequestBytes()

	if request.ContentLength > limit {
		return "", &http.MaxBytesError{Limit: limit}
	}

	var body []byte

	if body, err = io.ReadAll(http.MaxBytesReader(rw, request.Body, limit)); err != nil {
		return "", fmt.Errorf("ssfreceiver: the push delivery request body could not be read: %w", err)
	}

	return string(body), nil
}

func (r *Receiver) maxRequestBytes() (limit int64) {
	if r.Config.MaxRequestBytes > 0 {
		return r.Config.MaxRequestBytes
	}

	return DefaultMaxRequestBytes
}

// isSETContentType returns true when the one Content-Type of the request is 'application/secevent+jwt'.
//
// See: https://www.rfc-editor.org/rfc/rfc8935#section-2.1
func isSETContentType(header http.Header) bool {
	values := header.Values("Content-Type")

	if len(values) != 1 {
		return false
	}

	mediaType, _, err := mime.ParseMediaType(values[0])

	return err == nil && strings.EqualFold(mediaType, mediaTypeSET)
}

// writeAccepted writes the response to a SET that is acknowledged.
//
// See: https://www.rfc-editor.org/rfc/rfc8935#section-2.2
func writeAccepted(rw http.ResponseWriter) {
	rw.WriteHeader(http.StatusAccepted)
}

// writeSetError writes the response to a SET that is refused.
//
// See: https://www.rfc-editor.org/rfc/rfc8935#section-2.3
func writeSetError(rw http.ResponseWriter, serr *SetError) {
	data, err := json.Marshal(oauth2.SSFPollSetError{Err: serr.Code, Description: serr.Description})
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)

		return
	}

	rw.Header().Set("Content-Type", mediaTypeJSON)
	rw.Header().Set("Content-Language", "en")
	rw.WriteHeader(http.StatusBadRequest)

	_, _ = rw.Write(data)
}

// writeUnavailable writes the response to a failure that is not a fault of the SET, so the Transmitter delivers the SET
// again, and returns the cause.
//
// See: https://www.rfc-editor.org/rfc/rfc8935#section-2
func writeUnavailable(rw http.ResponseWriter, cause error) (err error) {
	rw.WriteHeader(http.StatusServiceUnavailable)

	return cause
}
