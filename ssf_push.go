// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

const (
	ssfContentTypeSecurityEventToken = "application/secevent+jwt"

	ssfPushMaxRetryAfter = 5 * time.Minute
)

// SSFPushOutcome is the classification of a single push attempt.
type SSFPushOutcome int

const (
	// SSFPushUnknown is the zero value, which no push attempt reports. A result holding it says nothing about the
	// delivery, so the Security Event Token must not be treated as delivered.
	SSFPushUnknown SSFPushOutcome = iota

	// SSFPushDelivered means the receiver accepted the Security Event Token with a 202.
	SSFPushDelivered

	// SSFPushRejected means the token was not delivered and repeating the request unchanged is not expected to help,
	// so it should not be retransmitted (RFC 8935 Section 2): a 400, a 501, a 505, a 511, any other status that is not
	// retryable, a delivery that is refused without a request, a receiver certificate that fails verification, an
	// error matching ErrSpecialUseAddress, which stays matchable in SSFPushResult.Err, or a disabled stream, which
	// gives an error matching ErrSSFStreamDisabled.
	SSFPushRejected

	// SSFPushRetryable means the failure is potentially recoverable and the attempt may succeed later: a 408, a 425, a
	// 429, any other 5xx, a network error, a timeout, an SSFEndpointValidator error matching ErrTemporarilyUnavailable,
	// or a paused stream, which gives an error matching ErrSSFStreamPaused.
	SSFPushRetryable
)

// String returns the name of the outcome.
func (o SSFPushOutcome) String() string {
	switch o {
	case SSFPushDelivered:
		return "delivered"
	case SSFPushRejected:
		return "rejected"
	case SSFPushRetryable:
		return "retryable"
	default:
		return "unknown"
	}
}

// SSFDelivery is the delivery configuration of a stream, push or poll.
type SSFDelivery struct {
	// Method is the delivery method URI: the RFC 8935 push URI, the RFC 8936 poll URI, or empty for push.
	Method string `json:"method"`

	// EndpointURL is the receiver endpoint of a push stream, which must use https, or the Transmitter poll endpoint.
	EndpointURL string `json:"endpoint_url,omitempty"`

	// AuthorizationHeader is the secret value sent as the Authorization header. It is never included in a result,
	// an error or formatted output.
	AuthorizationHeader string `json:"-"`
}

// Format implements [fmt.Formatter], redacting AuthorizationHeader for every verb.
func (d SSFDelivery) Format(f fmt.State, verb rune) {
	redacted := ""

	if d.AuthorizationHeader != "" {
		redacted = "[redacted]"
	}

	if verb == 'v' && f.Flag('#') {
		_, _ = fmt.Fprintf(f, "oauth2.SSFDelivery{Method:%q, EndpointURL:%q, AuthorizationHeader:%q}", d.Method, d.EndpointURL, redacted)

		return
	}

	_, _ = fmt.Fprintf(f, "{Method:%s EndpointURL:%s AuthorizationHeader:%s}", d.Method, d.EndpointURL, redacted)
}

// SSFPushResult is the outcome of a single push attempt. It never contains the authorization header.
type SSFPushResult struct {
	// Outcome is the classification of the attempt. The zero value is SSFPushUnknown.
	Outcome SSFPushOutcome

	// Status is the HTTP status code, zero when no response was received.
	Status int

	// ErrorCode and Description are the RFC 8935 'err' and 'description' of a 400 response. Both are untrusted remote
	// text.
	ErrorCode, Description string

	// RetryAfter is the receiver's Retry-After on an SSFPushRetryable response, capped at five minutes.
	RetryAfter time.Duration

	Err error
}

// PushSecurityEventToken makes one RFC 8935 push attempt on behalf of the stream's client and reports the outcome. It
// never retries and never follows redirects; queuing and retrying belong to the caller. An endpoint the
// SSFEndpointValidator does not permit for the client is refused without a request, as is any endpoint when no validator
// is configured. The token is sent as it is given and is otherwise opaque, but one that is not a compact serialized JWS
// or JWE, such as an empty string, is refused without a request (RFC 8935 Section 2.1).
//
// A failure is SSFPushRetryable only when it is potentially recoverable, as any other SET should not be retransmitted
// (RFC 8935 Section 2). See SSFPushRejected and SSFPushRetryable for the classification.
//
// The status of the stream is not known to this method, so the caller must not push on a stream that is paused or
// disabled (SSF Section 8.1.2.1). PushSecurityEventTokenToStream makes that check.
//
// See: https://www.rfc-editor.org/rfc/rfc8935.html
// See: https://www.rfc-editor.org/rfc/rfc8935.html#section-2
// See: https://www.rfc-editor.org/rfc/rfc8935.html#section-2.1
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.2.1
func (f *Fosite) PushSecurityEventToken(ctx context.Context, client Client, delivery SSFDelivery, token string) (result SSFPushResult) {
	if hint := ssfPushInputFault(client, delivery, token); hint != "" {
		return ssfPushRefused(hint)
	}

	var (
		config *SSFConfig
		err    error
	)

	if config = f.getSSFConfig(ctx); config == nil {
		return ssfPushRefused("The Shared Signals Framework transmitter is not configured.")
	}

	// An SET and its authorization header are only sent over https.
	if err = validateSSFPushEndpoint(ctx, config, client, delivery.EndpointURL); err != nil {
		if errors.Is(err, ErrTemporarilyUnavailable) {
			return SSFPushResult{Outcome: SSFPushRetryable, Err: err}
		}

		return SSFPushResult{Outcome: SSFPushRejected, Err: err}
	}

	var httpClient *http.Client

	if httpClient, err = f.ssfPushHTTPClient(ctx, config); err != nil {
		return SSFPushResult{Outcome: SSFPushRejected, Err: errorsx.WithStack(ErrServerError.WithWrap(err).WithDebugError(err))}
	}

	ctx, cancel := context.WithTimeout(ctx, FetchTimeout)
	defer cancel()

	var request *http.Request

	if request, err = newSSFPushRequest(ctx, delivery, token); err != nil {
		return ssfPushRefused("Failed to create the push request.")
	}

	var response *http.Response

	if response, err = httpClient.Do(request); response != nil {
		defer response.Body.Close()

		result.Status = response.StatusCode
	}

	if err != nil {
		result.Outcome = ssfPushTransportOutcome(err)
		result.Err = errorsx.WithStack(ErrServerError.WithHint("Failed to perform the push request.").WithWrap(err).WithDebugError(err))

		return result
	}

	// The body is bounded, and only a 400 uses it.
	body, _ := io.ReadAll(io.LimitReader(response.Body, backChannelLogoutResponseBodyLimit))

	switch {
	case response.StatusCode == http.StatusAccepted:
		result.Outcome = SSFPushDelivered
	case response.StatusCode == http.StatusBadRequest:
		result.Outcome = SSFPushRejected
		result.ErrorCode, result.Description = ssfPushParseError(body)
		result.Err = errorsx.WithStack(ErrServerError.WithHintf("The receiver rejected the Security Event Token with status code '%d'.", response.StatusCode))
	case ssfPushStatusRetryable(response.StatusCode):
		result.Outcome = SSFPushRetryable
		result.RetryAfter = ssfPushRetryAfter(response.Header.Get("Retry-After"), time.Now())
		result.Err = errorsx.WithStack(ErrServerError.WithHintf("The receiver responded with status code '%d'.", response.StatusCode))
	default:
		// Any other status is a general HTTP error (RFC 8935 Section 2.3) that waiting does not resolve.
		result.Outcome = SSFPushRejected
		result.Err = errorsx.WithStack(ErrServerError.WithHintf("The receiver responded with status code '%d', expected '202'.", response.StatusCode))
	}

	return result
}

// PushSecurityEventTokenToStream makes one RFC 8935 push attempt on a stream of the client, as PushSecurityEventToken
// does with the stored delivery of the stream, after reading the stream again and checking its status. A token queued
// while the stream was enabled is therefore not sent once the stream is paused or disabled (SSF Section 8.1.2.1).
//
// The eventType is the event type URI of the token, which is not read from the token as it may be encrypted. Nothing
// is sent, and the result has no Status, when:
//
//   - The stream is paused: SSFPushRetryable with an Err matching ErrSSFStreamPaused. The application should hold the
//     token and send it once the stream is enabled. Held events that affect the same subject must be sent in the order
//     they were generated, or only the last of them when it cancels or outdates the earlier ones.
//   - The stream is disabled: SSFPushRejected with an Err matching ErrSSFStreamDisabled. The token is not held.
//   - The stream is unknown or belongs to another client: SSFPushRejected with an Err matching ErrNotFound.
//   - The stream could not be read: SSFPushRetryable.
//
// A verification event is held or refused like any other event. A stream-updated event, which has the event type
// jwt.SecurityEventTypeSSFStreamUpdated, is exempt from the status check, as it is the event that tells the Receiver
// of a stream that is paused or disabled (SSF Section 8.1.5). A poll stream is refused whatever its status, as its
// tokens are returned by the poll endpoint.
//
// The status is the one stored when the stream is read, and the library does not stop it changing before the request
// is sent. The application must coordinate its queue with its status changes so that it sends nothing after one.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.2.1
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.5
func (f *Fosite) PushSecurityEventTokenToStream(ctx context.Context, client Client, streamID, eventType, token string) (result SSFPushResult) {
	if client == nil {
		return ssfPushRefused("The delivery has no client.")
	}

	storage, ok := f.Store.(SSFStreamStorage)
	if !ok {
		return ssfPushRefused("The storage does not implement SSFStreamStorage.")
	}

	stream, err := ownedSSFStream(ctx, storage, client.GetID(), streamID)

	switch {
	case errors.Is(err, ErrNotFound):
		return SSFPushResult{Outcome: SSFPushRejected, Err: errorsx.WithStack(ErrServerError.WithHint("The stream does not exist.").WithWrap(ErrNotFound))}
	case err != nil:
		return SSFPushResult{Outcome: SSFPushRetryable, Err: errorsx.WithStack(ErrServerError.WithHint("Failed to read the stream.").WithWrap(err).WithDebugError(err))}
	}

	// SSF Section 8.1.2.1: events are transmitted by the delivery method of the stream, which for a poll stream is the
	// poll endpoint whatever its status.
	if stream.Delivery.Method != "" && stream.Delivery.Method != SSFDeliveryMethodPush {
		return ssfPushRefused("The delivery method is not the RFC 8935 push method.")
	}

	// SSF Section 8.1.5: the stream updated event reports a status under which nothing else is transmitted.
	if eventType != jwt.SecurityEventTypeSSFStreamUpdated {
		// SSF Section 8.1.2.1: events are transmitted on an enabled stream only.
		switch stream.Status {
		case SSFStreamStatusEnabled:
			break
		case SSFStreamStatusPaused:
			return SSFPushResult{Outcome: SSFPushRetryable, Err: errorsx.WithStack(ErrServerError.WithHint("The stream is paused.").WithWrap(ErrSSFStreamPaused))}
		case SSFStreamStatusDisabled:
			return SSFPushResult{Outcome: SSFPushRejected, Err: errorsx.WithStack(ErrServerError.WithHint("The stream is disabled.").WithWrap(ErrSSFStreamDisabled))}
		default:
			return ssfPushRefused("The stream status is not known.")
		}
	}

	return f.PushSecurityEventToken(ctx, client, stream.Delivery, token)
}

func ssfPushInputFault(client Client, delivery SSFDelivery, token string) (hint string) {
	switch {
	case delivery.Method != "" && delivery.Method != SSFDeliveryMethodPush:
		// The URI of RFC 8935 is the only push method; the poll method is never pushed to.
		return "The delivery method is not the RFC 8935 push method."
	case client == nil:
		return "The delivery has no client."
	case !isSecurityEventTokenCompact(strings.Split(token, ".")):
		// RFC 8935 Section 2.1: the request body is the SET itself, as a JWT.
		return "The Security Event Token is not a compact serialized JWS or JWE."
	case !httpguts.ValidHeaderFieldValue(delivery.AuthorizationHeader):
		return "The delivery authorization header is not a valid header value."
	default:
		return ""
	}
}

func ssfPushStatusRetryable(status int) (retryable bool) {
	switch status {
	case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests:
		return true
	case http.StatusNotImplemented, http.StatusHTTPVersionNotSupported, http.StatusNetworkAuthenticationRequired:
		return false
	default:
		return status >= http.StatusInternalServerError
	}
}

func ssfPushTransportOutcome(err error) (outcome SSFPushOutcome) {
	var (
		verification *tls.CertificateVerificationError
		authority    x509.UnknownAuthorityError
		hostname     x509.HostnameError
		invalid      x509.CertificateInvalidError
	)

	switch {
	case errors.Is(err, ErrSpecialUseAddress):
		return SSFPushRejected
	case errors.As(err, &verification), errors.As(err, &authority), errors.As(err, &hostname), errors.As(err, &invalid):
		return SSFPushRejected
	default:
		return SSFPushRetryable
	}
}

func newSSFPushRequest(ctx context.Context, delivery SSFDelivery, token string) (request *http.Request, err error) {
	if request, err = http.NewRequestWithContext(ctx, http.MethodPost, delivery.EndpointURL, strings.NewReader(token)); err != nil {
		return nil, err
	}

	request.Header.Set(consts.HeaderContentType, ssfContentTypeSecurityEventToken)
	request.Header.Set(consts.HeaderAccept, consts.MediaTypeApplicationJSON)

	if delivery.AuthorizationHeader != "" {
		request.Header.Set(consts.HeaderAuthorization, delivery.AuthorizationHeader)
	}

	return request, nil
}

func (f *Fosite) ssfPushHTTPClient(ctx context.Context, config *SSFConfig) (client *http.Client, err error) {
	base := config.HTTPClient

	if base == nil {
		base = f.Config.GetHTTPClient(ctx)
	}

	if base, err = SpecialUseAddressGuardHTTPClient(ctx, f.Config, base); err != nil {
		return nil, err
	}

	// The caller owns retries and a log hook would see the secret request, so only the inner client is used. It shares
	// its transport with the pushes to every other receiver, which a failed push must not close the idle connections of.
	client = &http.Client{}

	if base != nil && base.HTTPClient != nil {
		copied := *base.HTTPClient
		client = &copied
	}

	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return client, nil
}

func ssfPushRefused(hint string) (result SSFPushResult) {
	return SSFPushResult{Outcome: SSFPushRejected, Err: errorsx.WithStack(ErrServerError.WithHint(hint))}
}

// ssfPushParseError reads the RFC 8935 §2.3 error body, returning empty values when it is not that JSON.
func ssfPushParseError(body []byte) (code, description string) {
	var parsed struct {
		Err         json.RawMessage `json:"err"`
		Description json.RawMessage `json:"description"`
	}

	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", ""
	}

	// RFC 8935 Section 2.3: each member is read on its own, so one of the wrong type does not discard the other.
	_ = json.Unmarshal(parsed.Err, &code)
	_ = json.Unmarshal(parsed.Description, &description)

	return code, description
}

// ssfPushRetryAfter parses a Retry-After delay in seconds or an HTTP date, bounded to five minutes.
func ssfPushRetryAfter(value string, now time.Time) (d time.Duration) {
	value = strings.TrimSpace(value)

	if value == "" {
		return 0
	}

	// RFC 9110 Section 10.2.3: delay-seconds is 1*DIGIT, so it has no sign.
	if !strings.ContainsFunc(value, func(r rune) bool { return r < '0' || r > '9' }) {
		seconds, err := strconv.ParseUint(value, 10, 64)

		// A value out of range is still bounded rather than dropped.
		if err != nil || seconds > uint64(ssfPushMaxRetryAfter/time.Second) {
			return ssfPushMaxRetryAfter
		}

		return time.Duration(seconds) * time.Second
	}

	at, err := http.ParseTime(value)
	if err != nil {
		return 0
	}

	switch d = at.Sub(now); {
	case d <= 0:
		return 0
	case d > ssfPushMaxRetryAfter:
		return ssfPushMaxRetryAfter
	default:
		return d
	}
}
