// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

const (
	ssfContentTypeSecurityEventToken = "application/secevent+jwt"
	ssfMediaTypeJSON                 = "application/json"

	ssfPushMaxRetryAfter = 5 * time.Minute
)

// SSFPushOutcome is the classification of a single push attempt.
type SSFPushOutcome int

const (
	// SSFPushDelivered means the receiver accepted the Security Event Token with a 202.
	SSFPushDelivered SSFPushOutcome = iota

	// SSFPushRejected means the receiver will not accept the token as sent, and repeating the request unchanged
	// is not expected to help.
	SSFPushRejected

	// SSFPushRetryable means the attempt may succeed later: a 429, a 5xx, a network error or a timeout.
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

// Format implements fmt.Formatter, redacting AuthorizationHeader for every verb.
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
	Outcome SSFPushOutcome

	// Status is the HTTP status code, zero when no response was received.
	Status int

	// ErrorCode and Description are the RFC 8935 'err' and 'description' of a 400 response. Both are untrusted remote
	// text.
	ErrorCode, Description string

	// RetryAfter is the receiver's Retry-After, capped at five minutes.
	RetryAfter time.Duration

	Err error
}

// PushSecurityEventToken makes one RFC 8935 push attempt and reports the outcome. It never retries and never
// follows redirects; queueing and retrying belong to the caller.
//
// See: https://www.rfc-editor.org/rfc/rfc8935.html
func (f *Fosite) PushSecurityEventToken(ctx context.Context, delivery SSFDelivery, token string) (result SSFPushResult) {
	// The URI of RFC 8935 is the only push method; the poll method is never pushed to.
	if delivery.Method != "" && delivery.Method != SSFDeliveryMethodPush {
		return ssfPushRefused("The delivery method is not the RFC 8935 push method.")
	}

	// An SET and its authorization header are only sent over https.
	var (
		uri *url.URL
		err error
	)

	if uri, err = url.Parse(delivery.EndpointURL); err != nil || uri.Scheme != "https" || uri.Hostname() == "" {
		return ssfPushRefused("The delivery endpoint URL must be an absolute https URL.")
	}

	client := backChannelLogoutHTTPClient(f.Config.GetHTTPClient(ctx))

	// The caller owns retries, and a log hook would see the secret request.
	client.RetryMax = 0
	client.RequestLogHook = nil
	client.ResponseLogHook = nil
	client.CheckRetry = func(context.Context, *http.Response, error) (bool, error) { return false, nil }

	ctx, cancel := context.WithTimeout(ctx, FetchTimeout)
	defer cancel()

	var request *retryablehttp.Request

	if request, err = retryablehttp.NewRequestWithContext(ctx, http.MethodPost, delivery.EndpointURL, strings.NewReader(token)); err != nil {
		return ssfPushRefused("Failed to create the push request.")
	}

	request.Header.Set(consts.HeaderContentType, ssfContentTypeSecurityEventToken)
	request.Header.Set("Accept", ssfMediaTypeJSON)

	if delivery.AuthorizationHeader != "" {
		request.Header.Set(consts.HeaderAuthorization, delivery.AuthorizationHeader)
	}

	var response *http.Response

	if response, err = client.Do(request); response != nil {
		defer response.Body.Close()

		result.Status = response.StatusCode
	}

	if err != nil {
		result.Outcome = SSFPushRetryable
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
	case response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= http.StatusInternalServerError:
		result.Outcome = SSFPushRetryable
		result.RetryAfter = ssfPushRetryAfter(response.Header.Get("Retry-After"), time.Now())
		result.Err = errorsx.WithStack(ErrServerError.WithHintf("The receiver responded with status code '%d'.", response.StatusCode))
	default:
		// RFC 8935 sanctions only 202 (§2.2) and 400 (§2.3).
		result.Outcome = SSFPushRejected
		result.Err = errorsx.WithStack(ErrServerError.WithHintf("The receiver responded with status code '%d', expected '202'.", response.StatusCode))
	}

	return result
}

func ssfPushRefused(hint string) (result SSFPushResult) {
	return SSFPushResult{Outcome: SSFPushRejected, Err: errorsx.WithStack(ErrServerError.WithHint(hint))}
}

// ssfPushParseError reads the RFC 8935 §2.3 error body, returning empty values when it is not that JSON.
func ssfPushParseError(body []byte) (code, description string) {
	var parsed struct {
		Err         string `json:"err"`
		Description string `json:"description"`
	}

	var err error

	if err = json.Unmarshal(body, &parsed); err != nil {
		return "", ""
	}

	return parsed.Err, parsed.Description
}

// ssfPushRetryAfter parses a Retry-After delay in seconds or an HTTP date, bounded to five minutes.
func ssfPushRetryAfter(value string, now time.Time) (d time.Duration) {
	value = strings.TrimSpace(value)

	if value == "" {
		return 0
	}

	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		switch {
		case seconds <= 0:
			return 0
		case seconds > int64(ssfPushMaxRetryAfter/time.Second):
			return ssfPushMaxRetryAfter
		default:
			return time.Duration(seconds) * time.Second
		}
	}

	var (
		at  time.Time
		err error
	)

	if at, err = http.ParseTime(value); err != nil {
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
