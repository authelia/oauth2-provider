// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/iox"
	"authelia.com/provider/oauth2/internal/ssfjson"
)

// AuthorizationInvalidator is optionally implemented by an Authorizer which caches the authorization it adds.
type AuthorizationInvalidator interface {
	// InvalidateAuthorization is called when the Transmitter identified by issuer answered a request authorized for
	// the scope with a 401. It discards the cached authorization and returns true when the next AuthorizeRequest
	// obtains a new one, in which case the request is sent once more.
	InvalidateAuthorization(ctx context.Context, issuer, scope string) (invalidated bool)
}

// BearerAuthorizer is an Authorizer which sends the access token the Token function returns as a bearer token. The
// function obtains, caches and renews the token.
//
// See: https://www.rfc-editor.org/rfc/rfc6750#section-2.1
// See: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html#section-2.7.3
type BearerAuthorizer struct {
	// Token returns an access token of the Transmitter identified by issuer which has the scope, which is
	// oauth2.ScopeSSFRead or oauth2.ScopeSSFManage.
	Token func(ctx context.Context, issuer, scope string) (token string, err error)

	// Invalidate is optional and discards the token cached for the issuer and the scope, which the Transmitter
	// refused. When set a request answered with a 401 is sent once more with the token Token returns next.
	Invalidate func(ctx context.Context, issuer, scope string)
}

// AuthorizeRequest implements Authorizer.
func (a *BearerAuthorizer) AuthorizeRequest(ctx context.Context, issuer, scope string, r *http.Request) (err error) {
	if a == nil || a.Token == nil {
		return errors.New("ssfreceiver: the bearer authorizer has no token function")
	}

	var token string

	if token, err = a.Token(ctx, issuer, scope); err != nil {
		return err
	}

	// RFC 6750 Section 2.1: the credentials are a b64token.
	if !isBearerToken(token) {
		return errors.New("ssfreceiver: the access token is not a valid bearer token")
	}

	r.Header.Set(consts.HeaderAuthorization, consts.AuthSchemeBearer+" "+token)

	return nil
}

// InvalidateAuthorization implements AuthorizationInvalidator.
func (a *BearerAuthorizer) InvalidateAuthorization(ctx context.Context, issuer, scope string) (invalidated bool) {
	if a == nil || a.Invalidate == nil {
		return false
	}

	a.Invalidate(ctx, issuer, scope)

	return true
}

// isBearerToken reports whether the token is a b64token.
//
// See: https://www.rfc-editor.org/rfc/rfc6750#section-2.1
func isBearerToken(token string) (ok bool) {
	value := strings.TrimRight(token, "=")

	if value == "" {
		return false
	}

	for i := 0; i < len(value); i++ {
		c := value[i]

		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '.', c == '_', c == '~', c == '+', c == '/':
		default:
			return false
		}
	}

	return true
}

var errNoAuthorizer = errors.New("ssfreceiver: the transmitter request could not be authorized: no authorizer is configured")

// transmitterRequest is a stream management or poll request to a Transmitter.
type transmitterRequest struct {
	method string

	// endpoint is the endpoint URL from the validated Transmitter Configuration Metadata or the stream configuration.
	// An empty one is an endpoint the Transmitter does not have.
	endpoint string

	// scope is oauth2.ScopeSSFRead for a read and oauth2.ScopeSSFManage for a write.
	scope string

	// query is added to the query of the endpoint.
	query url.Values

	// header is added to the request headers, other than the Authorization header.
	header http.Header

	// body is sent as JSON when not nil.
	body any

	// success is the expected status codes. Any 2xx is expected when empty.
	success []int

	// pending makes a 202 an error matching ErrStreamUpdatePending.
	pending bool

	// once sends the request once even when its method is idempotent, as the outcome of an attempt whose response was
	// lost would be hidden by the response to the next one.
	once bool

	// timeout bounds the request. oauth2.FetchTimeout is used when not positive.
	timeout time.Duration
}

// transmitterResponse is a response with an expected status code. The body is not larger than
// Config.MaxResponseBytes.
type transmitterResponse struct {
	status int
	header http.Header
	body   []byte
}

// object returns the members of the JSON object in the body by their exact names. Members that are not understood
// are for the caller to ignore.
func (r *transmitterResponse) object() (members map[string]json.RawMessage, err error) {
	if !isJSONContentType(r.header) {
		return nil, fmt.Errorf("ssfreceiver: the transmitter response is not valid: the content type is not '%s'", consts.MediaTypeApplicationJSON)
	}

	if members, err = ssfjson.ParseObject(r.body); err != nil {
		return nil, fmt.Errorf("ssfreceiver: the transmitter response is not valid: the body is not a JSON object: %w", err)
	}

	return members, nil
}

// transmit sends the request to the Transmitter identified by issuer and returns the response when it has an
// expected status code. The endpoint must be https, the request is authorized by Config.Authorizer for the scope, a
// redirect is not followed, and a response is never sent again except once after a 401 when the Authorizer discarded
// the authorization it cached. A request which failed without a response is sent again as the HTTP client is
// configured to only when its method is idempotent. One timeout covers every attempt and the authorization of each.
// Any other status code is a *TransmitterError, which never has the response body.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1
// See: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html#section-2.7.3
// See: https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.2
func (r *Receiver) transmit(ctx context.Context, issuer string, request transmitterRequest) (response *transmitterResponse, err error) {
	var (
		location string
		body     []byte
	)

	if location, err = transmitterLocation(request.endpoint, request.query); err != nil {
		return nil, err
	}

	if request.scope != oauth2.ScopeSSFRead && request.scope != oauth2.ScopeSSFManage {
		return nil, errors.New("ssfreceiver: the transmitter request has no stream management scope")
	}

	if r.Config.Authorizer == nil {
		return nil, errNoAuthorizer
	}

	if request.body != nil {
		if body, err = json.Marshal(request.body); err != nil {
			return nil, fmt.Errorf("ssfreceiver: the transmitter request could not be encoded: %w", err)
		}
	}

	var client *retryablehttp.Client

	if client, err = r.httpClient(ctx); err != nil {
		return nil, fmt.Errorf("ssfreceiver: the transmitter request could not be sent: %w", err)
	}

	// Every status code is mapped for the caller, which decides whether to send the request again.
	client.CheckRetry = transmitterRetryPolicy(client.CheckRetry, request.method, request.once)

	timeout := request.timeout

	if timeout <= 0 {
		timeout = oauth2.FetchTimeout
	}

	parent := ctx

	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	for attempt := 0; ; attempt++ {
		var unauthorized bool

		if response, unauthorized, err = r.transmitOnce(ctx, client, issuer, location, body, request); !unauthorized {
			return response, transmitTimeout(parent, ctx, err)
		}

		invalidator, ok := r.Config.Authorizer.(AuthorizationInvalidator)

		if !ok || !invalidator.InvalidateAuthorization(ctx, issuer, request.scope) || attempt != 0 {
			return nil, err
		}
	}
}

func (r *Receiver) transmitOnce(ctx context.Context, client *retryablehttp.Client, issuer, location string, body []byte, request transmitterRequest) (response *transmitterResponse, unauthorized bool, err error) {
	var (
		req     *retryablehttp.Request
		payload any
	)

	if body != nil {
		payload = body
	}

	if req, err = retryablehttp.NewRequestWithContext(ctx, request.method, location, payload); err != nil {
		return nil, false, fmt.Errorf("ssfreceiver: the transmitter request could not be sent: %w", err)
	}

	for name, values := range request.header {
		req.Header[http.CanonicalHeaderKey(name)] = slices.Clone(values)
	}

	req.Header.Del(consts.HeaderAuthorization)
	req.Header.Set(consts.HeaderAccept, consts.MediaTypeApplicationJSON)

	if body != nil {
		req.Header.Set(consts.HeaderContentType, consts.MediaTypeApplicationJSON)
	}

	if err = r.Config.Authorizer.AuthorizeRequest(ctx, issuer, request.scope, req.Request); err != nil {
		return nil, false, fmt.Errorf("ssfreceiver: the transmitter request could not be authorized: %w", err)
	}

	var res *http.Response

	sent := time.Now()

	if res, err = client.Do(req); err != nil {
		return nil, false, fmt.Errorf("ssfreceiver: the transmitter request could not be sent: %w", &unconfirmedError{err: err})
	}

	defer res.Body.Close()

	limit := r.maxResponseBytes()

	if err = transmitterStatus(res, request); err != nil {
		var terr *TransmitterError

		if errors.As(err, &terr) {
			terr.held = time.Since(sent)
		}

		// The body of an error is not used, and is read so the connection is reused.
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, limit))

		return nil, res.StatusCode == http.StatusUnauthorized, err
	}

	var (
		data  []byte
		large bool
	)

	if data, large, err = iox.ReadLimited(res.Body, limit); err != nil {
		return nil, false, fmt.Errorf("ssfreceiver: the transmitter response could not be read: %w", &unconfirmedError{err: err, status: res.StatusCode})
	}

	if large {
		return nil, false, fmt.Errorf("ssfreceiver: the transmitter response is not valid: %w", &unconfirmedError{err: fmt.Errorf("the body is larger than %d bytes", limit), status: res.StatusCode})
	}

	return &transmitterResponse{status: res.StatusCode, header: res.Header, body: data}, false, nil
}

// unconfirmedError is the error of a request the Transmitter may have processed: one that may have been sent and
// has no response, or one answered with an expected status code and a body which could not be read.
type unconfirmedError struct {
	err error

	// status is the expected status code of the response, or zero without a response.
	status int
}

// Error implements error.
func (e *unconfirmedError) Error() string {
	return e.err.Error()
}

// Unwrap returns the cause.
func (e *unconfirmedError) Unwrap() error {
	return e.err
}

// Is reports whether the target is ErrTransmitterUnconfirmed.
func (e *unconfirmedError) Is(target error) bool {
	return target == ErrTransmitterUnconfirmed
}

// timeoutError is the error of a request which was sent and which its own timeout ended, while waiting for the
// response or reading it. It is not the error of a timeout of the caller, of the Authorizer or of the HTTP client.
type timeoutError struct {
	err error
}

// Error implements error.
func (e *timeoutError) Error() string {
	return e.err.Error()
}

// Unwrap returns the cause.
func (e *timeoutError) Unwrap() error {
	return e.err
}

// transmitTimeout returns the error as a *timeoutError when it is of a request which was sent and which the timeout
// of its context ended, and not the caller with the parent context.
func transmitTimeout(parent, ctx context.Context, err error) error {
	if isUnconfirmed(err) && errors.Is(ctx.Err(), context.DeadlineExceeded) && parent.Err() == nil {
		return &timeoutError{err: err}
	}

	return err
}

// isUnconfirmed reports whether the Transmitter may have processed the request the error is of.
func isUnconfirmed(err error) (ok bool) {
	var e *unconfirmedError

	return errors.As(err, &e)
}

// isUnreadResponse reports whether the error is of a request the Transmitter answered with an expected status code,
// so it processed the request, and a body which could not be read.
func isUnreadResponse(err error) (ok bool) {
	var e *unconfirmedError

	return errors.As(err, &e) && e.status != 0
}

// transmitterLocation returns the URL of the endpoint with the query added. An endpoint which is not an https URL
// is refused, as is one with user information or a fragment, or with a parameter of the query.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.1
func transmitterLocation(endpoint string, query url.Values) (location string, err error) {
	if endpoint == "" {
		return "", ErrEndpointNotSupported
	}

	u, err := url.Parse(endpoint)

	// The parse error is not wrapped as it has the endpoint, which may have user information.
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "" || strings.Contains(endpoint, "#") {
		return "", ErrEndpointNotHTTPS
	}

	// A parameter in both would select two values, such as two streams. A query which can not be parsed can not be
	// checked.
	if len(query) != 0 {
		var have url.Values

		if have, err = url.ParseQuery(u.RawQuery); err != nil {
			return "", errors.New("ssfreceiver: the query of the endpoint is not valid")
		}

		for name := range query {
			if have.Has(name) {
				return "", fmt.Errorf("ssfreceiver: the endpoint already has the query parameter '%s'", name)
			}
		}
	}

	// The query of the endpoint is kept as the Transmitter wrote it.
	if extra := query.Encode(); extra != "" {
		if u.RawQuery != "" {
			extra = u.RawQuery + "&" + extra
		}

		u.RawQuery = extra
	}

	return u.String(), nil
}

// transmitterStatus returns nil for an expected status code and the *TransmitterError of any other.
func transmitterStatus(response *http.Response, request transmitterRequest) (err error) {
	status := response.StatusCode

	switch {
	case request.pending && status == http.StatusAccepted:
		// SSF Sections 8.1.1.3, 8.1.1.4 and 8.1.2.2: the request was accepted, but not processed.
		return &TransmitterError{Status: status, sentinel: ErrStreamUpdatePending}
	case len(request.success) == 0 && status >= 200 && status <= 299, slices.Contains(request.success, status):
		return nil
	}

	e := &TransmitterError{Status: status, RetryAfter: ssfjson.RetryAfter(response.Header.Get("Retry-After"), time.Now())}

	switch status {
	case http.StatusUnauthorized:
		e.sentinel = ErrTransmitterUnauthorized
	case http.StatusForbidden:
		e.sentinel = ErrTransmitterForbidden
	case http.StatusNotFound:
		e.sentinel = ErrStreamNotFound
	case http.StatusConflict:
		e.sentinel = ErrStreamConflict
	case http.StatusTooManyRequests:
		e.sentinel = ErrTransmitterThrottled
	}

	return e
}

// transmitterRetryPolicy returns the retry policy which never sends a request again once it has a response, and
// never sends a request whose method is not idempotent, or which is to be sent once, again at all, as the Transmitter
// may have processed it.
//
// See: https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.2
func transmitterRetryPolicy(policy retryablehttp.CheckRetry, method string, once bool) retryablehttp.CheckRetry {
	if policy == nil {
		policy = retryablehttp.DefaultRetryPolicy
	}

	return func(ctx context.Context, response *http.Response, err error) (retry bool, rerr error) {
		if err == nil && response != nil {
			return false, nil
		}

		if once || !isIdempotentMethod(method) {
			return false, err
		}

		return policy(ctx, response, err)
	}
}

// isIdempotentMethod reports whether the method is idempotent.
//
// See: https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.2
func isIdempotentMethod(method string) (ok bool) {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace, http.MethodPut, http.MethodDelete:
		return true
	default:
		return false
	}
}

func isJSONContentType(header http.Header) (ok bool) {
	mediaType, _, _ := mime.ParseMediaType(header.Get(consts.HeaderContentType))

	return strings.EqualFold(mediaType, consts.MediaTypeApplicationJSON)
}
