package httpclient

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

func NewClient() *Client {
	return &Client{
		HTTPClient:   NewStandardClient(),
		Logger:       defaultLogger,
		RetryWaitMin: defaultRetryWaitMin,
		RetryWaitMax: defaultRetryWaitMax,
		RetryMax:     defaultRetryMax,
		CheckRetry:   DefaultRetryPolicy,
		Backoff:      DefaultBackoff,
	}
}

func NewStandardClient() *http.Client {
	return &http.Client{Transport: NewTransport()}
}

func FromRequest(r *http.Request) (*Request, error) {
	bodyReader, _, err := getBodyReaderAndContentLength(r.Body)
	if err != nil {
		return nil, err
	}
	// Could assert contentLength == r.ContentLength
	return &Request{body: bodyReader, Request: r}, nil
}

// NewRequest creates a new wrapped request.
func NewRequest(method, url string, rawBody any) (*Request, error) {
	return NewRequestWithContext(context.Background(), method, url, rawBody)
}

// NewRequestWithContext creates a new wrapped request with the provided context.
//
// The context controls the entire lifetime of a request and its response:
// obtaining a connection, sending the request, and reading the response headers and body.
func NewRequestWithContext(ctx context.Context, method, url string, rawBody any) (*Request, error) {
	httpReq, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}

	req := &Request{
		Request: httpReq,
	}
	if err := req.SetBody(rawBody); err != nil {
		return nil, err
	}

	return req, nil
}

type ReaderFunc func() (reader io.Reader, err error)

type ResponseHandlerFunc func(resp *http.Response) (err error)

type LenReader interface {
	Len() int
}

type Request struct {
	body ReaderFunc

	handler ResponseHandlerFunc

	*http.Request
}

func (r *Request) WithContext(ctx context.Context) *Request {
	return &Request{
		body:    r.body,
		handler: r.handler,
		Request: r.Request.WithContext(ctx),
	}
}

func (r *Request) SetResponseHandler(fn ResponseHandlerFunc) {
	r.handler = fn
}

func (r *Request) BodyBytes() (data []byte, err error) {
	if r.body == nil {
		return nil, nil
	}

	body, err := r.body()
	if err != nil {
		return nil, err
	}

	buf := &bytes.Buffer{}

	if _, err = buf.ReadFrom(body); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// SetBody allows setting the request body.
//
// It is useful if a new body needs to be set without constructing a new Request.
func (r *Request) SetBody(raw any) error {
	reader, n, err := getBodyReaderAndContentLength(raw)
	if err != nil {
		return err
	}

	r.body, r.ContentLength = reader, n
	if reader != nil {
		r.GetBody = ReadCloserFromReaderFunc(reader)
	} else {
		r.GetBody = func() (io.ReadCloser, error) { return http.NoBody, nil }
	}

	return nil
}

func (r *Request) WriteTo(w io.Writer) (written int64, err error) {
	body, err := r.body()
	if err != nil {
		return 0, err
	}

	if c, ok := body.(io.Closer); ok {
		defer c.Close()
	}

	return io.Copy(w, body)
}

func ReadCloserFromReaderFunc(reader ReaderFunc) func() (io.ReadCloser, error) {
	return func() (rc io.ReadCloser, err error) {
		var (
			r  io.Reader
			ok bool
		)

		if r, err = reader(); err != nil {
			return nil, err
		}

		if rc, ok = r.(io.ReadCloser); ok {
			return rc, nil
		}

		return io.NopCloser(r), nil
	}
}

// CheckRetry specifies a policy for handling retries. It is called
// following each request with the response and error values returned by
// the http.Client. If CheckRetry returns false, the Client stops retrying
// and returns the response to the caller. If CheckRetry returns an error,
// that error value is returned in lieu of the error from the request. The
// Client will close any response body when retrying, but if the retry is
// aborted it is up to the CheckRetry callback to properly close any
// response body before returning.
type CheckRetry func(ctx context.Context, resp *http.Response, err error) (bool, error)

// Backoff specifies a policy for how long to wait between retries.
// It is called after a failing request to determine the amount of time
// that should pass before trying again.
type Backoff func(min, max time.Duration, attemptNum int, resp *http.Response) time.Duration

// ErrorHandler is called if retries are expired, containing the last status
// from the http library. If not specified, default behavior for the library is
// to close the body and return an error indicating how many tries were
// attempted. If overriding this, be sure to close the body if needed.
type ErrorHandler func(resp *http.Response, err error, numTries int) (*http.Response, error)

// PrepareRetry is called before retry operation. It can be used for example to re-sign the request
type PrepareRetry func(req *http.Request) error

// Client is used to make HTTP requests. It adds additional functionality
// like automatic retries to tolerate minor outages.
type Client struct {
	HTTPClient *http.Client // Internal HTTP client.
	Logger     any          // Customer logger instance. Can be either Logger or LeveledLogger

	RetryWaitMin time.Duration // Minimum time to wait
	RetryWaitMax time.Duration // Maximum time to wait
	RetryMax     int           // Maximum number of retries

	// RequestLogHook allows a user-supplied function to be called
	// before each retry.
	RequestLogHook RequestLogHook

	// ResponseLogHook allows a user-supplied function to be called
	// with the response from each HTTP request executed.
	ResponseLogHook ResponseLogHook

	// CheckRetry specifies the policy for handling retries, and is called
	// after each request. The default policy is DefaultRetryPolicy.
	CheckRetry CheckRetry

	// Backoff specifies the policy for how long to wait between retries
	Backoff Backoff

	// ErrorHandler specifies the custom error handler to use, if any
	ErrorHandler ErrorHandler

	// PrepareRetry can prepare the request for retry operation, for example re-sign it
	PrepareRetry PrepareRetry

	loggerInit sync.Once
	clientInit sync.Once
}

func (c *Client) logger() any {
	c.loggerInit.Do(func() {
		if c.Logger == nil {
			return
		}

		switch c.Logger.(type) {
		case Logger, LeveledLogger:
			// ok
		default:
			// This should happen in dev when they are setting Logger and work on code, not in prod.
			panic(fmt.Sprintf("invalid logger type passed, must be Logger or LeveledLogger, was %T", c.Logger))
		}
	})

	return c.Logger
}

// DefaultRetryPolicy provides a default callback for Client.CheckRetry, which
// will retry on connection errors and server errors.
func DefaultRetryPolicy(ctx context.Context, resp *http.Response, err error) (bool, error) {
	// do not retry on context.Canceled or context.DeadlineExceeded
	if ctx.Err() != nil {
		return false, ctx.Err()
	}

	// don't propagate other errors
	shouldRetry, _ := baseRetryPolicy(resp, err)
	return shouldRetry, nil
}

// ErrorPropagatedRetryPolicy is the same as DefaultRetryPolicy, except it
// propagates errors back instead of returning nil. This allows you to inspect
// why it decided to retry or not.
func ErrorPropagatedRetryPolicy(ctx context.Context, resp *http.Response, err error) (bool, error) {
	// do not retry on context.Canceled or context.DeadlineExceeded
	if ctx.Err() != nil {
		return false, ctx.Err()
	}

	return baseRetryPolicy(resp, err)
}

func baseRetryPolicy(resp *http.Response, err error) (bool, error) {
	if err != nil {
		if v, ok := err.(*url.Error); ok {
			// Don't retry if the error was due to too many redirects.
			if reRedirectsErr.MatchString(v.Error()) {
				return false, v
			}

			// Don't retry if the error was due to an invalid protocol scheme.
			if reSchemeErr.MatchString(v.Error()) {
				return false, v
			}

			// Don't retry if the error was due to an invalid header.
			if reInvalidHeaderError.MatchString(v.Error()) {
				return false, v
			}

			// Don't retry if the error was due to TLS cert verification failure.
			if reNotTrustedErr.MatchString(v.Error()) {
				return false, v
			}
			if isCertError(v.Err) {
				return false, v
			}
		}

		// The error is likely recoverable so retry.
		return true, nil
	}

	// 429 Too Many Requests is recoverable. Sometimes the server puts
	// a Retry-After response header to indicate when the server is
	// available to start processing request from client.
	if resp.StatusCode == http.StatusTooManyRequests {
		return true, nil
	}

	// Check the response code. We retry on 500-range responses to allow
	// the server time to recover, as 500's are typically not permanent
	// errors and may relate to outages on the server side. This will catch
	// invalid response codes as well, like 0 and 999.
	if resp.StatusCode == 0 || (resp.StatusCode >= 500 && resp.StatusCode != http.StatusNotImplemented) {
		return true, fmt.Errorf("unexpected HTTP status %s", resp.Status)
	}

	return false, nil
}

// DefaultBackoff provides a default callback for Client.Backoff which
// will perform exponential backoff based on the attempt number and limited
// by the provided minimum and maximum durations.
//
// It also tries to parse Retry-After response header when a http.StatusTooManyRequests
// (HTTP Code 429) is found in the resp parameter. Hence it will return the number of
// seconds the server states it may be ready to process more requests from this client.
func DefaultBackoff(min, max time.Duration, attemptNum int, resp *http.Response) time.Duration {
	if resp != nil {
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			if sleep, ok := parseRetryAfterHeader(resp.Header["Retry-After"]); ok {
				return sleep
			}
		}
	}

	mult := math.Pow(2, float64(attemptNum)) * float64(min)
	sleep := time.Duration(mult)
	if float64(sleep) != mult || sleep > max {
		sleep = max
	}
	return sleep
}

// parseRetryAfterHeader parses the Retry-After header and returns the
// delay duration according to the spec: https://httpwg.org/specs/rfc7231.html#header.retry-after
// The bool returned will be true if the header was successfully parsed.
// Otherwise, the header was either not present, or was not parseable according to the spec.
//
// Retry-After headers come in two flavors: Seconds or HTTP-Date
//
// Examples:
// * Retry-After: Fri, 31 Dec 1999 23:59:59 GMT
// * Retry-After: 120
func parseRetryAfterHeader(headers []string) (time.Duration, bool) {
	if len(headers) == 0 || headers[0] == "" {
		return 0, false
	}
	header := headers[0]
	// Retry-After: 120
	if sleep, err := strconv.ParseInt(header, 10, 64); err == nil {
		if sleep < 0 { // a negative sleep doesn't make sense
			return 0, false
		}
		return time.Second * time.Duration(sleep), true
	}

	// Retry-After: Fri, 31 Dec 1999 23:59:59 GMT
	retryTime, err := time.Parse(time.RFC1123, header)
	if err != nil {
		return 0, false
	}
	if until := retryTime.Sub(timeNow()); until > 0 {
		return until, true
	}
	// date is in the past
	return 0, true
}

// LinearJitterBackoff provides a callback for Client.Backoff which will
// perform linear backoff based on the attempt number and with jitter to
// prevent a thundering herd.
//
// min and max here are *not* absolute values. The number to be multiplied by
// the attempt number will be chosen at random from between them, thus they are
// bounding the jitter.
//
// For instance:
// * To get strictly linear backoff of one second increasing each retry, set
// both to one second (1s, 2s, 3s, 4s, ...)
// * To get a small amount of jitter centered around one second increasing each
// retry, set to around one second, such as a min of 800ms and max of 1200ms
// (892ms, 2102ms, 2945ms, 4312ms, ...)
// * To get extreme jitter, set to a very wide spread, such as a min of 100ms
// and a max of 20s (15382ms, 292ms, 51321ms, 35234ms, ...)
func LinearJitterBackoff(min, max time.Duration, attemptNum int, resp *http.Response) time.Duration {
	// attemptNum always starts at zero but we want to start at 1 for multiplication
	attemptNum++

	if max <= min {
		// Unclear what to do here, or they are the same, so return min *
		// attemptNum
		return min * time.Duration(attemptNum)
	}

	// Seed rand; doing this every time is fine
	source := rand.New(rand.NewSource(int64(time.Now().Nanosecond())))

	// Pick a random number that lies somewhere between the min and max and
	// multiply by the attemptNum. attemptNum starts at zero so we always
	// increment here. We first get a random percentage, then apply that to the
	// difference between min and max, and add to min.
	jitter := source.Float64() * float64(max-min)
	jitterMin := int64(jitter) + int64(min)
	return time.Duration(jitterMin * int64(attemptNum))
}

// PassthroughErrorHandler is an ErrorHandler that directly passes through the
// values from the net/http library for the final request. The body is not
// closed.
func PassthroughErrorHandler(resp *http.Response, err error, _ int) (*http.Response, error) {
	return resp, err
}

// Do wraps calling an HTTP method with retries.
func (c *Client) Do(req *Request) (*http.Response, error) {
	c.clientInit.Do(func() {
		if c.HTTPClient == nil {
			c.HTTPClient = NewStandardClient()
		}
	})

	logger := c.logger()

	if logger != nil {
		switch v := logger.(type) {
		case LeveledLogger:
			v.Debug("performing request", "method", req.Method, "url", req.URL)
		case Logger:
			v.Printf("[DEBUG] %s %s", req.Method, req.URL)
		}
	}

	var resp *http.Response
	var attempt int
	var shouldRetry bool
	var doErr, respErr, checkErr, prepareErr error

	for i := 0; ; i++ {
		doErr, respErr, prepareErr = nil, nil, nil
		attempt++

		// Always rewind the request body when non-nil.
		if req.body != nil {
			body, err := req.body()
			if err != nil {
				c.HTTPClient.CloseIdleConnections()
				return resp, err
			}
			if c, ok := body.(io.ReadCloser); ok {
				req.Body = c
			} else {
				req.Body = io.NopCloser(body)
			}
		}

		if c.RequestLogHook != nil {
			switch v := logger.(type) {
			case LeveledLogger:
				c.RequestLogHook(hookLogger{v}, req.Request, i)
			case Logger:
				c.RequestLogHook(v, req.Request, i)
			default:
				c.RequestLogHook(nil, req.Request, i)
			}
		}

		// Attempt the request
		resp, doErr = c.HTTPClient.Do(req.Request)

		// Check if we should continue with retries.
		shouldRetry, checkErr = c.CheckRetry(req.Context(), resp, doErr)
		if !shouldRetry && doErr == nil && req.handler != nil {
			respErr = req.handler(resp)
			shouldRetry, checkErr = c.CheckRetry(req.Context(), resp, respErr)
		}

		err := doErr
		if respErr != nil {
			err = respErr
		}
		if err != nil {
			switch v := logger.(type) {
			case LeveledLogger:
				v.Error("request failed", "error", err, "method", req.Method, "url", req.URL)
			case Logger:
				v.Printf("[ERR] %s %s request failed: %v", req.Method, req.URL, err)
			}
		} else {
			// Call this here to maintain the behavior of logging all requests,
			// even if CheckRetry signals to stop.
			if c.ResponseLogHook != nil {
				// Call the response logger function if provided.
				switch v := logger.(type) {
				case LeveledLogger:
					c.ResponseLogHook(hookLogger{v}, resp)
				case Logger:
					c.ResponseLogHook(v, resp)
				default:
					c.ResponseLogHook(nil, resp)
				}
			}
		}

		if !shouldRetry {
			break
		}

		// We do this before drainBody because there's no need for the I/O if
		// we're breaking out
		remain := c.RetryMax - i
		if remain <= 0 {
			break
		}

		// We're going to retry, consume any response to reuse the connection.
		if doErr == nil {
			c.drainBody(resp.Body)
		}

		wait := c.Backoff(c.RetryWaitMin, c.RetryWaitMax, i, resp)
		if logger != nil {
			desc := fmt.Sprintf("%s %s", req.Method, req.URL)
			if resp != nil {
				desc = fmt.Sprintf("%s (status: %d)", desc, resp.StatusCode)
			}
			switch v := logger.(type) {
			case LeveledLogger:
				v.Debug("retrying request", "request", desc, "timeout", wait, "remaining", remain)
			case Logger:
				v.Printf("[DEBUG] %s: retrying in %s (%d left)", desc, wait, remain)
			}
		}
		timer := time.NewTimer(wait)
		select {
		case <-req.Context().Done():
			timer.Stop()
			c.HTTPClient.CloseIdleConnections()
			return nil, req.Context().Err()
		case <-timer.C:
		}

		// Make shallow copy of http Request so that we can modify its body
		// without racing against the closeBody call in persistConn.writeLoop.
		httpreq := *req.Request
		req.Request = &httpreq

		if c.PrepareRetry != nil {
			if err := c.PrepareRetry(req.Request); err != nil {
				prepareErr = err
				break
			}
		}
	}

	// this is the closest we have to success criteria
	if doErr == nil && respErr == nil && checkErr == nil && prepareErr == nil && !shouldRetry {
		return resp, nil
	}

	defer c.HTTPClient.CloseIdleConnections()

	var err error
	if prepareErr != nil {
		err = prepareErr
	} else if checkErr != nil {
		err = checkErr
	} else if respErr != nil {
		err = respErr
	} else {
		err = doErr
	}

	if c.ErrorHandler != nil {
		return c.ErrorHandler(resp, err, attempt)
	}

	// By default, we close the response body and return an error without
	// returning the response
	if resp != nil {
		c.drainBody(resp.Body)
	}

	// this means CheckRetry thought the request was a failure, but didn't
	// communicate why
	if err == nil {
		return nil, fmt.Errorf("%s %s giving up after %d attempt(s)",
			req.Method, req.URL, attempt)
	}

	return nil, fmt.Errorf("%s %s giving up after %d attempt(s): %w",
		req.Method, req.URL, attempt, err)
}

// Try to read the response body so we can reuse this connection.
func (c *Client) drainBody(body io.ReadCloser) {
	defer body.Close()
	_, err := io.Copy(io.Discard, io.LimitReader(body, respReadLimit))
	if err != nil {
		if c.logger() != nil {
			switch v := c.logger().(type) {
			case LeveledLogger:
				v.Error("error reading response body", "error", err)
			case Logger:
				v.Printf("[ERR] error reading response body: %v", err)
			}
		}
	}
}

// Get is a convenience helper for doing simple GET requests.
func (c *Client) Get(url string) (resp *http.Response, err error) {
	req, err := NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	return c.Do(req)
}

// Head is a convenience method for doing simple HEAD requests.
func (c *Client) Head(url string) (resp *http.Response, err error) {
	req, err := NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return nil, err
	}

	return c.Do(req)
}

func (c *Client) Post(url, bodyType string, body any) (resp *http.Response, err error) {
	req, err := NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", bodyType)

	return c.Do(req)
}

func (c *Client) PostForm(url string, data url.Values) (resp *http.Response, err error) {
	return c.Post(url, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
}

func (c *Client) StandardClient() *http.Client {
	return &http.Client{
		Transport: &RoundTripper{Client: c},
	}
}
