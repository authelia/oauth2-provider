package httpclient

import (
	"errors"
	"net/http"
	"net/url"
	"sync"
)

type RoundTripper struct {
	Client *Client

	once sync.Once
}

func (rt *RoundTripper) init() {
	if rt.Client == nil {
		rt.Client = NewClient()
	}
}

// RoundTrip satisfies the http.RoundTripper interface.
func (rt *RoundTripper) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	rt.once.Do(rt.init)

	// Convert the request to be retryable.
	retryableReq, err := FromRequest(req)
	if err != nil {
		return nil, err
	}

	var e *url.Error

	// Execute the request.
	// If we got an error returned by standard library's `Do` method, unwrap it
	// otherwise we will wind up erroneously re-nesting the error.
	if resp, err = rt.Client.Do(retryableReq); errors.As(err, &e) {
		return resp, errors.Unwrap(err)
	}

	return resp, err
}
