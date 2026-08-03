// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/hashicorp/go-retryablehttp"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// backChannelLogoutResponseBodyLimit bounds how much of a Relying Party's response body is drained. The body is
// discarded, but draining it lets the connection be reused.
const backChannelLogoutResponseBodyLimit = 1 << 16

// SendBackChannelLogout delivers a Logout Token to each of the supplied clients, as per OpenID Connect
// Back-Channel Logout 1.0.
//
// The caller supplies the clients: this library does not track which clients participated in a session, and
// does not end any session. A result is returned for every client supplied, in the order supplied.
//
// Delivery is best effort. A Relying Party that is unreachable or that rejects the Logout Token is reported in
// its own result and never fails the call, so one broken Relying Party cannot prevent the others being
// notified. Only whole-operation failures are returned as err.
//
// Deliveries run concurrently, up to the configured concurrency limit. Each supplied Client and the requester's
// Extra map are read concurrently from the delivery goroutines, and so must be safe for concurrent reads.
//
// See: https://openid.net/specs/openid-connect-backchannel-1_0.html
func (f *Fosite) SendBackChannelLogout(ctx context.Context, requester BackChannelLogoutRequester) (results []BackChannelLogoutResult, err error) {
	subject, sid := requester.GetSubject(), requester.GetSessionID()

	// A Logout Token MUST contain either a 'sub' or a 'sid' claim, and MAY contain both.
	if subject == "" && sid == "" {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("A Logout Token must contain either the 'sub' or the 'sid' claim."))
	}

	clients := requester.GetClients()

	// A session in which no client participates is an ordinary outcome, not an error.
	if len(clients) == 0 {
		return []BackChannelLogoutResult{}, nil
	}

	strategy := f.Config.GetBackChannelLogoutTokenStrategy(ctx)

	if strategy == nil {
		return nil, errorsx.WithStack(ErrServerError.WithDebug("Failed to send the Back-Channel Logout requests because the Back-Channel Logout token strategy is not configured."))
	}

	extra := requester.GetExtra()

	concurrency := f.Config.GetBackChannelLogoutConcurrency(ctx)

	if concurrency <= 0 {
		concurrency = 1
	}

	results = make([]BackChannelLogoutResult, len(clients))

	// Constructed once, outside the delivery loop, so every delivery shares a single underlying transport and
	// connection pool. Constructing it per delivery (as GetHTTPClient's default of a nil Config.HTTPClient
	// would otherwise force) would hand each Relying Party a brand-new retryablehttp client with no connection
	// reuse at all.
	client := backChannelLogoutHTTPClient(f.Config.GetHTTPClient(ctx))

	var wg sync.WaitGroup

	sem := make(chan struct{}, concurrency)

	for i, c := range clients {
		wg.Add(1)

		go func() {
			defer wg.Done()

			sem <- struct{}{}

			defer func() { <-sem }()

			// Each goroutine writes its own index, so no synchronisation of results is required and the order
			// always matches the order the clients were supplied in.
			results[i] = f.sendBackChannelLogout(ctx, strategy, client, c, subject, sid, extra)
		}()
	}

	wg.Wait()

	return results, nil
}

// sendBackChannelLogout generates and delivers a single Logout Token, reporting every failure in the result
// rather than returning it.
func (f *Fosite) sendBackChannelLogout(ctx context.Context, strategy BackChannelLogoutTokenStrategy, httpClient *retryablehttp.Client, client Client, subject, sid string, extra map[string]any) (result BackChannelLogoutResult) {
	result.ClientID = client.GetID()

	uri, reason := backChannelLogoutURI(client, sid)

	if reason != "" {
		result.Skipped, result.Reason = true, reason

		return result
	}

	var (
		token string
		err   error
	)

	// The audience names only this client, so each Relying Party receives a token with its own 'jti'.
	if token, err = strategy.GenerateBackChannelLogoutToken(ctx, client, f.Config.GetBackChannelLogoutLifespan(ctx), subject, sid, []string{client.GetID()}, extra); err != nil {
		result.Err = errorsx.WithStack(ErrServerError.WithHint("Failed to generate the Logout Token.").WithWrap(err).WithDebugError(err))

		return result
	}

	result.Status, result.Err = postBackChannelLogout(ctx, httpClient, uri, token)

	return result
}

// postBackChannelLogout performs the form encoded POST to a Relying Party's back-channel logout URI.
func postBackChannelLogout(ctx context.Context, client *retryablehttp.Client, uri, token string) (status int, err error) {
	body := url.Values{consts.FormParameterLogoutToken: []string{token}}

	var request *retryablehttp.Request

	if request, err = retryablehttp.NewRequestWithContext(ctx, http.MethodPost, uri, strings.NewReader(body.Encode())); err != nil {
		return 0, errorsx.WithStack(ErrServerError.WithHint("Failed to create the Back-Channel Logout request.").WithWrap(err).WithDebugError(err))
	}

	request.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)

	var response *http.Response

	if response, err = client.Do(request); err != nil {
		return 0, errorsx.WithStack(ErrServerError.WithHint("Failed to perform the Back-Channel Logout request.").WithWrap(err).WithDebugError(err))
	}

	defer response.Body.Close()

	// Drain a bounded amount of the body so the connection can be reused; the content is not used.
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, backChannelLogoutResponseBodyLimit))

	// The specification requires 200 on success and 400 on failure, and warns that some frameworks substitute
	// 204 for 200 when the body is empty. Nothing else is sanctioned, so nothing else is treated as success.
	switch response.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		return response.StatusCode, nil
	default:
		return response.StatusCode, errorsx.WithStack(ErrServerError.WithHintf("The Relying Party responded with status code '%d', expected '200' or '204'.", response.StatusCode))
	}
}

// backChannelLogoutHTTPClient returns a client configured like base, except that it always returns the final
// response and error rather than discarding the response once retries are exhausted, and never follows
// redirects.
//
// The default ErrorHandler closes the body and synthesizes a generic "giving up" error once retries run out,
// even when a response was received (for example a Relying Party's default retry policy treats a 500 response
// as retryable, but discards the 500 response itself when no more retries remain). Back-Channel Logout results
// report the Relying Party's actual status code, so the response must be preserved. A fresh value is
// constructed rather than mutating base's ErrorHandler, because base is shared across concurrent deliveries and
// across calls to SendBackChannelLogout.
//
// The wrapped *http.Client is likewise a copy of base.HTTPClient, never base.HTTPClient itself, with
// CheckRedirect overridden so that a 3xx response is returned as-is instead of being followed: a registered
// Relying Party could otherwise use a 307 or 308 (which Go's client replays with the same method and body) to
// forward the signed Logout Token to a host that never registered to receive it. Copying rather than mutating
// base.HTTPClient in place means the integrator's own *http.Client, which may be shared and used elsewhere, is
// never touched.
func backChannelLogoutHTTPClient(base *retryablehttp.Client) (client *retryablehttp.Client) {
	httpClient := &http.Client{}

	if base.HTTPClient != nil {
		copied := *base.HTTPClient
		httpClient = &copied
	}

	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return &retryablehttp.Client{
		HTTPClient:      httpClient,
		Logger:          base.Logger,
		RetryWaitMin:    base.RetryWaitMin,
		RetryWaitMax:    base.RetryWaitMax,
		RetryMax:        base.RetryMax,
		RequestLogHook:  base.RequestLogHook,
		ResponseLogHook: base.ResponseLogHook,
		CheckRetry:      base.CheckRetry,
		Backoff:         base.Backoff,
		PrepareRetry:    base.PrepareRetry,
		ErrorHandler:    retryablehttp.PassthroughErrorHandler,
	}
}
