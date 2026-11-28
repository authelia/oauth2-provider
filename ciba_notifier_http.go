// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-retryablehttp"

	"authelia.com/provider/oauth2/internal/reflection"
)

// HTTPBackChannelNotifier is a BackChannelNotifier which POSTs the notification to the client. It never follows a
// redirect and treats a 3xx response as a failure. It must not be copied after first use.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.2
type HTTPBackChannelNotifier struct {
	// Client is the HTTP client used for delivery.
	Client *http.Client

	// Config, when Client is nil, is read for each delivery for the special-use address guard settings of
	// SpecialUseAddressGuardProvider, which apply as at every other location a client supplies. The notification
	// endpoint of a client resolved from a Client ID Metadata Document is always guarded without exception; when the
	// notification carries no Client, its ClientID decides. When Config is nil the guard applies without exception to
	// every client.
	Config any

	once sync.Once
	base *retryablehttp.Client
}

// NewHTTPBackChannelNotifier returns an HTTPBackChannelNotifier. When client is nil the notifier uses the guarded
// client of NewSpecialUseAddressGuardedHTTPClient with TLS 1.2 as the minimum version and only the TLS 1.2 cipher
// suites BCP 195 recommends, which refuses special-use addresses. A supplied client is used as is, except that it
// never follows redirects.
//
// See: https://www.rfc-editor.org/rfc/rfc9325#section-4.2
// See: https://openid.net/specs/fapi-ciba.html#section-5.9
func NewHTTPBackChannelNotifier(client *http.Client) (notifier *HTTPBackChannelNotifier) {
	if client == nil {
		client = newGuardedBackChannelHTTPClient()
	}

	return &HTTPBackChannelNotifier{Client: client}
}

func (n *HTTPBackChannelNotifier) deliveryClient(ctx context.Context, notification *BackChannelNotification) (client *http.Client, err error) {
	if n.Client != nil {
		return n.Client, nil
	}

	n.once.Do(func() {
		if n.base == nil {
			n.base = newBackChannelBaseHTTPClient()
		}
	})

	var hc *retryablehttp.Client

	if reflection.IsNil(n.Config) || isClientIDMetadataDocumentFetchClient(ctx, n.Config, backChannelNotificationClient(notification)) {
		hc, err = guardedHTTPClient(n.base, nil)
	} else {
		hc, err = SpecialUseAddressGuardHTTPClient(ctx, n.Config, n.base)
	}

	if err != nil {
		return nil, err
	}

	return hc.HTTPClient, nil
}

func backChannelNotificationClient(notification *BackChannelNotification) (client any) {
	if !reflection.IsNil(notification.Client) {
		return notification.Client
	}

	return &DefaultClient{ID: notification.ClientID}
}

func newBackChannelBaseHTTPClient() (client *retryablehttp.Client) {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	return &retryablehttp.Client{
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				DialContext:           dialer.DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          16,
				MaxConnsPerHost:       4,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   5 * time.Second,
				ResponseHeaderTimeout: 5 * time.Second,
				TLSClientConfig:       newBackChannelTLSConfig(),
			},
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		RetryMax:     0,
		CheckRetry:   noRetrySpecialUseAddress(retryablehttp.DefaultRetryPolicy),
		Backoff:      retryablehttp.DefaultBackoff,
		ErrorHandler: retryablehttp.PassthroughErrorHandler,
	}
}

func newBackChannelTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}
}

func newGuardedBackChannelHTTPClient() (client *http.Client) {
	client = NewSpecialUseAddressGuardedHTTPClient().HTTPClient

	if transport, ok := client.Transport.(*http.Transport); ok {
		transport.TLSClientConfig = newBackChannelTLSConfig()
	}

	return client
}

// NotifyBackChannelClient implements BackChannelNotifier. The endpoint must be https; 200 and 204 are success, the
// body of the response is ignored, and any other status is an error.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.2
func (n *HTTPBackChannelNotifier) NotifyBackChannelClient(ctx context.Context, notification *BackChannelNotification) (err error) {
	if notification == nil {
		return errors.New("the notification is nil")
	}

	if u, perr := url.Parse(notification.Endpoint); perr != nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" {
		return fmt.Errorf("the notification endpoint must be an https URL")
	}

	var req *http.Request

	if req, err = http.NewRequestWithContext(ctx, http.MethodPost, notification.Endpoint, bytes.NewReader(notification.Body)); err != nil {
		return fmt.Errorf("could not create the notification request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+notification.BearerToken)

	var base *http.Client

	if base, err = n.deliveryClient(ctx, notification); err != nil {
		return fmt.Errorf("could not deliver the notification: %w", err)
	}

	client := *base

	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	var resp *http.Response

	if resp, err = client.Do(req); err != nil {
		return fmt.Errorf("could not deliver the notification: %w", err)
	}

	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	switch {
	case resp.StatusCode == http.StatusOK, resp.StatusCode == http.StatusNoContent:
		return nil
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return fmt.Errorf("the notification endpoint responded with the redirect status %d, which is not followed", resp.StatusCode)
	default:
		return fmt.Errorf("the notification endpoint responded with the status %d", resp.StatusCode)
	}
}
