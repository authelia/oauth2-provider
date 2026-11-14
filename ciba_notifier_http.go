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
	"net/http"
	"net/url"
	"strings"
)

// HTTPBackChannelNotifier is a BackChannelNotifier which POSTs the notification to the client. It never follows a
// redirect and treats a 3xx response as a failure.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.2
type HTTPBackChannelNotifier struct {
	// Client is the HTTP client used for delivery.
	Client *http.Client
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

func newGuardedBackChannelHTTPClient() (client *http.Client) {
	client = NewSpecialUseAddressGuardedHTTPClient().HTTPClient

	if transport, ok := client.Transport.(*http.Transport); ok {
		transport.TLSClientConfig = &tls.Config{
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

	base := n.Client

	if base == nil {
		base = newGuardedBackChannelHTTPClient()
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
