// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
)

func newCIBANotifierTestRequest(id, token string) *oauth2.BackChannelAuthenticationRequest {
	request := oauth2.NewBackChannelAuthenticationRequest()
	request.SetID(id)
	request.ClientNotificationToken = token

	return request
}

func TestHTTPNotifierPostsPing(t *testing.T) {
	var (
		method, auth, contentType, body string
	)

	server := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		method, auth, contentType = r.Method, r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		data, _ := io.ReadAll(r.Body)
		body = string(data)

		rw.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := &oauth2.DefaultCIBAClient{DefaultClient: &oauth2.DefaultClient{ID: "c"}, BackChannelTokenDeliveryMode: "ping", BackChannelClientNotificationEndpoint: server.URL}

	notification, err := oauth2.NewBackChannelPingNotification(client, newCIBANotifierTestRequest("r1", "tok"), "x")
	require.NoError(t, err)
	assert.Equal(t, "ping", notification.Mode)
	assert.Equal(t, "c", notification.ClientID)
	assert.Equal(t, "r1", notification.RequestID)

	require.NoError(t, oauth2.NewHTTPBackChannelNotifier(server.Client()).NotifyBackChannelClient(context.Background(), notification))

	assert.Equal(t, http.MethodPost, method)
	assert.Equal(t, "Bearer tok", auth)
	assert.Equal(t, "application/json", contentType)
	assert.JSONEq(t, `{"auth_req_id":"x"}`, body)
}

func TestHTTPNotifierAccepts200And204(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusNoContent} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			rw.WriteHeader(status)
		}))

		err := oauth2.NewHTTPBackChannelNotifier(server.Client()).NotifyBackChannelClient(context.Background(), &oauth2.BackChannelNotification{Endpoint: server.URL, BearerToken: "t", Body: json.RawMessage(`{}`)})
		assert.NoError(t, err, status)

		server.Close()
	}
}

func TestHTTPNotifierRejectsOtherStatuses(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(http.StatusTeapot)
	}))
	defer server.Close()

	err := oauth2.NewHTTPBackChannelNotifier(server.Client()).NotifyBackChannelClient(context.Background(), &oauth2.BackChannelNotification{Endpoint: server.URL, BearerToken: "t", Body: json.RawMessage(`{}`)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "418")
}

func TestHTTPNotifierRefusesRedirect(t *testing.T) {
	var hits atomic.Int32

	target := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer target.Close()

	server := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		http.Redirect(rw, r, target.URL, http.StatusFound)
	}))
	defer server.Close()

	err := oauth2.NewHTTPBackChannelNotifier(server.Client()).NotifyBackChannelClient(context.Background(), &oauth2.BackChannelNotification{Endpoint: server.URL, BearerToken: "t", Body: json.RawMessage(`{}`)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "302")
	assert.Equal(t, int32(0), hits.Load())
}

func TestHTTPNotifierRefusesSpecialUseAddress(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	err := oauth2.NewHTTPBackChannelNotifier(nil).NotifyBackChannelClient(context.Background(), &oauth2.BackChannelNotification{Endpoint: server.URL, BearerToken: "t", Body: json.RawMessage(`{}`)})
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrSpecialUseAddress)
}

func TestHTTPNotifierRejectsHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		t.Error("the notifier must not contact an http endpoint")
	}))
	defer server.Close()

	err := oauth2.NewHTTPBackChannelNotifier(server.Client()).NotifyBackChannelClient(context.Background(), &oauth2.BackChannelNotification{Endpoint: server.URL, BearerToken: "t", Body: json.RawMessage(`{}`)})
	require.Error(t, err)
}

func TestPushErrorNotificationBody(t *testing.T) {
	client := &oauth2.DefaultCIBAClient{DefaultClient: &oauth2.DefaultClient{ID: "c"}, BackChannelTokenDeliveryMode: "push", BackChannelClientNotificationEndpoint: "https://client.example.com/cb"}

	notification, err := oauth2.NewBackChannelPushErrorNotification(client, newCIBANotifierTestRequest("r1", "tok"), "x", oauth2.ErrAccessDenied.WithHint(`said "no"`))
	require.NoError(t, err)
	assert.Equal(t, "push", notification.Mode)

	members := map[string]string{}
	require.NoError(t, json.Unmarshal(notification.Body, &members))

	assert.Equal(t, "x", members["auth_req_id"])
	assert.Equal(t, "access_denied", members["error"])
	assert.NotContains(t, members["error_description"], `"`)
	assert.True(t, strings.Contains(members["error_description"], "no"))

	notification, err = oauth2.NewBackChannelPushErrorNotification(client, newCIBANotifierTestRequest("r1", "tok"), "x", &oauth2.RFC6749Error{ErrorField: "transaction_failed"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"auth_req_id":"x","error":"transaction_failed"}`, string(notification.Body))
}

func TestBackChannelNotificationBuildersRequireEndpointAndToken(t *testing.T) {
	good := &oauth2.DefaultCIBAClient{DefaultClient: &oauth2.DefaultClient{ID: "c"}, BackChannelClientNotificationEndpoint: "https://client.example.com/cb"}
	noEndpoint := &oauth2.DefaultCIBAClient{DefaultClient: &oauth2.DefaultClient{ID: "c"}}

	_, err := oauth2.NewBackChannelPingNotification(noEndpoint, newCIBANotifierTestRequest("r", "tok"), "x")
	assert.Error(t, err)

	_, err = oauth2.NewBackChannelPingNotification(good, newCIBANotifierTestRequest("r", ""), "x")
	assert.Error(t, err)

	_, err = oauth2.NewBackChannelPingNotification(good, newCIBANotifierTestRequest("r", "tok"), "")
	assert.Error(t, err)

	_, err = oauth2.NewBackChannelPushErrorNotification(noEndpoint, newCIBANotifierTestRequest("r", "tok"), "x", oauth2.ErrAccessDenied)
	assert.Error(t, err)

	_, err = oauth2.NewBackChannelPushErrorNotification(good, newCIBANotifierTestRequest("r", ""), "x", oauth2.ErrAccessDenied)
	assert.Error(t, err)

	_, err = oauth2.NewBackChannelPushErrorNotification(good, newCIBANotifierTestRequest("r", "tok"), "x", nil)
	assert.Error(t, err)
}

func TestBackChannelNotificationBuildersRequireAnHTTPSEndpoint(t *testing.T) {
	testCases := []struct {
		name     string
		endpoint string
	}{
		{"ShouldRejectHTTP", "http://client.example.com/cb"},
		{"ShouldRejectARelativeURL", "/cb"},
		{"ShouldRejectAnHTTPSURLWithoutAHost", "https:///cb"},
		{"ShouldRejectAnUnparseableURL", "https://client.example.com/%zz"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := &oauth2.DefaultCIBAClient{DefaultClient: &oauth2.DefaultClient{ID: "c"}, BackChannelClientNotificationEndpoint: tc.endpoint}

			_, err := oauth2.NewBackChannelPingNotification(client, newCIBANotifierTestRequest("r", "tok"), "x")
			assert.EqualError(t, err, "the client backchannel_client_notification_endpoint is not an absolute https URL")

			_, err = oauth2.NewBackChannelPushErrorNotification(client, newCIBANotifierTestRequest("r", "tok"), "x", oauth2.ErrAccessDenied)
			assert.EqualError(t, err, "the client backchannel_client_notification_endpoint is not an absolute https URL")
		})
	}
}

func TestConfigGetBackChannelNotifier(t *testing.T) {
	config := &oauth2.Config{}
	ctx := context.Background()

	def := config.GetBackChannelNotifier(ctx)
	require.NotNil(t, def)
	assert.IsType(t, &oauth2.HTTPBackChannelNotifier{}, def)
	assert.Same(t, def, config.GetBackChannelNotifier(ctx))

	custom := oauth2.NewHTTPBackChannelNotifier(http.DefaultClient)
	assert.Same(t, custom, (&oauth2.Config{BackChannelNotifier: custom}).GetBackChannelNotifier(ctx))
}

func TestHTTPNotifierDefaultClientPermitsOnlyBCP195CipherSuites(t *testing.T) {
	notifier := oauth2.NewHTTPBackChannelNotifier(nil)

	transport, ok := notifier.Client.Transport.(*http.Transport)
	require.True(t, ok)
	require.NotNil(t, transport.TLSClientConfig)

	assert.Equal(t, uint16(tls.VersionTLS12), transport.TLSClientConfig.MinVersion)
	assert.ElementsMatch(t, []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}, transport.TLSClientConfig.CipherSuites)
}

func TestHTTPNotifierZeroValueRefusesSpecialUseAddress(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	err := (&oauth2.HTTPBackChannelNotifier{}).NotifyBackChannelClient(context.Background(), &oauth2.BackChannelNotification{Endpoint: server.URL, BearerToken: "t", Body: json.RawMessage(`{}`)})
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrSpecialUseAddress)
}

func TestPushErrorNotificationRejectsUnpermittedErrors(t *testing.T) {
	client := &oauth2.DefaultCIBAClient{DefaultClient: &oauth2.DefaultClient{ID: "c"}, BackChannelTokenDeliveryMode: "push", BackChannelClientNotificationEndpoint: "https://client.example.com/cb"}

	for _, permitted := range []*oauth2.RFC6749Error{oauth2.ErrAccessDenied, oauth2.ErrDeviceExpiredToken, oauth2.ErrTransactionFailed} {
		_, err := oauth2.NewBackChannelPushErrorNotification(client, newCIBANotifierTestRequest("r", "tok"), "x", permitted)
		assert.NoError(t, err, permitted.ErrorField)
	}

	for _, rejected := range []*oauth2.RFC6749Error{oauth2.ErrInvalidRequest, oauth2.ErrServerError, oauth2.ErrAuthorizationPending, {ErrorField: ""}} {
		_, err := oauth2.NewBackChannelPushErrorNotification(client, newCIBANotifierTestRequest("r", "tok"), "x", rejected)
		assert.Error(t, err, rejected.ErrorField)
	}
}
