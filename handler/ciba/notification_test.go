// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ciba_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/ciba"
)

// testBackchannelClient is a minimal oauth2.Client implementation that also satisfies BackchannelAuthenticationClient.
type testBackchannelClient struct {
	*oauth2.DefaultClient

	deliveryMode         string
	notificationEndpoint string
}

func (c *testBackchannelClient) GetBackchannelTokenDeliveryMode() string {
	return c.deliveryMode
}

func (c *testBackchannelClient) GetBackchannelClientNotificationEndpoint() string {
	return c.notificationEndpoint
}

type httpClientProvider struct {
	client *retryablehttp.Client
}

func (p *httpClientProvider) GetHTTPClient(_ context.Context) *retryablehttp.Client {
	return p.client
}

func newSilentRetryableClient() *retryablehttp.Client {
	c := retryablehttp.NewClient()
	c.Logger = nil
	c.RetryMax = 0
	c.RetryWaitMin = time.Millisecond
	c.RetryWaitMax = time.Millisecond
	return c
}

func newTestRequest(client oauth2.Client, notificationToken string) *oauth2.CIBARequest {
	r := oauth2.NewCIBARequest()
	r.Client = client
	r.Form = url.Values{}

	if notificationToken != "" {
		r.Form.Set("client_notification_token", notificationToken)
	}

	return r
}

func TestClientNotificationHandler_Notify(t *testing.T) {
	t.Run("ShouldNoOpForPollDelivery", func(t *testing.T) {
		handler := &ciba.ClientNotificationHandler{Config: &httpClientProvider{client: newSilentRetryableClient()}}

		request := newTestRequest(&testBackchannelClient{
			DefaultClient: &oauth2.DefaultClient{ID: "client"},
			deliveryMode:  "poll",
		}, "tok")

		require.NoError(t, handler.Notify(t.Context(), request, "auth-req-id", nil))
	})

	t.Run("ShouldNoOpForNonBackchannelClient", func(t *testing.T) {
		handler := &ciba.ClientNotificationHandler{Config: &httpClientProvider{client: newSilentRetryableClient()}}

		request := newTestRequest(&oauth2.DefaultClient{ID: "client"}, "tok")

		require.NoError(t, handler.Notify(t.Context(), request, "auth-req-id", nil))
	})

	t.Run("ShouldSendPingNotification", func(t *testing.T) {
		var (
			gotAuth   string
			gotCT     string
			gotBody   map[string]any
			gotMethod string
		)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotMethod = r.Method
			gotAuth = r.Header.Get("Authorization")
			gotCT = r.Header.Get("Content-Type")
			body, _ := io.ReadAll(r.Body)
			require.NoError(t, json.Unmarshal(body, &gotBody))

			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		handler := &ciba.ClientNotificationHandler{Config: &httpClientProvider{client: newSilentRetryableClient()}}

		request := newTestRequest(&testBackchannelClient{
			DefaultClient:        &oauth2.DefaultClient{ID: "client"},
			deliveryMode:         "ping",
			notificationEndpoint: server.URL,
		}, "the-token")

		require.NoError(t, handler.Notify(t.Context(), request, "auth-req-id-xyz", nil))

		assert.Equal(t, http.MethodPost, gotMethod)
		assert.Equal(t, "Bearer the-token", gotAuth)
		assert.Equal(t, "application/json; charset=utf-8", gotCT)
		assert.Equal(t, map[string]any{"auth_req_id": "auth-req-id-xyz"}, gotBody)
	})

	t.Run("ShouldSendPushNotificationWithTokens", func(t *testing.T) {
		var gotBody map[string]any

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			require.NoError(t, json.Unmarshal(body, &gotBody))
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		handler := &ciba.ClientNotificationHandler{Config: &httpClientProvider{client: newSilentRetryableClient()}}

		request := newTestRequest(&testBackchannelClient{
			DefaultClient:        &oauth2.DefaultClient{ID: "client"},
			deliveryMode:         "push",
			notificationEndpoint: server.URL,
		}, "the-token")

		response := oauth2.NewAccessResponse()
		response.SetAccessToken("the-access-token")
		response.SetTokenType("bearer")
		response.SetExpiresIn(time.Hour)
		response.SetScopes(oauth2.Arguments{"openid", "offline_access"})
		response.SetExtra("refresh_token", "the-refresh-token")
		response.SetExtra("id_token", "the-id-token")

		require.NoError(t, handler.Notify(t.Context(), request, "auth-req-id-xyz", response))

		assert.Equal(t, "auth-req-id-xyz", gotBody["auth_req_id"])
		assert.Equal(t, "the-access-token", gotBody["access_token"])
		assert.Equal(t, "bearer", gotBody["token_type"])
		assert.Equal(t, "the-refresh-token", gotBody["refresh_token"])
		assert.Equal(t, "the-id-token", gotBody["id_token"])
		assert.Equal(t, "openid offline_access", gotBody["scope"])
		assert.EqualValues(t, 3600, gotBody["expires_in"])
	})

	t.Run("ShouldOmitAbsentOptionalFieldsInPush", func(t *testing.T) {
		var gotBody map[string]any

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			require.NoError(t, json.Unmarshal(body, &gotBody))
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		handler := &ciba.ClientNotificationHandler{Config: &httpClientProvider{client: newSilentRetryableClient()}}

		request := newTestRequest(&testBackchannelClient{
			DefaultClient:        &oauth2.DefaultClient{ID: "client"},
			deliveryMode:         "push",
			notificationEndpoint: server.URL,
		}, "the-token")

		response := oauth2.NewAccessResponse()
		response.SetAccessToken("the-access-token")
		response.SetTokenType("bearer")

		require.NoError(t, handler.Notify(t.Context(), request, "auth-req-id-xyz", response))

		assert.Equal(t, "the-access-token", gotBody["access_token"])
		assert.Equal(t, "bearer", gotBody["token_type"])
		assert.NotContains(t, gotBody, "refresh_token")
		assert.NotContains(t, gotBody, "id_token")
		assert.NotContains(t, gotBody, "scope")
		assert.NotContains(t, gotBody, "expires_in")
	})

	t.Run("ShouldFailPushWithNilResponse", func(t *testing.T) {
		handler := &ciba.ClientNotificationHandler{Config: &httpClientProvider{client: newSilentRetryableClient()}}

		request := newTestRequest(&testBackchannelClient{
			DefaultClient:        &oauth2.DefaultClient{ID: "client"},
			deliveryMode:         "push",
			notificationEndpoint: "https://client.example/cb",
		}, "the-token")

		err := handler.Notify(t.Context(), request, "auth-req-id", nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrServerError)
	})

	t.Run("ShouldFailWhenEndpointMissing", func(t *testing.T) {
		handler := &ciba.ClientNotificationHandler{Config: &httpClientProvider{client: newSilentRetryableClient()}}

		request := newTestRequest(&testBackchannelClient{
			DefaultClient: &oauth2.DefaultClient{ID: "client"},
			deliveryMode:  "ping",
		}, "the-token")

		err := handler.Notify(t.Context(), request, "auth-req-id", nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrServerError)
	})

	t.Run("ShouldFailWhenNotificationTokenMissing", func(t *testing.T) {
		handler := &ciba.ClientNotificationHandler{Config: &httpClientProvider{client: newSilentRetryableClient()}}

		request := newTestRequest(&testBackchannelClient{
			DefaultClient:        &oauth2.DefaultClient{ID: "client"},
			deliveryMode:         "ping",
			notificationEndpoint: "https://client.example/cb",
		}, "")

		err := handler.Notify(t.Context(), request, "auth-req-id", nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrServerError)
	})

	t.Run("ShouldFailWhenRemoteReturnsError", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("boom"))
		}))
		defer server.Close()

		handler := &ciba.ClientNotificationHandler{Config: &httpClientProvider{client: newSilentRetryableClient()}}

		request := newTestRequest(&testBackchannelClient{
			DefaultClient:        &oauth2.DefaultClient{ID: "client"},
			deliveryMode:         "ping",
			notificationEndpoint: server.URL,
		}, "the-token")

		err := handler.Notify(t.Context(), request, "auth-req-id", nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrServerError)
	})

	t.Run("ShouldFailForUnknownDeliveryMode", func(t *testing.T) {
		handler := &ciba.ClientNotificationHandler{Config: &httpClientProvider{client: newSilentRetryableClient()}}

		request := newTestRequest(&testBackchannelClient{
			DefaultClient:        &oauth2.DefaultClient{ID: "client"},
			deliveryMode:         "fax",
			notificationEndpoint: "https://client.example/cb",
		}, "the-token")

		err := handler.Notify(t.Context(), request, "auth-req-id", nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrServerError)
	})
}

func TestClientNotificationHandler_NotifyError(t *testing.T) {
	t.Run("ShouldNoOpForPollDelivery", func(t *testing.T) {
		handler := &ciba.ClientNotificationHandler{Config: &httpClientProvider{client: newSilentRetryableClient()}}

		request := newTestRequest(&testBackchannelClient{
			DefaultClient: &oauth2.DefaultClient{ID: "client"},
			deliveryMode:  "poll",
		}, "tok")

		require.NoError(t, handler.NotifyError(t.Context(), request, "auth-req-id", oauth2.ErrAccessDenied))
	})

	t.Run("ShouldNoOpForPingDelivery", func(t *testing.T) {
		called := false

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		handler := &ciba.ClientNotificationHandler{Config: &httpClientProvider{client: newSilentRetryableClient()}}

		request := newTestRequest(&testBackchannelClient{
			DefaultClient:        &oauth2.DefaultClient{ID: "client"},
			deliveryMode:         "ping",
			notificationEndpoint: server.URL,
		}, "tok")

		require.NoError(t, handler.NotifyError(t.Context(), request, "auth-req-id", oauth2.ErrAccessDenied))
		assert.False(t, called, "ping mode should not POST an error notification")
	})

	t.Run("ShouldSendPushErrorNotification", func(t *testing.T) {
		var gotBody map[string]any

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			require.NoError(t, json.Unmarshal(body, &gotBody))
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		handler := &ciba.ClientNotificationHandler{Config: &httpClientProvider{client: newSilentRetryableClient()}}

		request := newTestRequest(&testBackchannelClient{
			DefaultClient:        &oauth2.DefaultClient{ID: "client"},
			deliveryMode:         "push",
			notificationEndpoint: server.URL,
		}, "the-token")

		require.NoError(t, handler.NotifyError(t.Context(), request, "auth-req-id", oauth2.ErrAccessDenied))

		assert.Equal(t, "auth-req-id", gotBody["auth_req_id"])
		assert.Equal(t, "access_denied", gotBody["error"])
		assert.Contains(t, gotBody, "error_description")
	})
}
