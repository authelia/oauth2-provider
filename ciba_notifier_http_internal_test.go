// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPBackChannelNotifierSpecialUseAddressGuard(t *testing.T) {
	_, loopback, err := net.ParseCIDR("127.0.0.0/8")
	require.NoError(t, err)

	resolving := func(config *Config) *Config {
		config.ClientIDMetadataDocumentResolver = &backChannelNotifierTestResolver{}

		return config
	}

	testCases := []struct {
		name      string
		config    any
		client    Client
		clientID  string
		delivered bool
	}{
		{name: "ShouldRefuseALoopbackEndpointByDefault", config: &Config{}},
		{name: "ShouldRefuseALoopbackEndpointWithoutAConfig"},
		{name: "ShouldDeliverWhenTheGuardIsDisabled", config: &Config{DisableSpecialUseAddressGuard: true}, delivered: true},
		{name: "ShouldDeliverToAnAllowedNetwork", config: &Config{SpecialUseAddressGuardAllowedNetworks: []*net.IPNet{loopback}}, delivered: true},
		{name: "ShouldRefuseAClientIDMetadataDocumentClientWhenTheGuardIsDisabled", config: &Config{DisableSpecialUseAddressGuard: true}, client: &backChannelNotifierTestDocumentClient{DefaultClient: &DefaultClient{ID: "https://client.example.com/metadata"}}},
		{name: "ShouldRefuseAClientIDMetadataDocumentClientInAnAllowedNetwork", config: &Config{SpecialUseAddressGuardAllowedNetworks: []*net.IPNet{loopback}}, client: &backChannelNotifierTestDocumentClient{DefaultClient: &DefaultClient{ID: "https://client.example.com/metadata"}}},
		{name: "ShouldRefuseAClientIdentifierURLWhenDocumentsAreResolved", config: resolving(&Config{DisableSpecialUseAddressGuard: true}), client: &DefaultClient{ID: "https://client.example.com/metadata"}},
		{name: "ShouldRefuseAClientIdentifierURLWithoutTheClientWhenDocumentsAreResolved", config: resolving(&Config{DisableSpecialUseAddressGuard: true}), clientID: "https://client.example.com/metadata"},
		{name: "ShouldDeliverWithoutTheClientWhenTheGuardIsDisabled", config: resolving(&Config{DisableSpecialUseAddressGuard: true}), clientID: "client", delivered: true},
		{name: "ShouldRefuseWithATypedNilConfig", config: (*Config)(nil)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32

			server := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				rw.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()

			notifier := newBackChannelNotifierTestNotifier(server, tc.config)

			err := notifier.NotifyBackChannelClient(context.Background(), &BackChannelNotification{ClientID: tc.clientID, Client: tc.client, Endpoint: server.URL, BearerToken: "token", Body: []byte(`{}`)})

			if tc.delivered {
				require.NoError(t, err)
				assert.Equal(t, int32(1), hits.Load())

				return
			}

			assert.ErrorIs(t, err, ErrSpecialUseAddress)
			assert.Zero(t, hits.Load())
		})
	}
}

func TestHTTPBackChannelNotifierKeepsTheDeliveryProperties(t *testing.T) {
	config := &Config{DisableSpecialUseAddressGuard: true}

	t.Run("ShouldNotFollowARedirect", func(t *testing.T) {
		var hits atomic.Int32

		server := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			http.Redirect(rw, r, "/elsewhere", http.StatusFound)
		}))
		defer server.Close()

		err := newBackChannelNotifierTestNotifier(server, config).NotifyBackChannelClient(context.Background(), &BackChannelNotification{Endpoint: server.URL, BearerToken: "token", Body: []byte(`{}`)})

		assert.Error(t, err)
		assert.Equal(t, int32(1), hits.Load())
	})

	t.Run("ShouldRefuseAVersionBelowTLS12", func(t *testing.T) {
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
			rw.WriteHeader(http.StatusNoContent)
		}))
		server.TLS = &tls.Config{MaxVersion: tls.VersionTLS11}
		server.StartTLS()

		defer server.Close()

		err := newBackChannelNotifierTestNotifier(server, config).NotifyBackChannelClient(context.Background(), &BackChannelNotification{Endpoint: server.URL, BearerToken: "token", Body: []byte(`{}`)})

		assert.Error(t, err)
	})
}

func TestBackChannelNotificationCarriesTheClient(t *testing.T) {
	client := &DefaultCIBAClient{DefaultClient: &DefaultClient{ID: "client"}, BackChannelClientNotificationEndpoint: "https://client.example.com/cb"}

	request := NewBackChannelAuthenticationRequest()
	request.ClientNotificationToken = "token"

	ping, err := NewBackChannelPingNotification(client, request, "auth-req-id")
	require.NoError(t, err)
	assert.Same(t, Client(client), ping.Client)

	failure, err := NewBackChannelPushErrorNotification(client, request, "auth-req-id", ErrAccessDenied)
	require.NoError(t, err)
	assert.Same(t, Client(client), failure.Client)
}

func TestConfigGetBackChannelNotifierDefault(t *testing.T) {
	t.Run("ShouldReadTheGuardSettingsOfTheConfig", func(t *testing.T) {
		config := &Config{}

		notifier, ok := config.GetBackChannelNotifier(context.Background()).(*HTTPBackChannelNotifier)

		require.True(t, ok)
		assert.Nil(t, notifier.Client)
		assert.Same(t, config, notifier.Config)
	})

	t.Run("ShouldReturnTheConfiguredNotifier", func(t *testing.T) {
		configured := NewHTTPBackChannelNotifier(&http.Client{})

		config := &Config{BackChannelNotifier: configured}

		assert.Same(t, configured, config.GetBackChannelNotifier(context.Background()))
	})
}

type backChannelNotifierTestResolver struct{}

func (r *backChannelNotifierTestResolver) ResolveClientIDMetadataDocumentClient(_ context.Context, _ string) (Client, error) {
	return nil, ErrNotFound
}

type backChannelNotifierTestDocumentClient struct {
	*DefaultClient
}

func (c *backChannelNotifierTestDocumentClient) IsClientIDMetadataDocumentClient() bool {
	return true
}

func newBackChannelNotifierTestNotifier(server *httptest.Server, config any) (notifier *HTTPBackChannelNotifier) {
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())

	base := newBackChannelBaseHTTPClient()
	base.HTTPClient.Transport.(*http.Transport).TLSClientConfig.RootCAs = pool

	return &HTTPBackChannelNotifier{Config: config, base: base}
}
