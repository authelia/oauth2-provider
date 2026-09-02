// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/oidckb"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/handler/rfc8628"
	"authelia.com/provider/oauth2/handler/rfc9449"
	"authelia.com/provider/oauth2/storage"
)

func TestOpenIDConnectKeyBindingFactories(t *testing.T) {
	config := &oauth2.Config{OIDCKeyBindingEnabled: true, DPoPEnabled: true}

	testCases := []struct {
		name     string
		factory  Factory
		expected any
	}{
		{name: "ShouldProduceAuthorizeBindingHandler", factory: OpenIDConnectKeyBindingAuthorizeFactory, expected: &oidckb.AuthorizeHandler{}},
		{name: "ShouldProduceDeviceAuthorizeBindingHandler", factory: OpenIDConnectKeyBindingDeviceAuthorizeFactory, expected: &oidckb.DeviceAuthorizeHandler{}},
		{name: "ShouldProduceTokenBindingHandler", factory: OpenIDConnectKeyBindingFactory, expected: &oidckb.Handler{}},
		{name: "ShouldProduceDPoPDeviceAuthorizeBindingHandler", factory: DPoPDeviceAuthorizeFactory, expected: &rfc9449.DeviceAuthorizeHandler{}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.IsType(t, tc.expected, tc.factory(config, nil, nil))
		})
	}
}

func TestComposeAllEnabledOrdersAuthorizationCodeBeforeOpenIDConnect(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	config := &oauth2.Config{
		OIDCKeyBindingEnabled:                 true,
		DPoPEnabled:                           true,
		GlobalSecret:                          []byte("some-cool-secret-that-is-32bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
	}

	_ = ComposeAllEnabled(config, storage.NewMemoryStore(), key)

	var code, oidc = -1, -1

	for i, h := range config.TokenEndpointHandlers {
		switch h.(type) {
		case *hoauth2.AuthorizeExplicitGrantHandler:
			code = i
		case *openid.OpenIDConnectExplicitHandler:
			oidc = i
		}
	}

	require.NotEqual(t, -1, code)
	require.NotEqual(t, -1, oidc)

	assert.Less(t, code, oidc, "the OAuth 2.0 authorization code handler must precede the OpenID Connect explicit handler")
}

func TestOpenIDConnectKeyBindingRequiresBindingHandlerOrdering(t *testing.T) {
	newConfig := func() *oauth2.Config {
		return &oauth2.Config{OIDCKeyBindingEnabled: true, DPoPEnabled: true}
	}

	// Config.TokenEndpointBindingHandlers is exported and may be assigned directly, bypassing Append's
	// deduplication, so the check must hold for a list carrying more than one of either handler.
	testCases := []struct {
		name      string
		handlers  oauth2.TokenEndpointBindingHandlers
		factories []Factory
		panics    bool
	}{
		{
			name:      "ShouldPanicWhenOpenIDConnectKeyBindingFactoryIsRegisteredFirst",
			factories: []Factory{OpenIDConnectKeyBindingFactory, DPoPTokenFactory},
			panics:    true,
		},
		{
			name:      "ShouldNotPanicWithDPoPTokenFactoryAlone",
			factories: []Factory{DPoPTokenFactory},
		},
		{
			name:      "ShouldNotPanicWithOpenIDConnectKeyBindingFactoryAloneToPermitACustomPublisher",
			factories: []Factory{OpenIDConnectKeyBindingFactory},
		},
		{
			name:     "ShouldPanicWhenAnEarlierKeyBindingHandlerPrecedesTheDPoPHandler",
			handlers: oauth2.TokenEndpointBindingHandlers{&oidckb.Handler{}, &rfc9449.Handler{}, &oidckb.Handler{}},
			panics:   true,
		},
		{
			name:     "ShouldNotPanicWhenEveryKeyBindingHandlerFollowsTheDPoPHandler",
			handlers: oauth2.TokenEndpointBindingHandlers{&rfc9449.Handler{}, &oidckb.Handler{}, &oidckb.Handler{}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := newConfig()

			run := func() {
				if tc.handlers != nil {
					config.TokenEndpointBindingHandlers = tc.handlers

					mustOrderTokenEndpointBindingHandlers(config)

					return
				}

				_ = Compose(config, storage.NewMemoryStore(), nil, tc.factories...)
			}

			if tc.panics {
				require.Panics(t, run)

				return
			}

			require.NotPanics(t, run)
		})
	}

	t.Run("ShouldComposeTheDocumentedOrder", func(t *testing.T) {
		config := newConfig()

		require.NotPanics(t, func() {
			_ = Compose(config, storage.NewMemoryStore(), nil, DPoPTokenFactory, OpenIDConnectKeyBindingFactory)
		})

		var oidckbIndex, rfc9449Index = -1, -1

		for i, h := range config.TokenEndpointBindingHandlers {
			switch h.(type) {
			case *oidckb.Handler:
				oidckbIndex = i
			case *rfc9449.Handler:
				rfc9449Index = i
			}
		}

		require.NotEqual(t, -1, oidckbIndex)
		require.NotEqual(t, -1, rfc9449Index)

		assert.Less(t, rfc9449Index, oidckbIndex, "rfc9449.Handler must be registered before oidckb.Handler in the token endpoint binding handler list")
	})
}

func TestOpenIDConnectKeyBindingRequiresUserAuthorizeHandlerOrdering(t *testing.T) {
	binding, device := &oidckb.UserAuthorizeHandler{}, &rfc8628.UserAuthorizeHandler{}

	testCases := []struct {
		name     string
		handlers []oauth2.RFC8628UserAuthorizeEndpointHandler
		panics   bool
	}{
		{
			name:     "ShouldPanicWhenTheDeviceHandlerIsRegisteredFirst",
			handlers: []oauth2.RFC8628UserAuthorizeEndpointHandler{device, binding},
			panics:   true,
		},
		{
			name:     "ShouldPanicWhenAKeyBindingHandlerFollowsAnEarlierDeviceHandler",
			handlers: []oauth2.RFC8628UserAuthorizeEndpointHandler{device, binding, device},
			panics:   true,
		},
		{
			name:     "ShouldNotPanicInTheDocumentedOrder",
			handlers: []oauth2.RFC8628UserAuthorizeEndpointHandler{binding, device},
		},
		{
			name:     "ShouldNotPanicWithTheDeviceHandlerAlone",
			handlers: []oauth2.RFC8628UserAuthorizeEndpointHandler{device},
		},
		{
			name:     "ShouldNotPanicWithTheKeyBindingHandlerAlone",
			handlers: []oauth2.RFC8628UserAuthorizeEndpointHandler{binding},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &oauth2.Config{OIDCKeyBindingEnabled: true, DPoPEnabled: true}
			config.RFC8628UserAuthorizeEndpointHandlers = tc.handlers

			run := func() { mustOrderRFC8628UserAuthorizeHandlers(config) }

			if tc.panics {
				require.Panics(t, run)

				return
			}

			require.NotPanics(t, run)
		})
	}
}

var (
	_ oauth2.AuthorizeEndpointBindingHandler              = (*oidckb.AuthorizeHandler)(nil)
	_ oauth2.RFC8628DeviceAuthorizeEndpointBindingHandler = (*oidckb.DeviceAuthorizeHandler)(nil)
	_ oauth2.TokenEndpointBindingHandler                  = (*oidckb.Handler)(nil)
	_ oauth2.RFC8628DeviceAuthorizeEndpointBindingHandler = (*rfc9449.DeviceAuthorizeHandler)(nil)
)
