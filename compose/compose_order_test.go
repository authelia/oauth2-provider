// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/oidckb"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/handler/pkce"
	"authelia.com/provider/oauth2/handler/rfc8628"
	"authelia.com/provider/oauth2/handler/rfc9449"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
)

func TestValidateHandlerOrderPKCE(t *testing.T) {
	explicit, proof := &hoauth2.AuthorizeExplicitGrantHandler{}, &pkce.Handler{}

	testCases := []struct {
		name     string
		handlers oauth2.TokenEndpointHandlers
		err      bool
	}{
		{name: "ShouldPassInTheDocumentedOrder", handlers: oauth2.TokenEndpointHandlers{explicit, proof}},
		{name: "ShouldPassWithThePKCEHandlerAlone", handlers: oauth2.TokenEndpointHandlers{proof}},
		{name: "ShouldPassWithTheExplicitHandlerAlone", handlers: oauth2.TokenEndpointHandlers{explicit}},
		{name: "ShouldFailWhenThePKCEHandlerIsRegisteredFirst", handlers: oauth2.TokenEndpointHandlers{proof, explicit}, err: true},
		{name: "ShouldFailWhenAnEarlierPKCEHandlerPrecedesTheExplicitHandler", handlers: oauth2.TokenEndpointHandlers{proof, explicit, proof}, err: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateHandlerOrder(&oauth2.Config{TokenEndpointHandlers: tc.handlers})

			if !tc.err {
				assert.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, ErrHandlerOrder)
			assert.Contains(t, err.Error(), "pkce.Handler")
		})
	}
}

func TestValidateHandlerOrderOpenIDConnect(t *testing.T) {
	testCases := []struct {
		name  string
		grant oauth2.TokenEndpointHandler
		oidc  oauth2.TokenEndpointHandler
		kind  string
	}{
		{name: "AuthorizationCode", grant: &hoauth2.AuthorizeExplicitGrantHandler{}, oidc: &openid.OpenIDConnectExplicitHandler{}, kind: "openid.OpenIDConnectExplicitHandler"},
		{name: "RefreshToken", grant: &hoauth2.RefreshTokenGrantHandler{}, oidc: &openid.OpenIDConnectRefreshHandler{}, kind: "openid.OpenIDConnectRefreshHandler"},
		{name: "DeviceCode", grant: &rfc8628.DeviceAuthorizeTokenEndpointHandler{}, oidc: &openid.OpenIDConnectDeviceAuthorizeHandler{}, kind: "openid.OpenIDConnectDeviceAuthorizeHandler"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("ShouldPassInTheDocumentedOrder", func(t *testing.T) {
				assert.NoError(t, ValidateHandlerOrder(&oauth2.Config{TokenEndpointHandlers: oauth2.TokenEndpointHandlers{tc.grant, tc.oidc}}))
			})

			t.Run("ShouldPassWithTheOpenIDConnectHandlerAlone", func(t *testing.T) {
				assert.NoError(t, ValidateHandlerOrder(&oauth2.Config{TokenEndpointHandlers: oauth2.TokenEndpointHandlers{tc.oidc}}))
			})

			t.Run("ShouldPassWithTheGrantHandlerAlone", func(t *testing.T) {
				assert.NoError(t, ValidateHandlerOrder(&oauth2.Config{TokenEndpointHandlers: oauth2.TokenEndpointHandlers{tc.grant}}))
			})

			t.Run("ShouldFailWhenTheOpenIDConnectHandlerIsRegisteredFirst", func(t *testing.T) {
				err := ValidateHandlerOrder(&oauth2.Config{TokenEndpointHandlers: oauth2.TokenEndpointHandlers{tc.oidc, tc.grant}})

				require.ErrorIs(t, err, ErrHandlerOrder)
				assert.Contains(t, err.Error(), tc.kind)
			})
		})
	}
}

func TestValidateHandlerOrderReportsEveryFault(t *testing.T) {
	config := &oauth2.Config{
		TokenEndpointHandlers:        oauth2.TokenEndpointHandlers{&pkce.Handler{}, &hoauth2.AuthorizeExplicitGrantHandler{}},
		TokenEndpointBindingHandlers: oauth2.TokenEndpointBindingHandlers{&oidckb.Handler{}, &rfc9449.Handler{}},
	}

	err := ValidateHandlerOrder(config)

	require.ErrorIs(t, err, ErrHandlerOrder)
	assert.Contains(t, err.Error(), "pkce.Handler")
	assert.Contains(t, err.Error(), "oidckb.Handler")
}

func TestComposeAllEnabledPassesValidateHandlerOrder(t *testing.T) {
	config := &oauth2.Config{
		OIDCKeyBindingEnabled:                 true,
		DPoPEnabled:                           true,
		GlobalSecret:                          []byte("some-cool-secret-that-is-32bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
	}

	_ = ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey())

	assert.NoError(t, ValidateHandlerOrder(config))
}

func TestComposePanicsWhenThePKCEFactoryPrecedesTheExplicitFactory(t *testing.T) {
	config := &oauth2.Config{GlobalSecret: []byte("some-cool-secret-that-is-32bytes")}

	assert.PanicsWithError(t, "oauth2: handlers are registered in an order which does not work: the pkce.Handler (OAuth2PKCEFactory) must be registered after the hoauth2.AuthorizeExplicitGrantHandler (OAuth2AuthorizeExplicitFactory), as it removes the PKCE request session which must outlive the authorization code", func() {
		_ = Compose(config, storage.NewMemoryStore(), NewOAuth2HMACStrategy(config), OAuth2PKCEFactory, OAuth2AuthorizeExplicitFactory)
	})
}
