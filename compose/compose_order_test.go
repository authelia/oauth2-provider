// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/idjag"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/oidckb"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/handler/pkce"
	"authelia.com/provider/oauth2/handler/rfc8628"
	"authelia.com/provider/oauth2/handler/rfc8693"
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

func TestValidateHandlerOrderAuthorizeEndpoint(t *testing.T) {
	explicit, hybrid := &hoauth2.AuthorizeExplicitGrantHandler{}, &openid.OpenIDConnectHybridHandler{}
	oidc, proof := &openid.OpenIDConnectExplicitHandler{}, &pkce.Handler{}

	testCases := []struct {
		name     string
		handlers oauth2.AuthorizeEndpointHandlers
		contains []string
	}{
		{name: "ShouldPassInTheDocumentedOrder", handlers: oauth2.AuthorizeEndpointHandlers{explicit, oidc, hybrid, proof}},
		{name: "ShouldPassWithTheDependentHandlersAlone", handlers: oauth2.AuthorizeEndpointHandlers{oidc, proof}},
		{name: "ShouldFailWhenTheOpenIDConnectExplicitHandlerIsRegisteredFirst", handlers: oauth2.AuthorizeEndpointHandlers{oidc, explicit}, contains: []string{"openid.OpenIDConnectExplicitHandler"}},
		{name: "ShouldFailWhenThePKCEHandlerPrecedesTheExplicitHandler", handlers: oauth2.AuthorizeEndpointHandlers{proof, explicit}, contains: []string{"pkce.Handler", "hoauth2.AuthorizeExplicitGrantHandler"}},
		{name: "ShouldFailWhenThePKCEHandlerPrecedesTheHybridHandler", handlers: oauth2.AuthorizeEndpointHandlers{explicit, proof, hybrid}, contains: []string{"pkce.Handler", "openid.OpenIDConnectHybridHandler"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateHandlerOrder(&oauth2.Config{AuthorizeEndpointHandlers: tc.handlers})

			if len(tc.contains) == 0 {
				assert.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, ErrHandlerOrder)

			for _, contains := range tc.contains {
				assert.Contains(t, err.Error(), contains)
			}
		})
	}
}

func TestValidateHandlerOrderRFC8693(t *testing.T) {
	grant, access, refresh, validator := &rfc8693.TokenExchangeGrantHandler{}, &rfc8693.AccessTokenTypeHandler{}, &rfc8693.RefreshTokenTypeHandler{}, &rfc8693.ActorTokenValidationHandler{}
	id, custom := &rfc8693.IDTokenTypeHandler{}, &rfc8693.CustomJWTTypeHandler{}

	testCases := []struct {
		name     string
		handlers oauth2.TokenEndpointHandlers
		err      string
	}{
		{name: "ShouldPassInTheDocumentedOrder", handlers: oauth2.TokenEndpointHandlers{grant, access, refresh, id, custom, validator}},
		{name: "ShouldPassWithATypeHandlerOmitted", handlers: oauth2.TokenEndpointHandlers{grant, access, validator}},
		{name: "ShouldPassWithUnrelatedHandlersInterleaved", handlers: oauth2.TokenEndpointHandlers{grant, &hoauth2.AuthorizeExplicitGrantHandler{}, access, &pkce.Handler{}, validator}},
		{name: "ShouldPassWithNoRFC8693Handlers", handlers: oauth2.TokenEndpointHandlers{&hoauth2.AuthorizeExplicitGrantHandler{}}},
		{name: "ShouldRejectTheGrantHandlerAfterATypeHandler", handlers: oauth2.TokenEndpointHandlers{access, grant, refresh, validator}, err: "rfc8693.TokenExchangeGrantHandler (RFC8693TokenExchangeGrantFactory) must be registered before"},
		{name: "ShouldRejectTheGrantHandlerAfterTheCustomJWTTypeHandler", handlers: oauth2.TokenEndpointHandlers{custom, grant, validator}, err: "must be registered before every RFC 8693 token type handler"},
		{name: "ShouldRejectAMissingGrantHandler", handlers: oauth2.TokenEndpointHandlers{access, validator}, err: "rfc8693.TokenExchangeGrantHandler (RFC8693TokenExchangeGrantFactory) must be registered with"},
		{name: "ShouldRejectTheValidationHandlerBeforeATypeHandler", handlers: oauth2.TokenEndpointHandlers{grant, validator, access}, err: "rfc8693.ActorTokenValidationHandler (RFC8693ActorTokenValidationFactory) must be registered after"},
		{name: "ShouldRejectTheValidationHandlerBeforeTheIDTokenTypeHandler", handlers: oauth2.TokenEndpointHandlers{grant, access, validator, id}, err: "must be registered after every RFC 8693 token type handler"},
		{name: "ShouldRejectAMissingValidationHandler", handlers: oauth2.TokenEndpointHandlers{grant, access}, err: "rfc8693.ActorTokenValidationHandler (RFC8693ActorTokenValidationFactory) must be registered with"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateHandlerOrder(&oauth2.Config{TokenEndpointHandlers: tc.handlers})

			if tc.err == "" {
				assert.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, ErrHandlerOrder)
			assert.Contains(t, err.Error(), tc.err)
		})
	}
}

func TestValidateHandlerOrderIDJAG(t *testing.T) {
	redeem := &idjag.RedeemHandler{}

	testCases := []struct {
		name     string
		token    oauth2.TokenEndpointHandlers
		binding  oauth2.TokenEndpointBindingHandlers
		contains string
	}{
		{name: "ShouldAcceptRedeemAfterDPoP", token: oauth2.TokenEndpointHandlers{redeem}, binding: oauth2.TokenEndpointBindingHandlers{&rfc9449.Handler{}, redeem}},
		{name: "ShouldAcceptRedeemWithoutDPoP", token: oauth2.TokenEndpointHandlers{redeem}, binding: oauth2.TokenEndpointBindingHandlers{redeem}},
		{name: "ShouldRejectRedeemBeforeDPoP", token: oauth2.TokenEndpointHandlers{redeem}, binding: oauth2.TokenEndpointBindingHandlers{redeem, &rfc9449.Handler{}}, contains: "must be registered before the idjag.RedeemHandler"},
		{name: "ShouldRejectRedeemMissingFromBinding", token: oauth2.TokenEndpointHandlers{redeem}, binding: oauth2.TokenEndpointBindingHandlers{&rfc9449.Handler{}}, contains: "must also be registered in the token endpoint binding handlers"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateHandlerOrder(&oauth2.Config{TokenEndpointHandlers: tc.token, TokenEndpointBindingHandlers: tc.binding})

			if tc.contains == "" {
				assert.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, ErrHandlerOrder)
			assert.Contains(t, err.Error(), tc.contains)
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

	assert.PanicsWithError(t, "oauth2: handlers are registered in an order which does not work: the pkce.Handler (OAuth2PKCEFactory) must be registered after the hoauth2.AuthorizeExplicitGrantHandler (OAuth2AuthorizeExplicitFactory) in the authorize endpoint handlers, as it records the PKCE request session under the authorization code the hoauth2.AuthorizeExplicitGrantHandler issues\noauth2: handlers are registered in an order which does not work: the pkce.Handler (OAuth2PKCEFactory) must be registered after the hoauth2.AuthorizeExplicitGrantHandler (OAuth2AuthorizeExplicitFactory), as it removes the PKCE request session which must outlive the authorization code", func() {
		_ = Compose(config, storage.NewMemoryStore(), NewOAuth2HMACStrategy(config), OAuth2PKCEFactory, OAuth2AuthorizeExplicitFactory)
	})
}

func TestComposePanicsWhenTheRFC8693GrantFactoryFollowsATypeFactory(t *testing.T) {
	config := &oauth2.Config{GlobalSecret: []byte("some-cool-secret-that-is-32bytes")}

	assert.PanicsWithError(t, "oauth2: handlers are registered in an order which does not work: the rfc8693.TokenExchangeGrantHandler (RFC8693TokenExchangeGrantFactory) must be registered before every RFC 8693 token type handler, as it writes the 'act' claim onto the session they issue the token from", func() {
		_ = Compose(config, storage.NewMemoryStore(), NewOAuth2HMACStrategy(config), RFC8693AccessTokenTypeFactory, RFC8693TokenExchangeGrantFactory, RFC8693ActorTokenValidationFactory)
	})
}
