// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/ciba"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/oidckb"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/handler/rfc8705"
	"authelia.com/provider/oauth2/handler/rfc9449"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func newCIBATestStrategy(config *oauth2.Config) *CommonStrategy {
	strategy := &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())}

	return &CommonStrategy{
		CoreStrategy:               NewOAuth2HMACStrategy(config),
		OpenIDConnectTokenStrategy: NewOpenIDConnectStrategy(nil, strategy, config),
		Strategy:                   strategy,
	}
}

func TestComposeCIBAFactories(t *testing.T) {
	config := &oauth2.Config{GlobalSecret: []byte("some-cool-secret-that-is-32bytes")}

	_ = Compose(config, storage.NewMemoryStore(), newCIBATestStrategy(config),
		CIBADecisionFactory,
		CIBATokenFactory,
		OpenIDConnectCIBAFactory,
		CIBAEndpointFactory,
	)

	require.Len(t, config.BackChannelAuthenticationEndpointHandlers, 2)
	assert.IsType(t, &openid.OpenIDConnectCIBAHandler{}, config.BackChannelAuthenticationEndpointHandlers[0])
	assert.IsType(t, &ciba.EndpointHandler{}, config.BackChannelAuthenticationEndpointHandlers[1])

	require.Len(t, config.BackChannelAuthenticationDecisionHandlers, 2)
	assert.IsType(t, &ciba.DecisionHandler{}, config.BackChannelAuthenticationDecisionHandlers[0])
	assert.IsType(t, &openid.OpenIDConnectCIBAHandler{}, config.BackChannelAuthenticationDecisionHandlers[1])

	require.Len(t, config.TokenEndpointHandlers, 2)
	require.IsType(t, &ciba.TokenEndpointHandler{}, config.TokenEndpointHandlers[0])
	assert.IsType(t, &ciba.TokenHandler{}, config.TokenEndpointHandlers[0].(*ciba.TokenEndpointHandler).CodeTokenEndpointHandler)
	require.IsType(t, &openid.OpenIDConnectCIBAHandler{}, config.TokenEndpointHandlers[1])
	assert.IsType(t, &ciba.TokenHandler{}, config.TokenEndpointHandlers[1].(*openid.OpenIDConnectCIBAHandler).CodeTokenEndpointHandler)

	assert.Nil(t, oauth2.SupportedGrantTypes(context.Background(), config))

	config.EndpointURLs.BackChannelAuthentication = "https://op.example.com/bc-authorize"

	assert.Equal(t, []string{"urn:openid:params:grant-type:ciba"}, oauth2.SupportedGrantTypes(context.Background(), config))
}

func TestComposeBindingFactoriesRegisterBackChannelBindingHandlers(t *testing.T) {
	config := &oauth2.Config{GlobalSecret: []byte("some-cool-secret-that-is-32bytes")}

	_ = Compose(config, storage.NewMemoryStore(), newCIBATestStrategy(config),
		DPoPTokenFactory,
		RFC8705Factory,
		OpenIDConnectKeyBindingFactory,
	)

	require.Len(t, config.BackChannelAuthenticationEndpointBindingHandlers, 3)
	assert.IsType(t, &rfc9449.Handler{}, config.BackChannelAuthenticationEndpointBindingHandlers[0])
	assert.IsType(t, &rfc8705.Handler{}, config.BackChannelAuthenticationEndpointBindingHandlers[1])
	assert.IsType(t, &oidckb.Handler{}, config.BackChannelAuthenticationEndpointBindingHandlers[2])

	assert.Len(t, config.TokenEndpointBindingHandlers, 3)
}

func TestValidateHandlerOrderBackChannelAuthenticationBinding(t *testing.T) {
	config := &oauth2.Config{}

	config.BackChannelAuthenticationEndpointBindingHandlers.Append(&oidckb.Handler{Config: config})
	config.BackChannelAuthenticationEndpointBindingHandlers.Append(&rfc9449.Handler{Config: config})

	assert.ErrorIs(t, ValidateHandlerOrder(config), ErrHandlerOrder)

	config = &oauth2.Config{}

	config.BackChannelAuthenticationEndpointBindingHandlers.Append(&rfc9449.Handler{Config: config})
	config.BackChannelAuthenticationEndpointBindingHandlers.Append(&oidckb.Handler{Config: config})

	assert.NoError(t, ValidateHandlerOrder(config))
}

func TestComposeCIBAFactoriesAcceptTheCoreStrategy(t *testing.T) {
	config := &oauth2.Config{GlobalSecret: []byte("some-cool-secret-that-is-32bytes")}

	assert.NotPanics(t, func() {
		_ = Compose(config, storage.NewMemoryStore(), NewOAuth2HMACStrategy(config), CIBAEndpointFactory, CIBADecisionFactory, CIBATokenFactory)
	})
}

func TestComposeCIBAFactoriesPanicWithoutAnAuthRequestIDStrategy(t *testing.T) {
	config := &oauth2.Config{GlobalSecret: []byte("some-cool-secret-that-is-32bytes")}

	strategy := &CommonStrategy{CoreStrategy: struct{ hoauth2.CoreStrategy }{NewOAuth2HMACStrategy(config)}}

	assert.PanicsWithError(t, "compose: the strategy (*compose.CommonStrategy) does not implement ciba.AuthRequestIDStrategy; use *hoauth2.HMACCoreStrategy or *hoauth2.JWTProfileCoreStrategy as the CoreStrategy, or implement it on your strategy", func() {
		_ = Compose(config, storage.NewMemoryStore(), strategy, CIBAEndpointFactory)
	})
}

func TestValidateHandlerOrderCIBA(t *testing.T) {
	oidc := &openid.OpenIDConnectCIBAHandler{}
	endpoint, decision, token := &ciba.EndpointHandler{}, &ciba.DecisionHandler{}, &ciba.TokenEndpointHandler{}

	testCases := []struct {
		name   string
		config *oauth2.Config
		err    string
	}{
		{
			name: "ShouldPassInTheComposedOrder",
			config: &oauth2.Config{
				BackChannelAuthenticationEndpointHandlers: oauth2.BackChannelAuthenticationEndpointHandlers{oidc, endpoint},
				BackChannelAuthenticationDecisionHandlers: oauth2.BackChannelAuthenticationDecisionHandlers{decision, oidc},
				TokenEndpointHandlers:                     oauth2.TokenEndpointHandlers{token, oidc},
			},
		},
		{
			name: "ShouldPassWithTheOpenIDConnectHandlerAlone",
			config: &oauth2.Config{
				BackChannelAuthenticationEndpointHandlers: oauth2.BackChannelAuthenticationEndpointHandlers{oidc},
				BackChannelAuthenticationDecisionHandlers: oauth2.BackChannelAuthenticationDecisionHandlers{oidc},
				TokenEndpointHandlers:                     oauth2.TokenEndpointHandlers{oidc},
			},
		},
		{
			name: "ShouldPassWithTheCIBAHandlersAlone",
			config: &oauth2.Config{
				BackChannelAuthenticationEndpointHandlers: oauth2.BackChannelAuthenticationEndpointHandlers{endpoint},
				BackChannelAuthenticationDecisionHandlers: oauth2.BackChannelAuthenticationDecisionHandlers{decision},
				TokenEndpointHandlers:                     oauth2.TokenEndpointHandlers{token},
			},
		},
		{
			name:   "ShouldFailWhenTheEndpointHandlerPrecedesTheOpenIDConnectHandler",
			config: &oauth2.Config{BackChannelAuthenticationEndpointHandlers: oauth2.BackChannelAuthenticationEndpointHandlers{endpoint, oidc}},
			err:    "oauth2: handlers are registered in an order which does not work: the openid.OpenIDConnectCIBAHandler (OpenIDConnectCIBAFactory) must be registered before the ciba.EndpointHandler (CIBAEndpointFactory) in the backchannel authentication endpoint handlers, as it rejects a reused 'nonce' before the ciba.EndpointHandler persists the request",
		},
		{
			name:   "ShouldFailWhenAnOpenIDConnectHandlerFollowsTheEndpointHandler",
			config: &oauth2.Config{BackChannelAuthenticationEndpointHandlers: oauth2.BackChannelAuthenticationEndpointHandlers{oidc, endpoint, oidc}},
			err:    "oauth2: handlers are registered in an order which does not work: the openid.OpenIDConnectCIBAHandler (OpenIDConnectCIBAFactory) must be registered before the ciba.EndpointHandler (CIBAEndpointFactory) in the backchannel authentication endpoint handlers, as it rejects a reused 'nonce' before the ciba.EndpointHandler persists the request",
		},
		{
			name:   "ShouldFailWhenTheOpenIDConnectHandlerPrecedesTheDecisionHandler",
			config: &oauth2.Config{BackChannelAuthenticationDecisionHandlers: oauth2.BackChannelAuthenticationDecisionHandlers{oidc, decision}},
			err:    "oauth2: handlers are registered in an order which does not work: the openid.OpenIDConnectCIBAHandler (OpenIDConnectCIBAFactory) must be registered after the ciba.DecisionHandler (CIBADecisionFactory) in the backchannel authentication decision handlers, as it writes the OpenID Connect session only for the decision the ciba.DecisionHandler records",
		},
		{
			name:   "ShouldFailWhenTheOpenIDConnectHandlerPrecedesTheTokenHandler",
			config: &oauth2.Config{TokenEndpointHandlers: oauth2.TokenEndpointHandlers{oidc, token}},
			err:    "oauth2: handlers are registered in an order which does not work: the openid.OpenIDConnectCIBAHandler (OpenIDConnectCIBAFactory) must be registered after the ciba.TokenEndpointHandler (CIBATokenFactory), as it requires the scopes the ciba.TokenEndpointHandler grants and computes the ID Token 'at_hash' claim from the access token it issues",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateHandlerOrder(tc.config)

			if tc.err == "" {
				assert.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, ErrHandlerOrder)
			assert.EqualError(t, err, tc.err)
		})
	}
}

func TestComposePanicsWhenTheCIBAEndpointFactoryPrecedesTheOpenIDConnectCIBAFactory(t *testing.T) {
	config := &oauth2.Config{GlobalSecret: []byte("some-cool-secret-that-is-32bytes")}

	assert.Panics(t, func() {
		_ = Compose(config, storage.NewMemoryStore(), newCIBATestStrategy(config), CIBAEndpointFactory, CIBADecisionFactory, CIBATokenFactory, OpenIDConnectCIBAFactory)
	})
}

func TestComposePanicsWhenTheOpenIDConnectCIBAFactoryPrecedesTheCIBATokenFactory(t *testing.T) {
	config := &oauth2.Config{GlobalSecret: []byte("some-cool-secret-that-is-32bytes")}

	assert.PanicsWithError(t, "oauth2: handlers are registered in an order which does not work: the openid.OpenIDConnectCIBAHandler (OpenIDConnectCIBAFactory) must be registered after the ciba.TokenEndpointHandler (CIBATokenFactory), as it requires the scopes the ciba.TokenEndpointHandler grants and computes the ID Token 'at_hash' claim from the access token it issues", func() {
		_ = Compose(config, storage.NewMemoryStore(), newCIBATestStrategy(config), CIBADecisionFactory, OpenIDConnectCIBAFactory, CIBAEndpointFactory, CIBATokenFactory)
	})
}

func TestComposeCIBAFactoriesServeThePollFlow(t *testing.T) {
	const subject = "peter"

	config := &oauth2.Config{GlobalSecret: []byte("some-cool-secret-that-is-32bytes")}
	store := storage.NewMemoryStore()

	store.Clients["ciba"] = &oauth2.DefaultCIBAClient{
		BackChannelTokenDeliveryMode: consts.CIBAModePoll,
		DefaultClient: &oauth2.DefaultClient{
			ID:           "ciba",
			ClientSecret: oauth2.NewPlainTextClientSecret("foobar"),
			GrantTypes:   []string{consts.GrantTypeOpenIDCIBA},
			Scopes:       []string{consts.ScopeOpenID},
		},
	}

	var provider oauth2.Provider

	require.NotPanics(t, func() {
		provider = Compose(config, store, newCIBATestStrategy(config), CIBAFactories()...)
	})

	ctx := context.Background()

	newRequest := func(form url.Values) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "https://auth.example.com/", strings.NewReader(form.Encode()))
		r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
		r.SetBasicAuth("ciba", "foobar")

		return r
	}

	session := openid.NewDefaultSession()

	request, err := provider.NewBackChannelAuthenticationRequest(ctx, newRequest(url.Values{
		consts.FormParameterScope:     {consts.ScopeOpenID},
		consts.FormParameterLoginHint: {subject},
	}), session)
	require.NoError(t, err)

	session.Subject, session.Claims.Subject = subject, subject

	request.(*oauth2.BackChannelAuthenticationRequest).RequestedAt = request.GetRequestedAt().Add(-time.Minute)

	response, err := provider.NewBackChannelAuthenticationResponse(ctx, request)
	require.NoError(t, err)

	poll := url.Values{
		consts.FormParameterGrantType: {consts.GrantTypeOpenIDCIBA},
		consts.FormParameterAuthReqID: {response.GetAuthRequestID()},
	}

	_, err = provider.NewAccessRequest(ctx, newRequest(poll), openid.NewDefaultSession())
	require.ErrorIs(t, err, oauth2.ErrAuthorizationPending)

	decision, err := provider.NewBackChannelAuthenticationDecisionRequest(ctx, request.GetID(), openid.NewDefaultSession())
	require.NoError(t, err)

	decision.GrantScope(consts.ScopeOpenID)

	approval := openid.NewDefaultSession()
	approval.Subject, approval.Claims.Subject = subject, subject

	_, err = provider.ApproveBackChannelAuthentication(ctx, decision, approval)
	require.NoError(t, err)

	access, err := provider.NewAccessRequest(ctx, newRequest(poll), openid.NewDefaultSession())
	require.NoError(t, err)

	token, err := provider.NewAccessResponse(ctx, access)
	require.NoError(t, err)

	assert.NotEmpty(t, token.GetAccessToken())
	assert.NotEmpty(t, token.GetExtra(consts.AccessResponseIDToken))
}
