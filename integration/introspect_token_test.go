// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestIntrospectToken(t *testing.T) {
	config := &oauth2.Config{
		GlobalSecret:                  []byte("some-super-cool-secret-that-nobody-knows"),
		EnforceJWTProfileAccessTokens: true,
	}

	strategy := &jwt.DefaultStrategy{
		Config: config,
		Issuer: jwt.NewDefaultIssuerRS256Unverified(defaultRSAKey),
	}

	for _, c := range []struct {
		description string
		strategy    hoauth2.AccessTokenStrategy
		factory     compose.Factory
	}{
		{
			description: "HMAC strategy with OAuth2TokenIntrospectionFactory",
			strategy:    hoauth2.NewCoreStrategy(config, "authelia_%s_", nil),
			factory:     compose.OAuth2TokenIntrospectionFactory,
		},
		{
			description: "JWT strategy with OAuth2TokenIntrospectionFactory",
			strategy:    hoauth2.NewCoreStrategy(config, "authelia_%s_", strategy),
			factory:     compose.OAuth2TokenIntrospectionFactory,
		},
		{
			description: "JWT strategy with OAuth2StatelessJWTIntrospectionFactory",
			strategy:    hoauth2.NewCoreStrategy(config, "authelia_%s_", strategy),
			factory:     compose.OAuth2StatelessJWTIntrospectionFactory,
		},
	} {
		runIntrospectTokenTest(t, c.strategy, c.factory)
	}
}

func runIntrospectTokenTest(t *testing.T, strategy hoauth2.AccessTokenStrategy, introspectionFactory compose.Factory) {
	f := compose.Compose(new(oauth2.Config), store, strategy, compose.OAuth2ClientCredentialsGrantFactory, introspectionFactory)
	ts := mockServer(t, f, &oauth2.DefaultSession{})
	defer ts.Close()

	oauthClient := newOAuth2AppClient(ts)
	a, err := oauthClient.Token(t.Context())
	require.NoError(t, err)
	b, err := oauthClient.Token(t.Context())
	require.NoError(t, err)

	for k, c := range []struct {
		prepare  func(r *http.Request)
		isActive bool
		scopes   string
	}{
		{
			prepare: func(r *http.Request) {
				r.SetBasicAuth(oauthClient.ClientID, oauthClient.ClientSecret)
			},
			isActive: true,
			scopes:   "",
		},
		{
			prepare: func(r *http.Request) {
				r.Header.Set(consts.HeaderAuthorization, "bearer "+a.AccessToken)
			},
			isActive: true,
			scopes:   "oauth2",
		},
		{
			prepare: func(r *http.Request) {
				r.Header.Set(consts.HeaderAuthorization, "bearer "+a.AccessToken)
			},
			isActive: true,
			scopes:   "",
		},
		{
			prepare: func(r *http.Request) {
				r.Header.Set(consts.HeaderAuthorization, "bearer "+a.AccessToken)
			},
			isActive: false,
			scopes:   "foo",
		},
		{
			prepare: func(r *http.Request) {
				r.Header.Set(consts.HeaderAuthorization, "bearer "+b.AccessToken)
			},
			isActive: false,
			scopes:   "",
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			res := struct {
				Active    bool    `json:"active"`
				ClientId  string  `json:"client_id"`
				Scope     string  `json:"scope"`
				ExpiresAt float64 `json:"exp"`
				IssuedAt  float64 `json:"iat"`
			}{}

			data := url.Values{
				consts.FormParameterToken: {b.AccessToken},
				consts.FormParameterScope: {c.scopes},
			}

			req, err := http.NewRequest(http.MethodPost, ts.URL+"/introspect", strings.NewReader(data.Encode()))
			require.NoError(t, err)

			req.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
			c.prepare(req)

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())

			require.NoError(t, json.Unmarshal(body, &res))

			assert.Equal(t, c.isActive, res.Active)
			if c.isActive {
				assert.Equal(t, "oauth2", res.Scope)
				assert.True(t, res.ExpiresAt > 0)
				assert.True(t, res.IssuedAt > 0)
				assert.True(t, res.IssuedAt < res.ExpiresAt)
			}
		})
	}
}
