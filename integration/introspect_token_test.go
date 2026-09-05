// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"encoding/json"
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

	testCases := []struct {
		name     string
		strategy hoauth2.AccessTokenStrategy
		factory  compose.Factory
	}{
		{
			name:     "HMAC strategy with OAuth2TokenIntrospectionFactory",
			strategy: hoauth2.NewCoreStrategy(config, "authelia_%s_", nil),
			factory:  compose.OAuth2TokenIntrospectionFactory,
		},
		{
			name:     "JWT strategy with OAuth2TokenIntrospectionFactory",
			strategy: hoauth2.NewCoreStrategy(config, "authelia_%s_", strategy),
			factory:  compose.OAuth2TokenIntrospectionFactory,
		},
		{
			name:     "JWT strategy with OAuth2StatelessJWTIntrospectionFactory",
			strategy: hoauth2.NewCoreStrategy(config, "authelia_%s_", strategy),
			factory:  compose.OAuth2StatelessJWTIntrospectionFactory,
		},
	}

	for _, tc := range testCases {
		runIntrospectTokenTest(t, tc.strategy, tc.factory)
	}
}

func runIntrospectTokenTest(t *testing.T, strategy hoauth2.AccessTokenStrategy, introspectionFactory compose.Factory) {
	f := compose.Compose(&oauth2.Config{
		AllowedIntrospectionScopes:    []string{"oauth2"},
		AllowedIntrospectionAudiences: []string{tokenURL},
	}, store, strategy, compose.OAuth2ClientCredentialsGrantFactory, introspectionFactory)
	ts := mockServer(t, f, &oauth2.DefaultSession{})
	defer ts.Close()

	oauthClient := newOAuth2AppClient(ts)
	oauthClient.EndpointParams = url.Values{consts.FormParameterAudience: []string{tokenURL}}
	a, err := oauthClient.Token(t.Context())
	require.NoError(t, err)
	b, err := oauthClient.Token(t.Context())
	require.NoError(t, err)

	testCases := []struct {
		name     string
		prepare  func(r *http.Request)
		isActive bool
		scopes   string
	}{
		{
			name: "ShouldReportActiveForClientBasicAuth",
			prepare: func(r *http.Request) {
				r.SetBasicAuth(oauthClient.ClientID, oauthClient.ClientSecret)
			},
			isActive: true,
			scopes:   "",
		},
		{
			name: "ShouldReportActiveForABearerCallerAskingForAGrantedScope",
			prepare: func(r *http.Request) {
				r.Header.Set(consts.HeaderAuthorization, "bearer "+a.AccessToken)
			},
			isActive: true,
			scopes:   "oauth2",
		},
		{
			name: "ShouldReportActiveForABearerCallerAskingForNoScope",
			prepare: func(r *http.Request) {
				r.Header.Set(consts.HeaderAuthorization, "bearer "+a.AccessToken)
			},
			isActive: true,
			scopes:   "",
		},
		{
			name: "ShouldReportInactiveForAScopeTheTokenWasNotGranted",
			prepare: func(r *http.Request) {
				r.Header.Set(consts.HeaderAuthorization, "bearer "+a.AccessToken)
			},
			isActive: false,
			scopes:   "foo",
		},
		{
			name: "ShouldReportInactiveForATokenIssuedToAnotherClient",
			prepare: func(r *http.Request) {
				r.Header.Set(consts.HeaderAuthorization, "bearer "+b.AccessToken)
			},
			isActive: false,
			scopes:   "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res := struct {
				Active    bool    `json:"active"`
				ClientId  string  `json:"client_id"`
				Scope     string  `json:"scope"`
				ExpiresAt float64 `json:"exp"`
				IssuedAt  float64 `json:"iat"`
			}{}

			data := url.Values{
				consts.FormParameterToken: {b.AccessToken},
				consts.FormParameterScope: {tc.scopes},
			}

			req, err := http.NewRequest(http.MethodPost, ts.URL+"/introspect", strings.NewReader(data.Encode()))
			require.NoError(t, err)

			req.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
			tc.prepare(req)

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())

			require.NoError(t, json.Unmarshal(body, &res))

			assert.Equal(t, tc.isActive, res.Active)
			if tc.isActive {
				assert.Equal(t, "oauth2", res.Scope)
				assert.True(t, res.ExpiresAt > 0)
				assert.True(t, res.IssuedAt > 0)
				assert.True(t, res.IssuedAt < res.ExpiresAt)
			}
		})
	}
}
