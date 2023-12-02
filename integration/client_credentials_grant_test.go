// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
	goauth "golang.org/x/oauth2"

	"github.com/authelia/goauth2"
	"github.com/authelia/goauth2/compose"
	"github.com/authelia/goauth2/handler/oauth2"
	"github.com/authelia/goauth2/internal"
)

func TestClientCredentialsFlow(t *testing.T) {
	for _, strategy := range []oauth2.AccessTokenStrategy{
		hmacStrategy,
	} {
		runClientCredentialsGrantTest(t, strategy)
	}
}

func introspect(t *testing.T, ts *httptest.Server, token string, p interface{}, username, password string) {
	req, err := http.NewRequest("POST", ts.URL+"/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
	require.NoError(t, err)
	req.SetBasicAuth(username, password)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, r.StatusCode, "%s", body)
	require.NoError(t, json.Unmarshal(body, p))
}

func runClientCredentialsGrantTest(t *testing.T, strategy oauth2.AccessTokenStrategy) {
	f := compose.Compose(new(goauth2.Config), fositeStore, strategy, compose.OAuth2ClientCredentialsGrantFactory, compose.OAuth2TokenIntrospectionFactory)
	ts := mockServer(t, f, &goauth2.DefaultSession{})
	defer ts.Close()

	oauthClient := newOAuth2AppClient(ts)
	fositeStore.Clients["my-client"].(*goauth2.DefaultClient).RedirectURIs[0] = ts.URL + "/callback"
	fositeStore.Clients["custom-lifespan-client"].(*goauth2.DefaultClientWithCustomTokenLifespans).RedirectURIs[0] = ts.URL + "/callback"
	for k, c := range []struct {
		description string
		setup       func()
		err         bool
		check       func(t *testing.T, token *goauth.Token)
		params      url.Values
	}{
		{
			description: "should fail because of ungranted scopes",
			setup: func() {
				oauthClient.Scopes = []string{"unknown"}
			},
			err: true,
		},
		{
			description: "should fail because of ungranted audience",
			params:      url.Values{"audience": {"https://www.ory.sh/not-api"}},
			setup: func() {
				oauthClient.Scopes = []string{"goauth2"}
			},
			err: true,
		},
		{
			params:      url.Values{"audience": {"https://www.ory.sh/api"}},
			description: "should pass",
			setup: func() {
			},
			check: func(t *testing.T, token *goauth.Token) {
				var j json.RawMessage
				introspect(t, ts, token.AccessToken, &j, oauthClient.ClientID, oauthClient.ClientSecret)
				assert.Equal(t, oauthClient.ClientID, gjson.GetBytes(j, "client_id").String())
				assert.Equal(t, "goauth2", gjson.GetBytes(j, "scope").String())
			},
		},
		{
			description: "should pass",
			setup: func() {
			},
			check: func(t *testing.T, token *goauth.Token) {
				var j json.RawMessage
				introspect(t, ts, token.AccessToken, &j, oauthClient.ClientID, oauthClient.ClientSecret)
				introspect(t, ts, token.AccessToken, &j, oauthClient.ClientID, oauthClient.ClientSecret)
				assert.Equal(t, oauthClient.ClientID, gjson.GetBytes(j, "client_id").String())
				assert.Equal(t, "goauth2", gjson.GetBytes(j, "scope").String())
				atReq, ok := fositeStore.AccessTokens[strings.Split(token.AccessToken, ".")[1]]
				require.True(t, ok)
				atExp := atReq.GetSession().GetExpiresAt(goauth2.AccessToken)
				internal.RequireEqualTime(t, time.Now().UTC().Add(time.Hour), atExp, time.Minute)
				atExpIn := time.Duration(token.Extra("expires_in").(float64)) * time.Second
				internal.RequireEqualDuration(t, time.Hour, atExpIn, time.Minute)
			},
		},
		{
			description: "should pass with custom client token lifespans",
			setup: func() {
				oauthClient.ClientID = "custom-lifespan-client"
			},
			check: func(t *testing.T, token *goauth.Token) {
				var j json.RawMessage
				introspect(t, ts, token.AccessToken, &j, oauthClient.ClientID, oauthClient.ClientSecret)
				introspect(t, ts, token.AccessToken, &j, oauthClient.ClientID, oauthClient.ClientSecret)
				assert.Equal(t, oauthClient.ClientID, gjson.GetBytes(j, "client_id").String())
				assert.Equal(t, "goauth2", gjson.GetBytes(j, "scope").String())

				atReq, ok := fositeStore.AccessTokens[strings.Split(token.AccessToken, ".")[1]]
				require.True(t, ok)
				atExp := atReq.GetSession().GetExpiresAt(goauth2.AccessToken)
				internal.RequireEqualTime(t, time.Now().UTC().Add(*internal.TestLifespans.ClientCredentialsGrantAccessTokenLifespan), atExp, time.Minute)
				atExpIn := time.Duration(token.Extra("expires_in").(float64)) * time.Second
				internal.RequireEqualDuration(t, *internal.TestLifespans.ClientCredentialsGrantAccessTokenLifespan, atExpIn, time.Minute)
				rtExp := atReq.GetSession().GetExpiresAt(goauth2.RefreshToken)
				internal.RequireEqualTime(t, time.Time{}, rtExp, time.Minute)
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			c.setup()

			oauthClient.EndpointParams = c.params
			token, err := oauthClient.Token(context.TODO())
			require.Equal(t, c.err, err != nil, "(%d) %s\n%s\n%s", k, c.description, c.err, err)
			if !c.err {
				assert.NotEmpty(t, token.AccessToken, "(%d) %s\n%s", k, c.description, token)
			}

			if c.check != nil {
				c.check(t, token)
			}

			t.Logf("Passed test case %d", k)
		})
	}
}
