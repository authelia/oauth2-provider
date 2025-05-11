// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
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
	xoauth2 "golang.org/x/oauth2"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestClientCredentialsFlow(t *testing.T) {
	for _, strategy := range []hoauth2.AccessTokenStrategy{
		hmacStrategy,
	} {
		runClientCredentialsGrantTest(t, strategy)
	}
}

func introspect(t *testing.T, ts *httptest.Server, token string, p any, username, password string) {
	req, err := http.NewRequest("POST", ts.URL+"/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
	require.NoError(t, err)
	req.SetBasicAuth(username, password)
	req.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
	r, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, r.StatusCode, "%s", body)
	require.NoError(t, json.Unmarshal(body, p))
}

func runClientCredentialsGrantTest(t *testing.T, strategy hoauth2.AccessTokenStrategy) {
	f := compose.Compose(new(oauth2.Config), store, strategy, compose.OAuth2ClientCredentialsGrantFactory, compose.OAuth2TokenIntrospectionFactory)
	ts := mockServer(t, f, &oauth2.DefaultSession{})
	defer ts.Close()

	oauthClient := newOAuth2AppClient(ts)
	store.Clients["my-client"].(*oauth2.DefaultClient).RedirectURIs[0] = ts.URL + "/callback"
	store.Clients[testClientIDLifespan].(*oauth2.DefaultClientWithCustomTokenLifespans).RedirectURIs[0] = ts.URL + "/callback"
	for k, c := range []struct {
		description string
		setup       func()
		err         bool
		check       func(t *testing.T, token *xoauth2.Token)
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
			params:      url.Values{"audience": {"https://www.authelia.com/not-api"}},
			setup: func() {
				oauthClient.Scopes = []string{"oauth2"}
			},
			err: true,
		},
		{
			params:      url.Values{"audience": {"https://www.authelia.com/api"}},
			description: "should pass",
			setup: func() {
			},
			check: func(t *testing.T, token *xoauth2.Token) {
				var j json.RawMessage
				introspect(t, ts, token.AccessToken, &j, oauthClient.ClientID, oauthClient.ClientSecret)
				assert.Equal(t, oauthClient.ClientID, gjson.GetBytes(j, consts.ClaimClientIdentifier).String())
				assert.Equal(t, "oauth2", gjson.GetBytes(j, consts.ClaimScope).String())
			},
		},
		{
			description: "should pass",
			setup: func() {
			},
			check: func(t *testing.T, token *xoauth2.Token) {
				var j json.RawMessage
				introspect(t, ts, token.AccessToken, &j, oauthClient.ClientID, oauthClient.ClientSecret)
				introspect(t, ts, token.AccessToken, &j, oauthClient.ClientID, oauthClient.ClientSecret)
				assert.Equal(t, oauthClient.ClientID, gjson.GetBytes(j, consts.ClaimClientIdentifier).String())
				assert.Equal(t, "oauth2", gjson.GetBytes(j, consts.ClaimScope).String())
				atReq, ok := store.AccessTokens[strings.Split(token.AccessToken, ".")[1]]
				require.True(t, ok)
				atExp := atReq.GetSession().GetExpiresAt(oauth2.AccessToken)
				internal.RequireEqualTime(t, time.Now().UTC().Add(time.Hour), atExp, time.Minute)
				atExpIn := time.Duration(token.Extra(consts.AccessResponseExpiresIn).(float64)) * time.Second
				internal.RequireEqualDuration(t, time.Hour, atExpIn, time.Minute)
			},
		},
		{
			description: "should pass with custom client token lifespans",
			setup: func() {
				oauthClient.ClientID = testClientIDLifespan
			},
			check: func(t *testing.T, token *xoauth2.Token) {
				var j json.RawMessage
				introspect(t, ts, token.AccessToken, &j, oauthClient.ClientID, oauthClient.ClientSecret)
				introspect(t, ts, token.AccessToken, &j, oauthClient.ClientID, oauthClient.ClientSecret)
				assert.Equal(t, oauthClient.ClientID, gjson.GetBytes(j, consts.ClaimClientIdentifier).String())
				assert.Equal(t, "oauth2", gjson.GetBytes(j, consts.ClaimScope).String())

				atReq, ok := store.AccessTokens[strings.Split(token.AccessToken, ".")[1]]
				require.True(t, ok)
				atExp := atReq.GetSession().GetExpiresAt(oauth2.AccessToken)
				internal.RequireEqualTime(t, time.Now().UTC().Add(*internal.TestLifespans.ClientCredentialsGrantAccessTokenLifespan), atExp, time.Minute)
				atExpIn := time.Duration(token.Extra(consts.AccessResponseExpiresIn).(float64)) * time.Second
				internal.RequireEqualDuration(t, *internal.TestLifespans.ClientCredentialsGrantAccessTokenLifespan, atExpIn, time.Minute)
				rtExp := atReq.GetSession().GetExpiresAt(oauth2.RefreshToken)
				internal.RequireEqualTime(t, time.Time{}, rtExp, time.Minute)
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			c.setup()

			oauthClient.EndpointParams = c.params
			token, err := oauthClient.Token(t.Context())
			require.Equal(t, c.err, err != nil, "(%d) %s\n%s\n%s", k, c.description, c.err, err)
			if !c.err {
				assert.NotEmpty(t, token.AccessToken, "(%d) %s\n%s", k, c.description, token)
			}

			if c.check != nil {
				c.check(t, token)
			}
		})
	}
}
