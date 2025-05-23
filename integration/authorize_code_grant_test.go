// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xoauth2 "golang.org/x/oauth2"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestAuthorizeCodeFlow(t *testing.T) {
	for _, strategy := range []hoauth2.AccessTokenStrategy{
		hmacStrategy,
	} {
		runAuthorizeCodeGrantTest(t, strategy)
	}
}

func TestAuthorizeCodeFlowDupeCode(t *testing.T) {
	for _, strategy := range []hoauth2.AccessTokenStrategy{
		hmacStrategy,
	} {
		runAuthorizeCodeGrantDupeCodeTest(t, strategy)
	}
}

func runAuthorizeCodeGrantTest(t *testing.T, strategy any) {
	f := compose.Compose(new(oauth2.Config), store, strategy, compose.OAuth2AuthorizeExplicitFactory, compose.OAuth2TokenIntrospectionFactory)
	ts := mockServer(t, f, &openid.DefaultSession{Subject: "foo-sub"})
	defer ts.Close()

	oauthClient := newOAuth2Client(ts)
	store.Clients["my-client"].(*oauth2.DefaultClient).RedirectURIs[0] = ts.URL + "/callback"
	store.Clients[testClientIDLifespan].(*oauth2.DefaultClientWithCustomTokenLifespans).RedirectURIs[0] = ts.URL + "/callback"

	var state string
	for k, c := range []struct {
		description    string
		setup          func()
		check          func(t *testing.T, r *http.Response, token *xoauth2.Token)
		params         []xoauth2.AuthCodeOption
		authStatusCode int
	}{
		{
			description: "should fail because of audience",
			params:      []xoauth2.AuthCodeOption{xoauth2.SetAuthURLParam("audience", "https://www.authelia.com/not-api")},
			setup: func() {
				oauthClient = newOAuth2Client(ts)
				state = testState
			},
			authStatusCode: http.StatusNotAcceptable,
		},
		{
			description: "should fail because of scope",
			params:      []xoauth2.AuthCodeOption{},
			setup: func() {
				oauthClient = newOAuth2Client(ts)
				oauthClient.Scopes = []string{"not-exist"}
				state = testState
			},
			authStatusCode: http.StatusNotAcceptable,
		},
		{
			description: "should pass with proper audience",
			params:      []xoauth2.AuthCodeOption{xoauth2.SetAuthURLParam("audience", "https://www.authelia.com/api")},
			setup: func() {
				oauthClient = newOAuth2Client(ts)
				state = testState
			},
			check: func(t *testing.T, r *http.Response, _ *xoauth2.Token) {
				var b oauth2.AccessRequest
				b.Client = new(oauth2.DefaultClient)
				b.Session = newDefaultSession()
				require.NoError(t, json.NewDecoder(r.Body).Decode(&b))
				assert.EqualValues(t, oauth2.Arguments{"https://www.authelia.com/api"}, b.RequestedAudience)
				assert.EqualValues(t, oauth2.Arguments{"https://www.authelia.com/api"}, b.GrantedAudience)
				assert.EqualValues(t, "foo-sub", b.Session.(*defaultSession).Subject)
			},
			authStatusCode: http.StatusOK,
		},
		{
			description: "should pass",
			setup: func() {
				oauthClient = newOAuth2Client(ts)
				state = testState
			},
			authStatusCode: http.StatusOK,
		},
		{
			description: "should pass with custom client token lifespans",
			setup: func() {
				oauthClient = newOAuth2Client(ts)
				oauthClient.ClientID = testClientIDLifespan
				oauthClient.Scopes = []string{"oauth2", consts.ScopeOffline}
				state = testState
			},
			check: func(t *testing.T, r *http.Response, token *xoauth2.Token) {
				var b oauth2.AccessRequest
				b.Client = new(oauth2.DefaultClient)
				b.Session = newDefaultSession()
				require.NoError(t, json.NewDecoder(r.Body).Decode(&b))
				atExp := b.Session.GetExpiresAt(oauth2.AccessToken)
				internal.RequireEqualTime(t, time.Now().UTC().Add(*internal.TestLifespans.AuthorizationCodeGrantAccessTokenLifespan), atExp, time.Minute)
				atExpIn := time.Duration(token.Extra(consts.AccessResponseExpiresIn).(float64)) * time.Second
				internal.RequireEqualDuration(t, *internal.TestLifespans.AuthorizationCodeGrantAccessTokenLifespan, atExpIn, time.Minute)
				rtExp := b.Session.GetExpiresAt(oauth2.RefreshToken)
				internal.RequireEqualTime(t, time.Now().UTC().Add(*internal.TestLifespans.AuthorizationCodeGrantRefreshTokenLifespan), rtExp, time.Minute)
			},
			authStatusCode: http.StatusOK,
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, c.description), func(t *testing.T) {
			c.setup()

			resp, err := http.Get(oauthClient.AuthCodeURL(state, c.params...))
			require.NoError(t, err)
			require.Equal(t, c.authStatusCode, resp.StatusCode)

			if resp.StatusCode == http.StatusOK {
				token, err := oauthClient.Exchange(t.Context(), resp.Request.URL.Query().Get(consts.FormParameterAuthorizationCode))
				require.NoError(t, err)
				require.NotEmpty(t, token.AccessToken)

				httpClient := oauthClient.Client(t.Context(), token)
				resp, err := httpClient.Get(ts.URL + "/info")
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode)

				if c.check != nil {
					c.check(t, resp, token)
				}
			}
		})
	}
}

func runAuthorizeCodeGrantDupeCodeTest(t *testing.T, strategy any) {
	f := compose.Compose(new(oauth2.Config), store, strategy, compose.OAuth2AuthorizeExplicitFactory, compose.OAuth2TokenIntrospectionFactory)
	ts := mockServer(t, f, &oauth2.DefaultSession{})
	defer ts.Close()

	client := newOAuth2Client(ts)
	store.Clients["my-client"].(*oauth2.DefaultClient).RedirectURIs[0] = ts.URL + "/callback"
	state := testState

	resp, err := http.Get(client.AuthCodeURL(state))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	token, err := client.Exchange(t.Context(), resp.Request.URL.Query().Get(consts.FormParameterAuthorizationCode))
	require.NoError(t, err)
	require.NotEmpty(t, token.AccessToken)

	req, err := http.NewRequest("GET", ts.URL+"/info", nil)
	require.NoError(t, err)
	req.Header.Set(consts.HeaderAuthorization, "Bearer "+token.AccessToken)

	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	_, err = client.Exchange(t.Context(), resp.Request.URL.Query().Get(consts.FormParameterAuthorizationCode))
	require.Error(t, err)

	resp, err = http.DefaultClient.Get(ts.URL + "/info")
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
