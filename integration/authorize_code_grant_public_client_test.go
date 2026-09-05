// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xoauth2 "golang.org/x/oauth2"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestAuthorizeCodeFlowWithPublicClient(t *testing.T) {
	for _, strategy := range []hoauth2.AccessTokenStrategy{
		hmacStrategy,
	} {
		runAuthorizeCodeGrantWithPublicClientTest(t, strategy)
	}
}

func runAuthorizeCodeGrantWithPublicClientTest(t *testing.T, strategy any) {
	f := compose.Compose(new(oauth2.Config), store, strategy, compose.OAuth2AuthorizeExplicitFactory, compose.OAuth2TokenIntrospectionFactory)
	ts := mockServer(t, f, &oauth2.DefaultSession{Subject: "foo-sub"})
	defer ts.Close()

	oauthClient := newOAuth2Client(ts)
	oauthClient.ClientSecret = ""
	oauthClient.ClientID = testClientIDPublic
	store.Clients[testClientIDPublic].(*oauth2.DefaultClient).RedirectURIs[0] = ts.URL + "/callback"

	var state string
	testCases := []struct {
		name           string
		setup          func()
		check          func(t *testing.T, r *http.Response)
		params         []xoauth2.AuthCodeOption
		authStatusCode int
	}{
		{
			name:   "should fail because of audience",
			params: []xoauth2.AuthCodeOption{xoauth2.SetAuthURLParam("audience", "https://www.authelia.com/not-api")},
			setup: func() {
				state = testState
			},
			authStatusCode: http.StatusNotAcceptable,
		},
		{
			name:   "should fail because of scope",
			params: []xoauth2.AuthCodeOption{},
			setup: func() {
				oauthClient.Scopes = []string{"not-exist"}
				state = testState
			},
			authStatusCode: http.StatusNotAcceptable,
		},
		{
			name:   "should pass with proper audience",
			params: []xoauth2.AuthCodeOption{xoauth2.SetAuthURLParam("audience", "https://www.authelia.com/api")},
			setup: func() {
				state = testState
				oauthClient.Scopes = []string{"oauth2"}
			},
			check: func(t *testing.T, r *http.Response) {
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
			name: "should pass",
			setup: func() {
				state = testState
			},
			authStatusCode: http.StatusOK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup()

			resp, err := http.Get(oauthClient.AuthCodeURL(state, tc.params...))
			require.NoError(t, err)
			require.Equal(t, tc.authStatusCode, resp.StatusCode)

			if resp.StatusCode == http.StatusOK {
				token, err := oauthClient.Exchange(t.Context(), resp.Request.URL.Query().Get(consts.FormParameterAuthorizationCode))
				require.NoError(t, err)
				require.NotEmpty(t, token.AccessToken)

				httpClient := oauthClient.Client(t.Context(), token)
				resp, err := httpClient.Get(ts.URL + "/info")
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode)

				if tc.check != nil {
					tc.check(t, resp)
				}
			}
		})
	}
}
