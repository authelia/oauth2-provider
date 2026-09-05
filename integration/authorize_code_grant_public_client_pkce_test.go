// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xoauth2 "golang.org/x/oauth2"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestAuthorizeCodeFlowWithPublicClientAndPKCE(t *testing.T) {
	for _, strategy := range []hoauth2.AccessTokenStrategy{
		hmacStrategy,
	} {
		runAuthorizeCodeGrantWithPublicClientAndPKCETest(t, strategy)
	}
}

func runAuthorizeCodeGrantWithPublicClientAndPKCETest(t *testing.T, strategy any) {
	c := new(oauth2.Config)
	c.EnforcePKCE = true
	c.EnablePKCEPlainChallengeMethod = true
	provider := compose.Compose(c, store, strategy, compose.OAuth2AuthorizeExplicitFactory, compose.OAuth2PKCEFactory, compose.OAuth2TokenIntrospectionFactory)
	ts := mockServer(t, provider, &oauth2.DefaultSession{})
	defer ts.Close()

	oauthClient := newOAuth2Client(ts)
	oauthClient.ClientSecret = ""
	oauthClient.ClientID = testClientIDPublic
	store.Clients[testClientIDPublic].(*oauth2.DefaultClient).RedirectURIs[0] = ts.URL + "/callback"

	var authCodeUrl string
	var verifier string
	testCases := []struct {
		name            string
		setup           func()
		authStatusCode  int
		tokenStatusCode int
	}{
		{
			name: "should fail because no challenge was given",
			setup: func() {
				authCodeUrl = oauthClient.AuthCodeURL(testState)
			},
			authStatusCode: http.StatusNotAcceptable,
		},
		{
			name: "should pass",
			setup: func() {
				verifier = "somechallengesomechallengesomechallengesomechallengesomechallengesomechallenge"
				authCodeUrl = oauthClient.AuthCodeURL(testState) + "&code_challenge=somechallengesomechallengesomechallengesomechallengesomechallengesomechallenge"
			},
			authStatusCode: http.StatusOK,
		},
		{
			name: "should fail because the verifier is mismatching",
			setup: func() {
				verifier = "failchallengefailchallengefailchallengefailchallengefailchallengefailchallengefailchallengefailchallenge"
				authCodeUrl = oauthClient.AuthCodeURL(testState) + "&code_challenge=somechallengesomechallengesomechallengesomechallengesomechallengesomechallengesomechallengesomechallenge"
			},
			authStatusCode:  http.StatusOK,
			tokenStatusCode: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup()

			resp, err := http.Get(authCodeUrl) //nolint:gosec
			require.NoError(t, err)
			require.Equal(t, resp.StatusCode, tc.authStatusCode)

			if resp.StatusCode == http.StatusOK {
				tokenResp, err := http.PostForm(ts.URL+"/token", url.Values{
					consts.FormParameterAuthorizationCode: {resp.Request.URL.Query().Get(consts.FormParameterAuthorizationCode)},
					consts.FormParameterGrantType:         {consts.GrantTypeAuthorizationCode},
					consts.FormParameterClientID:          {testClientIDPublic},
					consts.FormParameterRedirectURI:       {ts.URL + "/callback"},
					consts.FormParameterCodeVerifier:      {verifier},
				})
				require.NoError(t, err)
				defer tokenResp.Body.Close()

				body, err := io.ReadAll(tokenResp.Body)
				require.NoError(t, err)

				if tc.tokenStatusCode != 0 {
					require.Equal(t, tc.tokenStatusCode, tokenResp.StatusCode)
					token := xoauth2.Token{}
					require.NoError(t, json.Unmarshal(body, &token))
					require.Empty(t, token.AccessToken)
					return
				}

				assert.Equal(t, tokenResp.StatusCode, http.StatusOK)
				token := xoauth2.Token{}
				require.NoError(t, json.Unmarshal(body, &token))

				require.NotEmpty(t, token.AccessToken, "Got body: %s", string(body))

				httpClient := oauthClient.Client(t.Context(), &token)
				resp, err = httpClient.Get(ts.URL + "/info")
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, tokenResp.StatusCode)
			}
		})
	}
}
