// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
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
	oauthClient.ClientID = "public-client"
	store.Clients["public-client"].(*oauth2.DefaultClient).RedirectURIs[0] = ts.URL + "/callback"

	var authCodeUrl string
	var verifier string
	for k, c := range []struct {
		description     string
		setup           func()
		authStatusCode  int
		tokenStatusCode int
	}{
		{
			description: "should fail because no challenge was given",
			setup: func() {
				authCodeUrl = oauthClient.AuthCodeURL("12345678901234567890")
			},
			authStatusCode: http.StatusNotAcceptable,
		},
		{
			description: "should pass",
			setup: func() {
				verifier = "somechallengesomechallengesomechallengesomechallengesomechallengesomechallenge"
				authCodeUrl = oauthClient.AuthCodeURL("12345678901234567890") + "&code_challenge=somechallengesomechallengesomechallengesomechallengesomechallengesomechallenge"
			},
			authStatusCode: http.StatusOK,
		},
		{
			description: "should fail because the verifier is mismatching",
			setup: func() {
				verifier = "failchallengefailchallengefailchallengefailchallengefailchallengefailchallengefailchallengefailchallenge"
				authCodeUrl = oauthClient.AuthCodeURL("12345678901234567890") + "&code_challenge=somechallengesomechallengesomechallengesomechallengesomechallengesomechallengesomechallengesomechallenge"
			},
			authStatusCode:  http.StatusOK,
			tokenStatusCode: http.StatusBadRequest,
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, c.description), func(t *testing.T) {
			c.setup()

			t.Logf("Got url: %s", authCodeUrl)

			resp, err := http.Get(authCodeUrl) //nolint:gosec
			require.NoError(t, err)
			require.Equal(t, resp.StatusCode, c.authStatusCode)

			if resp.StatusCode == http.StatusOK {
				// This should fail because no verifier was given
				// _, err := oauthClient.Exchange(xoauth2.NoContext, resp.Request.URL.Query().Get(consts.FormParameterAuthorizationCode))
				// require.Error(t, err)
				// require.Empty(t, token.AccessToken)
				t.Logf("Got redirect url: %s", resp.Request.URL)

				resp, err := http.PostForm(ts.URL+"/token", url.Values{
					consts.FormParameterAuthorizationCode: {resp.Request.URL.Query().Get(consts.FormParameterAuthorizationCode)},
					consts.FormParameterGrantType:         {consts.GrantTypeAuthorizationCode},
					consts.FormParameterClientID:          {"public-client"},
					consts.FormParameterRedirectURI:       {ts.URL + "/callback"},
					consts.FormParameterCodeVerifier:      {verifier},
				})
				require.NoError(t, err)
				defer resp.Body.Close()

				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)

				if c.tokenStatusCode != 0 {
					require.Equal(t, c.tokenStatusCode, resp.StatusCode)
					token := xoauth2.Token{}
					require.NoError(t, json.Unmarshal(body, &token))
					require.Empty(t, token.AccessToken)
					return
				}

				assert.Equal(t, resp.StatusCode, http.StatusOK)
				token := xoauth2.Token{}
				require.NoError(t, json.Unmarshal(body, &token))

				require.NotEmpty(t, token.AccessToken, "Got body: %s", string(body))

				httpClient := oauthClient.Client(context.TODO(), &token)
				resp, err = httpClient.Get(ts.URL + "/info")
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode)
			}
		})
	}
}
