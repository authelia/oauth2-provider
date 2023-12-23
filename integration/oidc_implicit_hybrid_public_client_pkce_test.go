// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xoauth2 "golang.org/x/oauth2"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestOIDCImplicitFlowPublicClientPKCE(t *testing.T) {
	testCases := []struct {
		name      string
		have      string
		state     string
		nonce     string
		setup     func(t *testing.T)
		challenge string
		verifier  string
	}{
		{
			name:      "should pass id token (id_token code) with PKCE applied.",
			have:      consts.ResponseTypeHybridFlowIDToken,
			state:     "12345678901234567890",
			nonce:     "1111111111111111",
			setup:     nil,
			challenge: "J11vOtKUitab04a_N0Ogm0dQBytTgl0fgHzYk4xUryo",
			verifier:  "e7343b9bee0847e3b589ccb60d124ff81adcba6067b84f79b092f86249111fdc",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			session := &defaultSession{
				DefaultSession: &openid.DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "peter",
					},
					Headers: &jwt.Headers{},
				},
			}
			f := compose.ComposeAllEnabled(&oauth2.Config{
				GlobalSecret: []byte("some-secret-thats-random-some-secret-thats-random-"),
			}, store, gen.MustRSAKey())
			ts := mockServer(t, f, session)
			defer ts.Close()

			oauthClient := newOAuth2Client(ts)

			oauthClient.ClientSecret = ""
			oauthClient.ClientID = "public-client"
			oauthClient.Scopes = []string{consts.ScopeOpenID}

			store.Clients["public-client"].(*oauth2.DefaultClient).RedirectURIs[0] = ts.URL + "/callback"

			if tc.setup != nil {
				tc.setup(t)
			}

			var callbackURL *url.URL

			authURL := oauthClient.AuthCodeURL(
				tc.state,
				xoauth2.SetAuthURLParam(consts.FormParameterResponseType, tc.have),
				xoauth2.SetAuthURLParam(consts.FormParameterNonce, tc.nonce),
				xoauth2.SetAuthURLParam(consts.FormParameterCodeChallengeMethod, consts.PKCEChallengeMethodSHA256),
				xoauth2.SetAuthURLParam(consts.FormParameterCodeChallenge, tc.challenge),
			)

			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					callbackURL = req.URL
					return errors.New("Dont follow redirects")
				},
			}

			response, err := client.Get(authURL)
			require.Error(t, err)
			assert.NotNil(t, response)

			fragment, err := url.ParseQuery(callbackURL.Fragment)
			require.NoError(t, err)

			code := fragment.Get(consts.FormParameterAuthorizationCode)
			assert.NotEmpty(t, code)

			assert.NotEmpty(t, fragment.Get(consts.AccessResponseIDToken))

			response, err = http.PostForm(oauthClient.Endpoint.TokenURL, url.Values{
				consts.FormParameterAuthorizationCode: {code},
				consts.FormParameterGrantType:         {consts.GrantTypeAuthorizationCode},
				consts.FormParameterClientID:          {"public-client"},
				consts.FormParameterRedirectURI:       {ts.URL + "/callback"},
				consts.FormParameterCodeVerifier:      {tc.verifier},
			})

			require.NoError(t, err)

			defer response.Body.Close()

			body, err := io.ReadAll(response.Body)
			require.NoError(t, err)

			assert.Equal(t, response.StatusCode, http.StatusOK)
			token := xoauth2.Token{}
			require.NoError(t, json.Unmarshal(body, &token))

			require.NotEmpty(t, token.AccessToken, "Got body: %s", string(body))
		})
	}
}
