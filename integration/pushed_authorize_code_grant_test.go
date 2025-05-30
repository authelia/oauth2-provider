// Copyright © 2023 Ory Corp
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
)

func TestPushedAuthorizeCodeFlow(t *testing.T) {
	for _, strategy := range []hoauth2.AccessTokenStrategy{
		hmacStrategy,
	} {
		runPushedAuthorizeCodeGrantTest(t, strategy)
	}
}

func runPushedAuthorizeCodeGrantTest(t *testing.T, strategy any) {
	f := compose.Compose(new(oauth2.Config), store, strategy, compose.OAuth2AuthorizeExplicitFactory, compose.OAuth2TokenIntrospectionFactory, compose.PushedAuthorizeHandlerFactory)
	ts := mockServer(t, f, &oauth2.DefaultSession{Subject: "foo-sub"})

	defer ts.Close()

	oauthClient := newOAuth2Client(ts)
	store.Clients["my-client"].(*oauth2.DefaultClient).RedirectURIs[0] = ts.URL + "/callback"

	var state string

	for k, c := range []struct {
		description    string
		setup          func()
		check          func(t *testing.T, r *http.Response)
		params         map[string]string
		authStatusCode int
		parStatusCode  int
	}{
		{
			description: "should fail because of audience",
			params:      map[string]string{consts.FormParameterAudience: "https://www.authelia.com/not-api"},
			setup: func() {
				oauthClient = newOAuth2Client(ts)
				state = testState
			},
			parStatusCode:  http.StatusBadRequest,
			authStatusCode: http.StatusNotAcceptable,
		},
		{
			description: "should fail because of scope",
			params:      nil,
			setup: func() {
				oauthClient = newOAuth2Client(ts)
				oauthClient.Scopes = []string{"not-exist"}
				state = testState
			},
			parStatusCode:  http.StatusBadRequest,
			authStatusCode: http.StatusNotAcceptable,
		},
		{
			description: "should pass with proper audience",
			params:      map[string]string{consts.FormParameterAudience: "https://www.authelia.com/api"},
			setup: func() {
				oauthClient = newOAuth2Client(ts)
				state = testState
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
			parStatusCode:  http.StatusCreated,
			authStatusCode: http.StatusOK,
		},
		{
			description: "should pass",
			setup: func() {
				oauthClient = newOAuth2Client(ts)
				state = testState
			},
			parStatusCode:  http.StatusCreated,
			authStatusCode: http.StatusOK,
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, c.description), func(t *testing.T) {
			c.setup()

			// build request from the OAuth client
			data := url.Values{}
			data.Set(consts.FormParameterClientID, oauthClient.ClientID)
			data.Set(consts.FormParameterClientSecret, oauthClient.ClientSecret)
			data.Set(consts.FormParameterResponseType, consts.ResponseTypeAuthorizationCodeFlow)
			data.Set(consts.FormParameterState, state)
			data.Set(consts.FormParameterScope, strings.Join(oauthClient.Scopes, " "))
			data.Set(consts.FormParameterRedirectURI, oauthClient.RedirectURL)
			for k, v := range c.params {
				data.Set(k, v)
			}

			req, err := http.NewRequest("POST", ts.URL+"/par", strings.NewReader(data.Encode()))
			require.NoError(t, err)

			req.Header.Add(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
			resp, err := http.DefaultClient.Do(req)

			require.NoError(t, err)

			body, err := checkStatusAndGetBody(t, resp, c.parStatusCode)
			require.NoError(t, err, "Unable to get body after PAR. Err=%v", err)

			if resp.StatusCode != http.StatusCreated {
				return
			}

			m := map[string]any{}
			err = json.Unmarshal(body, &m)

			assert.NoError(t, err, "Error occurred when unamrshaling the body: %v", err)

			// validate request_uri
			requestURI, _ := m[consts.FormParameterRequestURI].(string)
			assert.NotEmpty(t, requestURI, "request_uri is empty")
			assert.Condition(t, func() bool {
				return strings.HasPrefix(requestURI, consts.PrefixRequestURI)
			}, "PAR Prefix is incorrect: %s", requestURI)

			// validate expires_in
			assert.EqualValues(t, 300, int(m[consts.AccessResponseExpiresIn].(float64)), "Invalid expires_in value=%v", m[consts.AccessResponseExpiresIn])

			// call authorize
			data = url.Values{}
			data.Set(consts.FormParameterClientID, oauthClient.ClientID)
			data.Set(consts.FormParameterRequestURI, m[consts.FormParameterRequestURI].(string))
			req, err = http.NewRequest("POST", ts.URL+"/auth", strings.NewReader(data.Encode()))
			require.NoError(t, err)

			req.Header.Add(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)

			resp, err = http.DefaultClient.Do(req)
			require.NoError(t, err)
			require.Equal(t, c.authStatusCode, resp.StatusCode)
			if resp.StatusCode != http.StatusOK {
				return
			}

			require.NotEmpty(t, resp.Request.URL.Query().Get("code"), "Auth code is empty")

			token, err := oauthClient.Exchange(t.Context(), resp.Request.URL.Query().Get("code"))
			require.NoError(t, err)
			require.NotEmpty(t, token.AccessToken)

			httpClient := oauthClient.Client(t.Context(), token)
			resp, err = httpClient.Get(ts.URL + "/info")
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)

			if c.check != nil {
				c.check(t, resp)
			}
		})
	}
}

func checkStatusAndGetBody(t *testing.T, resp *http.Response, expectedStatusCode int) ([]byte, error) {
	defer resp.Body.Close()

	require.Equal(t, expectedStatusCode, resp.StatusCode)

	b, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)

	if expectedStatusCode != resp.StatusCode {
		return nil, fmt.Errorf("Invalid status code %d", resp.StatusCode)
	}

	return b, err
}
