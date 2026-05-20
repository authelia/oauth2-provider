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
	"time"

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

	testCases := []struct {
		name           string
		setup          func()
		check          func(t *testing.T, r *http.Response)
		tamperPAR      func(t *testing.T, requester oauth2.AuthorizeRequester)
		params         map[string]string
		authStatusCode int
		parStatusCode  int
	}{
		{
			name:   "ShouldNotPassWithInvalidAudience",
			params: map[string]string{consts.FormParameterAudience: "https://www.authelia.com/not-api"},
			setup: func() {
				oauthClient = newOAuth2Client(ts)
				state = testState
			},
			parStatusCode:  http.StatusBadRequest,
			authStatusCode: http.StatusNotAcceptable,
		},
		{
			name:   "ShouldNotPassWithInvalidScope",
			params: nil,
			setup: func() {
				oauthClient = newOAuth2Client(ts)
				oauthClient.Scopes = []string{"not-exist"}
				state = testState
			},
			parStatusCode:  http.StatusBadRequest,
			authStatusCode: http.StatusNotAcceptable,
		},
		{
			name:   "ShouldPassWithValidAudience",
			params: map[string]string{consts.FormParameterAudience: "https://www.authelia.com/api"},
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
			name: "ShouldPass",
			setup: func() {
				oauthClient = newOAuth2Client(ts)
				state = testState
			},
			parStatusCode:  http.StatusCreated,
			authStatusCode: http.StatusOK,
		},
		{
			name: "ShouldNotPassWithExpiredPARSession",
			setup: func() {
				oauthClient = newOAuth2Client(ts)
				state = testState
			},
			tamperPAR: func(t *testing.T, requester oauth2.AuthorizeRequester) {
				require.NotNil(t, requester, "PAR session should exist in the store")
				requester.GetSession().SetExpiresAt(oauth2.PushedAuthorizeRequestContext, time.Now().Add(-time.Hour))
			},
			parStatusCode:  http.StatusCreated,
			authStatusCode: http.StatusNotAcceptable,
		},
		{
			name: "ShouldNotPassWithMissingPARSession",
			setup: func() {
				oauthClient = newOAuth2Client(ts)
				state = testState
			},
			tamperPAR: func(t *testing.T, requester oauth2.AuthorizeRequester) {
				require.NotNil(t, requester, "PAR session should exist in the store")
				requester.SetSession(nil)
			},
			parStatusCode:  http.StatusCreated,
			authStatusCode: http.StatusNotAcceptable,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup()

			data := url.Values{}
			data.Set(consts.FormParameterClientID, oauthClient.ClientID)
			data.Set(consts.FormParameterClientSecret, oauthClient.ClientSecret)
			data.Set(consts.FormParameterResponseType, consts.ResponseTypeAuthorizationCodeFlow)
			data.Set(consts.FormParameterState, state)
			data.Set(consts.FormParameterScope, strings.Join(oauthClient.Scopes, " "))
			data.Set(consts.FormParameterRedirectURI, oauthClient.RedirectURL)
			for k, v := range tc.params {
				data.Set(k, v)
			}

			req, err := http.NewRequest("POST", ts.URL+"/par", strings.NewReader(data.Encode()))
			require.NoError(t, err)

			req.Header.Add(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
			resp, err := http.DefaultClient.Do(req)

			require.NoError(t, err)

			body, err := checkStatusAndGetBody(t, resp, tc.parStatusCode)
			require.NoError(t, err, "Unable to get body after PAR. Err=%v", err)

			if resp.StatusCode != http.StatusCreated {
				return
			}

			m := map[string]any{}
			err = json.Unmarshal(body, &m)

			assert.NoError(t, err, "Error occurred when unamrshaling the body: %v", err)

			requestURI, _ := m[consts.FormParameterRequestURI].(string)
			assert.NotEmpty(t, requestURI, "request_uri is empty")
			assert.Condition(t, func() bool {
				return strings.HasPrefix(requestURI, consts.PrefixRequestURI)
			}, "PAR Prefix is incorrect: %s", requestURI)

			assert.EqualValues(t, 300, int(m[consts.AccessResponseExpiresIn].(float64)), "Invalid expires_in value=%v", m[consts.AccessResponseExpiresIn])

			if tc.tamperPAR != nil {
				tc.tamperPAR(t, store.PARSessions[requestURI])
			}

			data = url.Values{}
			data.Set(consts.FormParameterClientID, oauthClient.ClientID)
			data.Set(consts.FormParameterRequestURI, m[consts.FormParameterRequestURI].(string))
			req, err = http.NewRequest("POST", ts.URL+"/auth", strings.NewReader(data.Encode()))
			require.NoError(t, err)

			req.Header.Add(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)

			resp, err = http.DefaultClient.Do(req)
			require.NoError(t, err)
			require.Equal(t, tc.authStatusCode, resp.StatusCode)
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

			if tc.check != nil {
				tc.check(t, resp)
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
