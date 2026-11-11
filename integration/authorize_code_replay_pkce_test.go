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
	"authelia.com/provider/oauth2/internal/consts"
)

func TestAuthorizeCodeReplayByAPublicClientRequiresTheCodeVerifier(t *testing.T) {
	const (
		verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	)

	config := &oauth2.Config{EnforcePKCE: true}
	provider := compose.Compose(config, store, hmacStrategy, compose.OAuth2AuthorizeExplicitFactory, compose.OAuth2PKCEFactory, compose.OAuth2TokenIntrospectionFactory, compose.OAuth2TokenRevocationFactory)
	ts := mockServer(t, provider, &oauth2.DefaultSession{})
	defer ts.Close()

	oauthClient := newOAuth2Client(ts)
	oauthClient.ClientSecret = ""
	oauthClient.ClientID = testClientIDPublic
	store.Clients[testClientIDPublic].(*oauth2.DefaultClient).RedirectURIs[0] = ts.URL + "/callback"

	resp, err := http.Get(oauthClient.AuthCodeURL(testState) + "&code_challenge_method=S256&code_challenge=" + challenge)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	code := resp.Request.URL.Query().Get(consts.FormParameterAuthorizationCode)
	require.NotEmpty(t, code)

	exchange := func(t *testing.T, verifier string) (status int, token xoauth2.Token) {
		t.Helper()

		form := url.Values{
			consts.FormParameterAuthorizationCode: {code},
			consts.FormParameterGrantType:         {consts.GrantTypeAuthorizationCode},
			consts.FormParameterClientID:          {testClientIDPublic},
			consts.FormParameterRedirectURI:       {ts.URL + "/callback"},
		}

		if verifier != "" {
			form.Set(consts.FormParameterCodeVerifier, verifier)
		}

		res, err := http.PostForm(ts.URL+"/token", form)
		require.NoError(t, err)

		defer res.Body.Close()

		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &token))

		return res.StatusCode, token
	}

	active := func(t *testing.T, token *xoauth2.Token) int {
		t.Helper()

		res, err := oauthClient.Client(t.Context(), token).Get(ts.URL + "/info")
		require.NoError(t, err)

		defer res.Body.Close()

		return res.StatusCode
	}

	status, token := exchange(t, verifier)
	require.Equal(t, http.StatusOK, status)
	require.NotEmpty(t, token.AccessToken)
	require.Equal(t, http.StatusOK, active(t, &token))

	t.Run("ShouldNotRevokeTheGrantForAReplayWithoutTheCodeVerifier", func(t *testing.T) {
		status, _ := exchange(t, "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, http.StatusOK, active(t, &token))
	})

	t.Run("ShouldNotRevokeTheGrantForAReplayWithAnotherCodeVerifier", func(t *testing.T) {
		status, _ := exchange(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, http.StatusOK, active(t, &token))
	})

	t.Run("ShouldRevokeTheGrantForAReplayWithTheCodeVerifier", func(t *testing.T) {
		status, _ := exchange(t, verifier)
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, http.StatusUnauthorized, active(t, &token))
	})
}

func TestAuthorizeCodeReplayWithoutThePKCEHandlerRevokesTheGrant(t *testing.T) {
	testCases := []struct {
		name      string
		whitelist []string
	}{
		{name: "ShouldRevokeWithTheDefaultSanitationWhiteList"},
		{name: "ShouldRevokeWithASanitationWhiteListRetainingTheCodeChallenge", whitelist: []string{consts.FormParameterRedirectURI, consts.FormParameterCodeChallenge, consts.FormParameterCodeChallengeMethod}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testAuthorizeCodeReplayWithoutThePKCEHandler(t, &oauth2.Config{SanitationWhiteList: tc.whitelist})
		})
	}
}

func testAuthorizeCodeReplayWithoutThePKCEHandler(t *testing.T, config *oauth2.Config) {
	const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	provider := compose.Compose(config, store, hmacStrategy, compose.OAuth2AuthorizeExplicitFactory, compose.OAuth2TokenIntrospectionFactory)
	ts := mockServer(t, provider, &oauth2.DefaultSession{})
	defer ts.Close()

	oauthClient := newOAuth2Client(ts)
	oauthClient.ClientSecret = ""
	oauthClient.ClientID = testClientIDPublic
	store.Clients[testClientIDPublic].(*oauth2.DefaultClient).RedirectURIs[0] = ts.URL + "/callback"

	resp, err := http.Get(oauthClient.AuthCodeURL(testState) + "&code_challenge_method=S256&code_challenge=" + challenge)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	form := url.Values{
		consts.FormParameterAuthorizationCode: {resp.Request.URL.Query().Get(consts.FormParameterAuthorizationCode)},
		consts.FormParameterGrantType:         {consts.GrantTypeAuthorizationCode},
		consts.FormParameterClientID:          {testClientIDPublic},
		consts.FormParameterRedirectURI:       {ts.URL + "/callback"},
	}

	exchange := func(t *testing.T) (status int, token xoauth2.Token) {
		t.Helper()

		res, err := http.PostForm(ts.URL+"/token", form)
		require.NoError(t, err)

		defer res.Body.Close()

		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &token))

		return res.StatusCode, token
	}

	status, token := exchange(t)
	require.Equal(t, http.StatusOK, status)
	require.NotEmpty(t, token.AccessToken)

	status, _ = exchange(t)
	assert.Equal(t, http.StatusBadRequest, status)

	res, err := oauthClient.Client(t.Context(), &token).Get(ts.URL + "/info")
	require.NoError(t, err)

	defer res.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
}
