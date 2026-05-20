// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
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

func TestRevokeToken(t *testing.T) {
	for _, strategy := range []hoauth2.AccessTokenStrategy{
		hmacStrategy,
	} {
		runRevokeTokenTest(t, strategy)
	}
}

func runRevokeTokenTest(t *testing.T, strategy hoauth2.AccessTokenStrategy) {
	f := compose.Compose(new(oauth2.Config), store, strategy, compose.OAuth2ClientCredentialsGrantFactory, compose.OAuth2TokenIntrospectionFactory, compose.OAuth2TokenRevocationFactory)
	ts := mockServer(t, f, &oauth2.DefaultSession{})

	defer ts.Close()

	oauthClient := newOAuth2AppClient(ts)
	token, err := oauthClient.Token(t.Context())
	require.NoError(t, err)

	data := url.Values{consts.FormParameterToken: {"asdf"}}
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/revoke", strings.NewReader(data.Encode()))
	require.NoError(t, err)

	req.SetBasicAuth(oauthClient.ClientID, oauthClient.ClientSecret)
	req.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	data = url.Values{consts.FormParameterToken: {token.AccessToken}}
	req, err = http.NewRequest(http.MethodPost, ts.URL+"/revoke", strings.NewReader(data.Encode()))
	require.NoError(t, err)

	req.SetBasicAuth(oauthClient.ClientID, oauthClient.ClientSecret)
	req.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)

	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	req, err = http.NewRequest(http.MethodGet, ts.URL+"/info", nil)
	require.NoError(t, err)

	req.Header.Set(consts.HeaderAuthorization, "bearer "+token.AccessToken)

	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
