// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/parnurzeal/gorequest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
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
	token, err := oauthClient.Token(context.TODO())
	require.NoError(t, err)

	resp, _, errs := gorequest.New().Post(ts.URL+"/revoke").
		SetBasicAuth(oauthClient.ClientID, oauthClient.ClientSecret).
		Type("form").
		SendStruct(map[string]string{"token": "asdf"}).End()
	require.Len(t, errs, 0)
	assert.Equal(t, 200, resp.StatusCode)

	resp, _, errs = gorequest.New().Post(ts.URL+"/revoke").
		SetBasicAuth(oauthClient.ClientID, oauthClient.ClientSecret).
		Type("form").
		SendStruct(map[string]string{"token": token.AccessToken}).End()
	require.Len(t, errs, 0)
	assert.Equal(t, 200, resp.StatusCode)

	hres, _, errs := gorequest.New().Get(ts.URL+"/info").
		Set("Authorization", "bearer "+token.AccessToken).
		End()
	require.Len(t, errs, 0)
	assert.Equal(t, http.StatusUnauthorized, hres.StatusCode)
}
