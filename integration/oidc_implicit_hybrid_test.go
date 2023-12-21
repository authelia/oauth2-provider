// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

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

func TestOIDCImplicitFlow(t *testing.T) {
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
	store.Clients["my-client"].(*oauth2.DefaultClient).RedirectURIs[0] = ts.URL + "/callback"

	var state = "12345678901234567890"
	for k, c := range []struct {
		responseType string
		description  string
		nonce        string
		setup        func()
		hasToken     bool
		hasIdToken   bool
		hasCode      bool
	}{
		{
			description:  "should pass without id token",
			responseType: "token",
			setup: func() {
				oauthClient.Scopes = []string{"oauth2"}
			},
			hasToken: true,
		},
		{

			responseType: "id_token%20token",
			nonce:        "1111111111111111",
			description:  "should pass id token (id_token token)",
			setup: func() {
				oauthClient.Scopes = []string{"oauth2", consts.ScopeOpenID}
			},
			hasToken:   true,
			hasIdToken: true,
		},
		{

			responseType: "token%20id_token%20code",
			nonce:        "1111111111111111",
			description:  "should pass id token (code id_token token)",
			setup:        func() {},
			hasToken:     true,
			hasCode:      true,
			hasIdToken:   true,
		},
		{

			responseType: "token%20code",
			nonce:        "1111111111111111",
			description:  "should pass id token (code token)",
			setup:        func() {},
			hasToken:     true,
			hasCode:      true,
		},
		{

			responseType: "id_token%20code",
			nonce:        "1111111111111111",
			description:  "should pass id token (id_token code)",
			setup:        func() {},
			hasCode:      true,
			hasIdToken:   true,
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, c.description), func(t *testing.T) {
			c.setup()

			var callbackURL *url.URL

			authURL := strings.Replace(oauthClient.AuthCodeURL(state), "response_type=code", "response_type="+c.responseType, -1) + "&nonce=" + c.nonce

			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					callbackURL = req.URL
					return errors.New("Dont follow redirects")
				},
			}

			resp, err := client.Get(authURL)
			require.Error(t, err)

			t.Logf("Response (%d): %s", k, callbackURL.String())
			fragment, err := url.ParseQuery(callbackURL.Fragment)
			require.NoError(t, err)

			if c.hasToken {
				assert.NotEmpty(t, fragment.Get(consts.AccessResponseAccessToken))
			} else {
				assert.Empty(t, fragment.Get(consts.AccessResponseAccessToken))
			}

			if c.hasCode {
				assert.NotEmpty(t, fragment.Get(consts.FormParameterAuthorizationCode))
			} else {
				assert.Empty(t, fragment.Get(consts.FormParameterAuthorizationCode))
			}

			if c.hasIdToken {
				assert.NotEmpty(t, fragment.Get(consts.AccessResponseIDToken))
			} else {
				assert.Empty(t, fragment.Get(consts.AccessResponseIDToken))
			}

			if !c.hasToken {
				return
			}

			expires, err := strconv.Atoi(fragment.Get(consts.AccessResponseExpiresIn))
			require.NoError(t, err)

			token := &xoauth2.Token{
				AccessToken:  fragment.Get(consts.AccessResponseAccessToken),
				TokenType:    fragment.Get(consts.AccessResponseTokenType),
				RefreshToken: fragment.Get(consts.AccessResponseRefreshToken),
				Expiry:       time.Now().UTC().Add(time.Duration(expires) * time.Second),
			}

			httpClient := oauthClient.Client(context.TODO(), token)
			resp, err = httpClient.Get(ts.URL + "/info")
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			t.Logf("Passed test case (%d) %s", k, c.description)
		})
	}
}
