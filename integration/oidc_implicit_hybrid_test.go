// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
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
	testCases := []struct {
		name         string
		setup        func(t *testing.T, client *xoauth2.Config)
		responseType string
		nonce        string
		hasToken     bool
		hasIdToken   bool
		hasCode      bool
	}{
		{
			name:         "ShouldPassImplicitToken",
			responseType: consts.ResponseTypeImplicitFlowToken,
			setup: func(t *testing.T, client *xoauth2.Config) {
				client.Scopes = []string{"oauth2"}
			},
			hasToken: true,
		},
		{
			name:         "ShouldPassImplicitBoth",
			responseType: consts.ResponseTypeImplicitFlowBoth,
			nonce:        "1111111111111111",
			setup: func(t *testing.T, client *xoauth2.Config) {
				client.Scopes = []string{"oauth2", consts.ScopeOpenID}
			},
			hasToken:   true,
			hasIdToken: true,
		},
		{
			name:         "ShouldPassHybridBoth",
			responseType: consts.ResponseTypeHybridFlowBoth,
			nonce:        "1111111111111111",
			setup: func(t *testing.T, client *xoauth2.Config) {
				client.Scopes = []string{"oauth2", consts.ScopeOpenID}
			},
			hasToken:   true,
			hasCode:    true,
			hasIdToken: true,
		},
		{
			name:         "ShouldPassHybridToken",
			responseType: consts.ResponseTypeHybridFlowToken,
			nonce:        "1111111111111111",
			setup:        nil,
			hasToken:     true,
			hasCode:      true,
		},
		{
			name:         "ShouldPassHybridIDToken",
			responseType: consts.ResponseTypeHybridFlowIDToken,
			nonce:        "1111111111111111",
			setup: func(t *testing.T, client *xoauth2.Config) {
				client.Scopes = []string{"oauth2", consts.ScopeOpenID}
			},
			hasCode:    true,
			hasIdToken: true,
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

			client := newOAuth2Client(ts)
			store.Clients["my-client"].(*oauth2.DefaultClient).RedirectURIs[0] = ts.URL + "/callback"

			var state = "12345678901234567890"

			if tc.setup != nil {
				tc.setup(t, client)
			}

			var callbackURL *url.URL

			authURL, err := url.Parse(client.AuthCodeURL(state))
			require.NoError(t, err)

			query := authURL.Query()
			query.Set(consts.FormParameterResponseType, tc.responseType)
			query.Set(consts.FormParameterNonce, tc.nonce)

			authURL.RawQuery = query.Encode()

			c := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					callbackURL = req.URL
					return errors.New("Dont follow redirects")
				},
			}

			// TODO: investigate this.
			//nolint:staticcheck
			response, err := c.Get(authURL.String())
			require.Error(t, err)

			fragment, err := url.ParseQuery(callbackURL.Fragment)
			require.NoError(t, err)

			if tc.hasToken {
				assert.NotEmpty(t, fragment.Get(consts.AccessResponseAccessToken))
			} else {
				assert.Empty(t, fragment.Get(consts.AccessResponseAccessToken))
			}

			if tc.hasCode {
				assert.NotEmpty(t, fragment.Get(consts.FormParameterAuthorizationCode))
			} else {
				assert.Empty(t, fragment.Get(consts.FormParameterAuthorizationCode))
			}

			if tc.hasIdToken {
				assert.NotEmpty(t, fragment.Get(consts.AccessResponseIDToken))
			} else {
				assert.Empty(t, fragment.Get(consts.AccessResponseIDToken))
			}

			if !tc.hasToken {
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

			httpClient := client.Client(context.TODO(), token)
			response, err = httpClient.Get(ts.URL + "/info")
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, response.StatusCode)
		})
	}
}
