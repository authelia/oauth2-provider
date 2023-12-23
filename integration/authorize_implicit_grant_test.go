// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"encoding/json"
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
	"authelia.com/provider/oauth2/internal/consts"
)

func TestAuthorizeImplicitFlow(t *testing.T) {
	testCases := []struct {
		name           string
		setup          func(t *testing.T, client *xoauth2.Config)
		check          func(t *testing.T, r *http.Response)
		state          string
		params         []xoauth2.AuthCodeOption
		authStatusCode int
	}{
		{
			name: "ShouldFailWithInvalidAudience",
			params: []xoauth2.AuthCodeOption{
				xoauth2.SetAuthURLParam(consts.FormParameterAudience, "https://www.authelia.com/not-api"),
				xoauth2.SetAuthURLParam(consts.FormParameterResponseType, consts.ResponseTypeImplicitFlowToken),
			},
			state:          "12345678901234567890",
			authStatusCode: http.StatusNotAcceptable,
		},
		{
			name: "ShouldFailWithInvalidScope",
			params: []xoauth2.AuthCodeOption{
				xoauth2.SetAuthURLParam(consts.FormParameterResponseType, consts.ResponseTypeImplicitFlowToken),
			},
			state: "12345678901234567890",
			setup: func(t *testing.T, client *xoauth2.Config) {
				client.Scopes = []string{"not-exist"}
			},
			authStatusCode: http.StatusNotAcceptable,
		},
		{
			name: "ShouldPassWithValidAudience",
			params: []xoauth2.AuthCodeOption{
				xoauth2.SetAuthURLParam(consts.FormParameterAudience, "https://www.authelia.com/api"),
				xoauth2.SetAuthURLParam(consts.FormParameterResponseType, consts.ResponseTypeImplicitFlowToken),
			},
			state: "12345678901234567890",
			setup: func(t *testing.T, client *xoauth2.Config) {
				client.Scopes = []string{"oauth2"}
			},
			check: func(t *testing.T, r *http.Response) {
				var b oauth2.AccessRequest
				b.Client = new(oauth2.DefaultClient)
				b.Session = new(defaultSession)
				require.NoError(t, json.NewDecoder(r.Body).Decode(&b))
				assert.EqualValues(t, oauth2.Arguments{"https://www.authelia.com/api"}, b.RequestedAudience)
				assert.EqualValues(t, oauth2.Arguments{"https://www.authelia.com/api"}, b.GrantedAudience)
				assert.EqualValues(t, "foo-sub", b.Session.(*defaultSession).Subject)
			},
			authStatusCode: http.StatusOK,
		},
		{
			name:  "ShouldPassWithoutAudience",
			state: "12345678901234567890",
			params: []xoauth2.AuthCodeOption{
				xoauth2.SetAuthURLParam(consts.FormParameterResponseType, consts.ResponseTypeImplicitFlowToken),
			},
			authStatusCode: http.StatusOK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := compose.Compose(new(oauth2.Config), store, hmacStrategy, compose.OAuth2AuthorizeImplicitFactory, compose.OAuth2TokenIntrospectionFactory)

			server := mockServer(t, f, &oauth2.DefaultSession{})
			defer server.Close()

			oauthClient := newOAuth2Client(server)
			store.Clients["my-client"].(*oauth2.DefaultClient).RedirectURIs[0] = server.URL + "/callback"

			if tc.setup != nil {
				tc.setup(t, oauthClient)
			}

			var callbackURL *url.URL

			authURL := oauthClient.AuthCodeURL(tc.state, tc.params...)

			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					callbackURL = req.URL
					return errors.New("Dont follow redirects")
				},
			}
			resp, err := client.Get(authURL)
			require.Error(t, err)

			if resp.StatusCode == http.StatusOK {
				fragment, err := url.ParseQuery(callbackURL.Fragment)
				require.NoError(t, err)
				expires, err := strconv.Atoi(fragment.Get(consts.AccessResponseExpiresIn))
				require.NoError(t, err)
				token := &xoauth2.Token{
					AccessToken:  fragment.Get(consts.AccessResponseAccessToken),
					TokenType:    fragment.Get(consts.AccessResponseTokenType),
					RefreshToken: fragment.Get(consts.AccessResponseRefreshToken),
					Expiry:       time.Now().UTC().Add(time.Duration(expires) * time.Second),
				}

				httpClient := oauthClient.Client(context.TODO(), token)
				resp, err := httpClient.Get(server.URL + "/info")
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode)

				if tc.check != nil {
					tc.check(t, resp)
				}
			}
		})
	}
}
