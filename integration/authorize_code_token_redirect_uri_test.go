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
	xoauth2 "golang.org/x/oauth2"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestAuthorizeCodeTokenRequestRedirectURIOptional(t *testing.T) {
	testCases := []struct {
		name     string
		optional bool
		pkce     bool
		expected int
	}{
		{name: "ShouldRejectOmittedRedirectURIByDefault", pkce: true, expected: http.StatusBadRequest},
		{name: "ShouldAcceptOmittedRedirectURIWithPKCE", optional: true, pkce: true, expected: http.StatusOK},
		{name: "ShouldRejectOmittedRedirectURIWithoutPKCE", optional: true, expected: http.StatusBadRequest},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &oauth2.Config{TokenRequestRedirectURIOptional: tc.optional}
			provider := compose.Compose(config, store, hmacStrategy, compose.OAuth2AuthorizeExplicitFactory, compose.OAuth2PKCEFactory, compose.OAuth2TokenIntrospectionFactory)
			ts := mockServer(t, provider, &oauth2.DefaultSession{})
			defer ts.Close()

			oauthClient := newOAuth2Client(ts)
			store.Clients[oauthClient.ClientID].(*oauth2.DefaultClient).RedirectURIs[0] = ts.URL + "/callback"

			verifier := xoauth2.GenerateVerifier()

			authorize := oauthClient.AuthCodeURL(testState)
			if tc.pkce {
				authorize = oauthClient.AuthCodeURL(testState, xoauth2.S256ChallengeOption(verifier))
			}

			resp, err := http.Get(authorize)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)

			code := resp.Request.URL.Query().Get(consts.FormParameterAuthorizationCode)
			require.NotEmpty(t, code)

			form := url.Values{
				consts.FormParameterAuthorizationCode: {code},
				consts.FormParameterGrantType:         {consts.GrantTypeAuthorizationCode},
			}

			if tc.pkce {
				form.Set(consts.FormParameterCodeVerifier, verifier)
			}

			req, err := http.NewRequest(http.MethodPost, ts.URL+"/token", strings.NewReader(form.Encode()))
			require.NoError(t, err)

			req.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
			req.SetBasicAuth(oauthClient.ClientID, oauthClient.ClientSecret)

			res, err := http.DefaultClient.Do(req)
			require.NoError(t, err)

			defer res.Body.Close()

			// OAuth 2.1 Section 10.2.
			assert.Equal(t, tc.expected, res.StatusCode)
		})
	}
}
