// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xoauth2 "golang.org/x/oauth2"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/handler/pkce"
	"authelia.com/provider/oauth2/internal/consts"
)

// RFC 6749 Section 4.1.3 and OAuth 2.1 Section 10.2.
func TestTokenRequestRedirectURIWaiverRequiresPKCEAtBothEndpoints(t *testing.T) {
	isPKCEToken := func(h oauth2.TokenEndpointHandler) bool { _, ok := h.(*pkce.Handler); return ok }
	isPKCEAuthorize := func(h oauth2.AuthorizeEndpointHandler) bool { _, ok := h.(*pkce.Handler); return ok }

	testCases := []struct {
		name  string
		strip func(config *oauth2.Config)
	}{
		{name: "ShouldRejectWithPKCEAtBothEndpoints", strip: func(config *oauth2.Config) {}},
		{name: "ShouldRejectWithPKCEAtTheAuthorizeEndpointOnly", strip: func(config *oauth2.Config) {
			config.TokenEndpointHandlers = slices.DeleteFunc(config.TokenEndpointHandlers, isPKCEToken)
		}},
		{name: "ShouldRejectWithPKCEAtTheTokenEndpointOnly", strip: func(config *oauth2.Config) {
			config.AuthorizeEndpointHandlers = slices.DeleteFunc(config.AuthorizeEndpointHandlers, isPKCEAuthorize)
		}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &oauth2.Config{TokenRequestRedirectURIOptional: true, RedirectSecureChecker: oauth2.IsRedirectURISecure}
			provider := compose.Compose(config, store, hmacStrategy, compose.OAuth2AuthorizeExplicitFactory, compose.OAuth2PKCEFactory, compose.OAuth2TokenIntrospectionFactory)

			tc.strip(config)

			ts := mockServer(t, provider, &oauth2.DefaultSession{})
			defer ts.Close()

			client := newOAuth2Client(ts)
			store.Clients[client.ClientID].(*oauth2.DefaultClient).RedirectURIs[0] = ts.URL + "/callback"

			resp, err := http.Get(client.AuthCodeURL(testState, xoauth2.S256ChallengeOption(xoauth2.GenerateVerifier())))
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)

			code := resp.Request.URL.Query().Get(consts.FormParameterAuthorizationCode)
			require.NotEmpty(t, code)

			form := url.Values{consts.FormParameterAuthorizationCode: {code}, consts.FormParameterGrantType: {consts.GrantTypeAuthorizationCode}}

			req, err := http.NewRequest(http.MethodPost, ts.URL+"/token", strings.NewReader(form.Encode()))
			require.NoError(t, err)

			req.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
			req.SetBasicAuth(client.ClientID, client.ClientSecret)

			res, err := http.DefaultClient.Do(req)
			require.NoError(t, err)

			defer res.Body.Close()

			assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		})
	}
}
