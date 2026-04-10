// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func parseUrl(uu string) *url.URL {
	u, _ := url.Parse(uu)
	return u
}

func TestAuthorizeCode_HandleAuthorizeEndpointRequestHMAC(t *testing.T) {
	testCases := []struct {
		name   string
		config *oauth2.Config
		areq   *oauth2.AuthorizeRequest
		err    string
		expect func(t *testing.T, areq *oauth2.AuthorizeRequest, aresp *oauth2.AuthorizeResponse)
	}{
		{
			name: "ShouldPassNotResponsibleForEmptyResponseType",
			areq: &oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{""},
				Request:       *oauth2.NewRequest(),
			},
		},
		{
			name: "ShouldPassNotResponsibleForInvalidResponseType",
			areq: &oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{"foo"},
				Request:       *oauth2.NewRequest(),
			},
		},
		{
			name: "ShouldFailRedirectURINotHTTPS",
			areq: &oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
				Request: oauth2.Request{
					Client: &oauth2.DefaultClient{
						Public:        true,
						ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
						RedirectURIs:  []string{"http://asdf.com/cb"},
					},
					Session: &oauth2.DefaultSession{
						ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.AccessToken: time.Now().UTC().Add(time.Hour)},
					},
				},
				RedirectURI: parseUrl("http://asdf.com/cb"),
			},
			err: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Redirect URL is using an insecure protocol, http is only allowed for confidential clients or hosts with suffix 'localhost', for example: http://myapp.localhost/.",
		},
		{
			name: "ShouldFailAudienceMismatch",
			areq: &oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
				Request: oauth2.Request{
					Client: &oauth2.DefaultClient{
						ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
						RedirectURIs:  []string{"https://asdf.com/cb"},
						Audience:      []string{"https://www.authelia.com/api"},
					},
					RequestedAudience: []string{"https://www.authelia.com/not-api"},
				},
				RedirectURI: parseUrl("https://asdf.com/cb"),
			},
			err: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Requested audience 'https://www.authelia.com/not-api' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name: "ShouldPassRedirectURIHTTPConfidential",
			areq: &oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
				Request: oauth2.Request{
					Client: &oauth2.DefaultClient{
						ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
						RedirectURIs:  []string{"http://asdf.de/cb"},
						Audience:      []string{"https://www.authelia.com/api"},
					},
					RequestedAudience: []string{"https://www.authelia.com/api"},
					GrantedScope:      oauth2.Arguments{"a", "b"},
					Session: &oauth2.DefaultSession{
						ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.AccessToken: time.Now().UTC().Add(time.Hour)},
					},
					RequestedAt: time.Now().UTC(),
				},
				State:       "superstate",
				RedirectURI: parseUrl("http://asdf.de/cb"),
			},
			expect: func(t *testing.T, areq *oauth2.AuthorizeRequest, aresp *oauth2.AuthorizeResponse) {
				code := aresp.GetParameters().Get(consts.FormParameterAuthorizationCode)
				assert.NotEmpty(t, code)

				assert.Equal(t, strings.Join(areq.GrantedScope, " "), aresp.GetParameters().Get(consts.FormParameterScope))
				assert.Equal(t, areq.State, aresp.GetParameters().Get(consts.FormParameterState))
				assert.Equal(t, oauth2.ResponseModeQuery, areq.GetResponseMode())
			},
		},
		{
			name: "ShouldPass",
			areq: &oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
				Request: oauth2.Request{
					Client: &oauth2.DefaultClient{
						ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
						RedirectURIs:  []string{"https://asdf.de/cb"},
						Audience:      []string{"https://www.authelia.com/api"},
					},
					RequestedAudience: []string{"https://www.authelia.com/api"},
					GrantedScope:      oauth2.Arguments{"a", "b"},
					Session: &oauth2.DefaultSession{
						ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.AccessToken: time.Now().UTC().Add(time.Hour)},
					},
					RequestedAt: time.Now().UTC(),
				},
				State:       "superstate",
				RedirectURI: parseUrl("https://asdf.de/cb"),
			},
			expect: func(t *testing.T, areq *oauth2.AuthorizeRequest, aresp *oauth2.AuthorizeResponse) {
				code := aresp.GetParameters().Get(consts.FormParameterAuthorizationCode)
				assert.NotEmpty(t, code)

				assert.Equal(t, strings.Join(areq.GrantedScope, " "), aresp.GetParameters().Get(consts.FormParameterScope))
				assert.Equal(t, areq.State, aresp.GetParameters().Get(consts.FormParameterState))
				assert.Equal(t, oauth2.ResponseModeQuery, areq.GetResponseMode())
			},
		},
		{
			name: "ShouldPassButNoScopeInRedirectURI",
			config: &oauth2.Config{
				ScopeStrategy:            oauth2.HierarchicScopeStrategy,
				AudienceMatchingStrategy: oauth2.DefaultAudienceMatchingStrategy,
				OmitRedirectScopeParam:   true,
			},
			areq: &oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
				Request: oauth2.Request{
					Client: &oauth2.DefaultClient{
						ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
						RedirectURIs:  []string{"https://asdf.de/cb"},
						Audience:      []string{"https://www.authelia.com/api"},
					},
					RequestedAudience: []string{"https://www.authelia.com/api"},
					GrantedScope:      oauth2.Arguments{"a", "b"},
					Session: &oauth2.DefaultSession{
						ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.AccessToken: time.Now().UTC().Add(time.Hour)},
					},
					RequestedAt: time.Now().UTC(),
				},
				State:       "superstate",
				RedirectURI: parseUrl("https://asdf.de/cb"),
			},
			expect: func(t *testing.T, areq *oauth2.AuthorizeRequest, aresp *oauth2.AuthorizeResponse) {
				code := aresp.GetParameters().Get(consts.FormParameterAuthorizationCode)
				assert.NotEmpty(t, code)

				assert.Empty(t, aresp.GetParameters().Get(consts.FormParameterScope))
				assert.Equal(t, areq.State, aresp.GetParameters().Get(consts.FormParameterState))
				assert.Equal(t, oauth2.ResponseModeQuery, areq.GetResponseMode())
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			strategy := &hmacshaStrategy
			store := storage.NewMemoryStore()
			config := tc.config
			if config == nil {
				config = &oauth2.Config{
					AudienceMatchingStrategy: oauth2.DefaultAudienceMatchingStrategy,
					ScopeStrategy:            oauth2.HierarchicScopeStrategy,
				}
			}
			handler := AuthorizeExplicitGrantHandler{
				CoreStorage:           store,
				AuthorizeCodeStrategy: strategy,
				Config:                config,
			}

			aresp := oauth2.NewAuthorizeResponse()
			err := handler.HandleAuthorizeEndpointRequest(t.Context(), tc.areq, aresp)
			if tc.err != "" {
				require.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)
			} else {
				require.NoError(t, err)
			}

			if tc.expect != nil {
				tc.expect(t, tc.areq, aresp)
			}
		})
	}
}
