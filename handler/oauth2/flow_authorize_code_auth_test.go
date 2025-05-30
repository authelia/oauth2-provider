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

func TestAuthorizeCode_HandleAuthorizeEndpointRequest(t *testing.T) {
	for k, strategy := range map[string]CoreStrategy{
		"hmac": &hmacshaStrategy,
	} {
		t.Run("strategy="+k, func(t *testing.T) {
			store := storage.NewMemoryStore()
			handler := AuthorizeExplicitGrantHandler{
				CoreStorage:           store,
				AuthorizeCodeStrategy: strategy,
				Config: &oauth2.Config{
					AudienceMatchingStrategy: oauth2.DefaultAudienceMatchingStrategy,
					ScopeStrategy:            oauth2.HierarchicScopeStrategy,
				},
			}
			for _, c := range []struct {
				handler     AuthorizeExplicitGrantHandler
				areq        *oauth2.AuthorizeRequest
				description string
				expectErr   error
				expect      func(t *testing.T, areq *oauth2.AuthorizeRequest, aresp *oauth2.AuthorizeResponse)
			}{
				{
					handler: handler,
					areq: &oauth2.AuthorizeRequest{
						ResponseTypes: oauth2.Arguments{""},
						Request:       *oauth2.NewRequest(),
					},
					description: "should pass because not responsible for handling an empty response type",
				},
				{
					handler: handler,
					areq: &oauth2.AuthorizeRequest{
						ResponseTypes: oauth2.Arguments{"foo"},
						Request:       *oauth2.NewRequest(),
					},
					description: "should pass because not responsible for handling an invalid response type",
				},
				{
					handler: handler,
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
					description: "should fail because redirect uri is not https",
					expectErr:   oauth2.ErrInvalidRequest,
				},
				{
					handler: handler,
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
					description: "should fail because audience doesn't match",
					expectErr:   oauth2.ErrInvalidRequest,
				},
				{
					handler: handler,
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
					description: "should pass redirect uri http confidential",
					expect: func(t *testing.T, areq *oauth2.AuthorizeRequest, aresp *oauth2.AuthorizeResponse) {
						code := aresp.GetParameters().Get(consts.FormParameterAuthorizationCode)
						assert.NotEmpty(t, code)

						assert.Equal(t, strings.Join(areq.GrantedScope, " "), aresp.GetParameters().Get(consts.FormParameterScope))
						assert.Equal(t, areq.State, aresp.GetParameters().Get(consts.FormParameterState))
						assert.Equal(t, oauth2.ResponseModeQuery, areq.GetResponseMode())
					},
				},
				{
					handler: handler,
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
					description: "should pass",
					expect: func(t *testing.T, areq *oauth2.AuthorizeRequest, aresp *oauth2.AuthorizeResponse) {
						code := aresp.GetParameters().Get(consts.FormParameterAuthorizationCode)
						assert.NotEmpty(t, code)

						assert.Equal(t, strings.Join(areq.GrantedScope, " "), aresp.GetParameters().Get(consts.FormParameterScope))
						assert.Equal(t, areq.State, aresp.GetParameters().Get(consts.FormParameterState))
						assert.Equal(t, oauth2.ResponseModeQuery, areq.GetResponseMode())
					},
				},
				{
					handler: AuthorizeExplicitGrantHandler{
						CoreStorage:           store,
						AuthorizeCodeStrategy: strategy,
						Config: &oauth2.Config{
							ScopeStrategy:            oauth2.HierarchicScopeStrategy,
							AudienceMatchingStrategy: oauth2.DefaultAudienceMatchingStrategy,
							OmitRedirectScopeParam:   true,
						},
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
					description: "should pass but no scope in redirect uri",
					expect: func(t *testing.T, areq *oauth2.AuthorizeRequest, aresp *oauth2.AuthorizeResponse) {
						code := aresp.GetParameters().Get(consts.FormParameterAuthorizationCode)
						assert.NotEmpty(t, code)

						assert.Empty(t, aresp.GetParameters().Get(consts.FormParameterScope))
						assert.Equal(t, areq.State, aresp.GetParameters().Get(consts.FormParameterState))
						assert.Equal(t, oauth2.ResponseModeQuery, areq.GetResponseMode())
					},
				},
			} {
				t.Run("case="+c.description, func(t *testing.T) {
					aresp := oauth2.NewAuthorizeResponse()
					err := c.handler.HandleAuthorizeEndpointRequest(t.Context(), c.areq, aresp)
					if c.expectErr != nil {
						require.EqualError(t, err, c.expectErr.Error())
					} else {
						require.NoError(t, err)
					}

					if c.expect != nil {
						c.expect(t, c.areq, aresp)
					}
				})
			}
		})
	}
}
