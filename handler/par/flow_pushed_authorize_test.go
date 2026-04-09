// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package par_test

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	. "authelia.com/provider/oauth2/handler/par"
	"authelia.com/provider/oauth2/storage"
)

func parseURL(uu string) *url.URL {
	u, _ := url.Parse(uu)
	return u
}

func TestAuthorizeCode_HandleAuthorizeEndpointRequest(t *testing.T) {
	requestURIPrefix := "urn:ietf:params:oauth:request_uri_diff:"

	testCases := []struct {
		name   string
		areq   *oauth2.AuthorizeRequest
		err    string
		expect func(t *testing.T, areq *oauth2.AuthorizeRequest, aresp *oauth2.PushedAuthorizeResponse)
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
				ResponseTypes: oauth2.Arguments{"code"},
				Request: oauth2.Request{
					Client: &oauth2.DefaultClient{
						ResponseTypes: oauth2.Arguments{"code"},
						RedirectURIs:  []string{"http://asdf.com/cb"},
					},
				},
				RedirectURI: parseURL("http://asdf.com/cb"),
			},
			err: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Redirect URL is using an insecure protocol, http is only allowed for hosts with suffix 'localhost', for example: http://myapp.localhost/.",
		},
		{
			name: "ShouldFailAudienceMismatch",
			areq: &oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{"code"},
				Request: oauth2.Request{
					Client: &oauth2.DefaultClient{
						ResponseTypes: oauth2.Arguments{"code"},
						RedirectURIs:  []string{"https://asdf.com/cb"},
						Audience:      []string{"https://www.authelia.com/api"},
					},
					RequestedAudience: []string{"https://www.authelia.com/not-api"},
				},
				RedirectURI: parseURL("https://asdf.com/cb"),
			},
			err: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Requested audience 'https://www.authelia.com/not-api' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name: "ShouldPass",
			areq: &oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{"code"},
				Request: oauth2.Request{
					Client: &oauth2.DefaultClient{
						ResponseTypes: oauth2.Arguments{"code"},
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
				RedirectURI: parseURL("https://asdf.de/cb"),
			},
			expect: func(t *testing.T, areq *oauth2.AuthorizeRequest, aresp *oauth2.PushedAuthorizeResponse) {
				requestURI := aresp.RequestURI
				assert.NotEmpty(t, requestURI)
				assert.True(t, strings.HasPrefix(requestURI, requestURIPrefix), "requestURI does not match: %s", requestURI)
			},
		},
		{
			name: "ShouldPassPARCWithLifespan",
			areq: &oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{"code"},
				Request: oauth2.Request{
					Client: &PARCTestClient{
						DefaultClient: &oauth2.DefaultClient{
							ResponseTypes: oauth2.Arguments{"code"},
							RedirectURIs:  []string{"https://asdf.de/cb"},
							Audience:      []string{"https://www.authelia.com/api"},
						},
						lifespan: time.Hour,
					},
					RequestedAudience: []string{"https://www.authelia.com/api"},
					GrantedScope:      oauth2.Arguments{"a", "b"},
					Session: &oauth2.DefaultSession{
						ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.AccessToken: time.Now().UTC().Add(time.Hour)},
					},
					RequestedAt: time.Now().UTC(),
				},
				State:       "superstate",
				RedirectURI: parseURL("https://asdf.de/cb"),
			},
			expect: func(t *testing.T, areq *oauth2.AuthorizeRequest, aresp *oauth2.PushedAuthorizeResponse) {
				requestURI := aresp.RequestURI
				assert.NotEmpty(t, requestURI)
				assert.True(t, strings.HasPrefix(requestURI, requestURIPrefix), "requestURI does not match: %s", requestURI)
			},
		},
		{
			name: "ShouldPassPARCWithoutLifespan",
			areq: &oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{"code"},
				Request: oauth2.Request{
					Client: &PARCTestClient{
						DefaultClient: &oauth2.DefaultClient{
							ResponseTypes: oauth2.Arguments{"code"},
							RedirectURIs:  []string{"https://asdf.de/cb"},
							Audience:      []string{"https://www.authelia.com/api"},
						},
					},
					RequestedAudience: []string{"https://www.authelia.com/api"},
					GrantedScope:      oauth2.Arguments{"a", "b"},
					Session: &oauth2.DefaultSession{
						ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.AccessToken: time.Now().UTC().Add(time.Hour)},
					},
					RequestedAt: time.Now().UTC(),
				},
				State:       "superstate",
				RedirectURI: parseURL("https://asdf.de/cb"),
			},
			expect: func(t *testing.T, areq *oauth2.AuthorizeRequest, aresp *oauth2.PushedAuthorizeResponse) {
				requestURI := aresp.RequestURI
				assert.NotEmpty(t, requestURI)
				assert.True(t, strings.HasPrefix(requestURI, requestURIPrefix), "requestURI does not match: %s", requestURI)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := storage.NewMemoryStore()
			handler := PushedAuthorizeHandler{
				Storage: store,
				Config: &oauth2.Config{
					PushedAuthorizeContextLifespan:  30 * time.Minute,
					PushedAuthorizeRequestURIPrefix: requestURIPrefix,
					ScopeStrategy:                   oauth2.HierarchicScopeStrategy,
					AudienceMatchingStrategy:        oauth2.DefaultAudienceMatchingStrategy,
				},
			}

			aresp := &oauth2.PushedAuthorizeResponse{}
			err := handler.HandlePushedAuthorizeEndpointRequest(context.Background(), tc.areq, aresp)
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

type PARCTestClient struct {
	*oauth2.DefaultClient

	require  bool
	lifespan time.Duration
}

func (p *PARCTestClient) GetRequirePushedAuthorizationRequests() (require bool) {
	return p.require
}

func (p *PARCTestClient) GetPushedAuthorizeContextLifespan() (lifespan time.Duration) {
	return p.lifespan
}

var _ oauth2.PushedAuthorizationRequestClient = (*PARCTestClient)(nil)
