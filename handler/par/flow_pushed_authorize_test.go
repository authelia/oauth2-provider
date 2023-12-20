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
	for _, c := range []struct {
		handler     PushedAuthorizeHandler
		areq        *oauth2.AuthorizeRequest
		description string
		expectErr   error
		expect      func(t *testing.T, areq *oauth2.AuthorizeRequest, aresp *oauth2.PushedAuthorizeResponse)
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
				ResponseTypes: oauth2.Arguments{"code"},
				Request: oauth2.Request{
					Client: &oauth2.DefaultClient{
						ResponseTypes: oauth2.Arguments{"code"},
						RedirectURIs:  []string{"http://asdf.com/cb"},
					},
				},
				RedirectURI: parseURL("http://asdf.com/cb"),
			},
			description: "should fail because redirect uri is not https",
			expectErr:   oauth2.ErrInvalidRequest,
		},
		{
			handler: handler,
			areq: &oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{"code"},
				Request: oauth2.Request{
					Client: &oauth2.DefaultClient{
						ResponseTypes: oauth2.Arguments{"code"},
						RedirectURIs:  []string{"https://asdf.com/cb"},
						Audience:      []string{"https://www.ory.sh/api"},
					},
					RequestedAudience: []string{"https://www.ory.sh/not-api"},
				},
				RedirectURI: parseURL("https://asdf.com/cb"),
			},
			description: "should fail because audience doesn't match",
			expectErr:   oauth2.ErrInvalidRequest,
		},
		{
			handler: handler,
			areq: &oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{"code"},
				Request: oauth2.Request{
					Client: &oauth2.DefaultClient{
						ResponseTypes: oauth2.Arguments{"code"},
						RedirectURIs:  []string{"https://asdf.de/cb"},
						Audience:      []string{"https://www.ory.sh/api"},
					},
					RequestedAudience: []string{"https://www.ory.sh/api"},
					GrantedScope:      oauth2.Arguments{"a", "b"},
					Session: &oauth2.DefaultSession{
						ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.AccessToken: time.Now().UTC().Add(time.Hour)},
					},
					RequestedAt: time.Now().UTC(),
				},
				State:       "superstate",
				RedirectURI: parseURL("https://asdf.de/cb"),
			},
			description: "should pass",
			expect: func(t *testing.T, areq *oauth2.AuthorizeRequest, aresp *oauth2.PushedAuthorizeResponse) {
				requestURI := aresp.RequestURI
				assert.NotEmpty(t, requestURI)
				assert.True(t, strings.HasPrefix(requestURI, requestURIPrefix), "requestURI does not match: %s", requestURI)
			},
		},
	} {
		t.Run("case="+c.description, func(t *testing.T) {
			aresp := &oauth2.PushedAuthorizeResponse{}
			err := c.handler.HandlePushedAuthorizeEndpointRequest(context.Background(), c.areq, aresp)
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
}
