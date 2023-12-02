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

	"github.com/authelia/goauth2"
	. "github.com/authelia/goauth2/handler/par"
	"github.com/authelia/goauth2/storage"
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
		Config: &goauth2.Config{
			PushedAuthorizeContextLifespan:  30 * time.Minute,
			PushedAuthorizeRequestURIPrefix: requestURIPrefix,
			ScopeStrategy:                   goauth2.HierarchicScopeStrategy,
			AudienceMatchingStrategy:        goauth2.DefaultAudienceMatchingStrategy,
		},
	}
	for _, c := range []struct {
		handler     PushedAuthorizeHandler
		areq        *goauth2.AuthorizeRequest
		description string
		expectErr   error
		expect      func(t *testing.T, areq *goauth2.AuthorizeRequest, aresp *goauth2.PushedAuthorizeResponse)
	}{
		{
			handler: handler,
			areq: &goauth2.AuthorizeRequest{
				ResponseTypes: goauth2.Arguments{""},
				Request:       *goauth2.NewRequest(),
			},
			description: "should pass because not responsible for handling an empty response type",
		},
		{
			handler: handler,
			areq: &goauth2.AuthorizeRequest{
				ResponseTypes: goauth2.Arguments{"foo"},
				Request:       *goauth2.NewRequest(),
			},
			description: "should pass because not responsible for handling an invalid response type",
		},
		{
			handler: handler,
			areq: &goauth2.AuthorizeRequest{
				ResponseTypes: goauth2.Arguments{"code"},
				Request: goauth2.Request{
					Client: &goauth2.DefaultClient{
						ResponseTypes: goauth2.Arguments{"code"},
						RedirectURIs:  []string{"http://asdf.com/cb"},
					},
				},
				RedirectURI: parseURL("http://asdf.com/cb"),
			},
			description: "should fail because redirect uri is not https",
			expectErr:   goauth2.ErrInvalidRequest,
		},
		{
			handler: handler,
			areq: &goauth2.AuthorizeRequest{
				ResponseTypes: goauth2.Arguments{"code"},
				Request: goauth2.Request{
					Client: &goauth2.DefaultClient{
						ResponseTypes: goauth2.Arguments{"code"},
						RedirectURIs:  []string{"https://asdf.com/cb"},
						Audience:      []string{"https://www.ory.sh/api"},
					},
					RequestedAudience: []string{"https://www.ory.sh/not-api"},
				},
				RedirectURI: parseURL("https://asdf.com/cb"),
			},
			description: "should fail because audience doesn't match",
			expectErr:   goauth2.ErrInvalidRequest,
		},
		{
			handler: handler,
			areq: &goauth2.AuthorizeRequest{
				ResponseTypes: goauth2.Arguments{"code"},
				Request: goauth2.Request{
					Client: &goauth2.DefaultClient{
						ResponseTypes: goauth2.Arguments{"code"},
						RedirectURIs:  []string{"https://asdf.de/cb"},
						Audience:      []string{"https://www.ory.sh/api"},
					},
					RequestedAudience: []string{"https://www.ory.sh/api"},
					GrantedScope:      goauth2.Arguments{"a", "b"},
					Session: &goauth2.DefaultSession{
						ExpiresAt: map[goauth2.TokenType]time.Time{goauth2.AccessToken: time.Now().UTC().Add(time.Hour)},
					},
					RequestedAt: time.Now().UTC(),
				},
				State:       "superstate",
				RedirectURI: parseURL("https://asdf.de/cb"),
			},
			description: "should pass",
			expect: func(t *testing.T, areq *goauth2.AuthorizeRequest, aresp *goauth2.PushedAuthorizeResponse) {
				requestURI := aresp.RequestURI
				assert.NotEmpty(t, requestURI)
				assert.True(t, strings.HasPrefix(requestURI, requestURIPrefix), "requestURI does not match: %s", requestURI)
			},
		},
	} {
		t.Run("case="+c.description, func(t *testing.T) {
			aresp := &goauth2.PushedAuthorizeResponse{}
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
