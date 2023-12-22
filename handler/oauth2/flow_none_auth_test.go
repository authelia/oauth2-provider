package oauth2

import (
	"context"
	"strings"
	"testing"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"github.com/stretchr/testify/assert"
)

func TestNone_HandleAuthorizeEndpointRequest(t *testing.T) {
	testCases := []struct {
		name      string
		handler   *NoneResponseTypeHandler
		requester *oauth2.AuthorizeRequest
		err       string
		expect    func(t *testing.T, areq *oauth2.AuthorizeRequest, aresp *oauth2.AuthorizeResponse)
	}{
		{
			name: "ShouldPassWhenNotResponsibleForEmptyResponseType",
			requester: &oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{""},
				Request:       *oauth2.NewRequest(),
			},
			expect: func(t *testing.T, requester *oauth2.AuthorizeRequest, responder *oauth2.AuthorizeResponse) {
				assert.Equal(t, "", responder.GetParameters().Get(consts.FormParameterScope))
				assert.Equal(t, "", responder.GetParameters().Get(consts.FormParameterState))
				assert.Equal(t, oauth2.ResponseModeType(""), requester.GetResponseMode())
			},
		},
		{
			name: "ShouldPassWhenNotResponsibleForInvalidResponseType",
			requester: &oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{"foo"},
				Request:       *oauth2.NewRequest(),
			},
			expect: func(t *testing.T, requester *oauth2.AuthorizeRequest, responder *oauth2.AuthorizeResponse) {
				assert.Equal(t, "", responder.GetParameters().Get(consts.FormParameterScope))
				assert.Equal(t, "", responder.GetParameters().Get(consts.FormParameterState))
				assert.Equal(t, oauth2.ResponseModeType(""), requester.GetResponseMode())
			},
		},
		{
			name: "ShouldFailWhenInsecureRedirectURI",
			requester: &oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{"none"},
				Request: oauth2.Request{
					Client: &oauth2.DefaultClient{
						ResponseTypes: oauth2.Arguments{"code", "none"},
						RedirectURIs:  []string{"http://asdf.com/cb"},
					},
				},
				RedirectURI: parseUrl("http://asdf.com/cb"),
			},
			err: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Redirect URL is using an insecure protocol, http is only allowed for hosts with suffix 'localhost', for example: http://myapp.localhost/.",
		},
		{
			name: "ShouldFailMismatchedAudiences",
			requester: &oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{"none"},
				Request: oauth2.Request{
					Client: &oauth2.DefaultClient{
						ResponseTypes: oauth2.Arguments{"code", "none"},
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
			name: "ShouldPassNoneResponseType",
			requester: &oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{consts.ResponseTypeNone},
				Request: oauth2.Request{
					Client: &oauth2.DefaultClient{
						ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeNone},
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
				assert.Equal(t, strings.Join(areq.GrantedScope, " "), aresp.GetParameters().Get(consts.FormParameterScope))
				assert.Equal(t, areq.State, aresp.GetParameters().Get(consts.FormParameterState))
				assert.Equal(t, oauth2.ResponseModeQuery, areq.GetResponseMode())
			},
		},
		{
			name: "ShouldPassNoneResponseTypeWithScopes",
			requester: &oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{consts.ResponseTypeNone},
				Request: oauth2.Request{
					Client: &oauth2.DefaultClient{
						ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeNone},
						RedirectURIs:  []string{"https://asdf.de/cb"},
						Audience:      []string{"https://www.authelia.com/api"},
						Scopes:        []string{"a", "b"},
					},
					RequestedAudience: []string{"https://www.authelia.com/api"},
					RequestedScope:    oauth2.Arguments{"a", "b"},
					GrantedScope:      oauth2.Arguments{"a", "b"},
					Session: &oauth2.DefaultSession{
						ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.AccessToken: time.Now().UTC().Add(time.Hour)},
					},
					RequestedAt: time.Now().UTC(),
				},
				State:       "superstate",
				RedirectURI: parseUrl("https://asdf.de/cb"),
			},
			expect: func(t *testing.T, requester *oauth2.AuthorizeRequest, responder *oauth2.AuthorizeResponse) {
				assert.Equal(t, strings.Join(requester.GrantedScope, " "), responder.GetParameters().Get(consts.FormParameterScope))
				assert.Equal(t, requester.State, responder.GetParameters().Get(consts.FormParameterState))
				assert.Equal(t, oauth2.ResponseModeQuery, requester.GetResponseMode())
			},
		},
		{
			name: "ShouldPassNoneResponseTypeWithScopes",
			requester: &oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{consts.ResponseTypeNone},
				Request: oauth2.Request{
					Client: &oauth2.DefaultClient{
						ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeNone},
						RedirectURIs:  []string{"https://asdf.de/cb"},
						Audience:      []string{"https://www.authelia.com/api"},
						Scopes:        []string{"a", "b"},
					},
					RequestedAudience: []string{"https://www.authelia.com/api"},
					RequestedScope:    oauth2.Arguments{"a", "b"},
					Session: &oauth2.DefaultSession{
						ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.AccessToken: time.Now().UTC().Add(time.Hour)},
					},
					RequestedAt: time.Now().UTC(),
				},
				State:       "superstate",
				RedirectURI: parseUrl("https://asdf.de/cb"),
			},
			expect: func(t *testing.T, areq *oauth2.AuthorizeRequest, aresp *oauth2.AuthorizeResponse) {
				assert.Equal(t, strings.Join(areq.GrantedScope, " "), aresp.GetParameters().Get(consts.FormParameterScope))
				assert.Equal(t, areq.State, aresp.GetParameters().Get(consts.FormParameterState))
				assert.Equal(t, oauth2.ResponseModeQuery, areq.GetResponseMode())
			},
		},
		{
			name: "ShouldFailNoneResponseTypeWithInvalidScopes",
			requester: &oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{consts.ResponseTypeNone},
				Request: oauth2.Request{
					Client: &oauth2.DefaultClient{
						ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeNone},
						RedirectURIs:  []string{"https://asdf.de/cb"},
						Audience:      []string{"https://www.authelia.com/api"},
					},
					RequestedAudience: []string{"https://www.authelia.com/api"},
					RequestedScope:    oauth2.Arguments{"a", "b"},
					Session: &oauth2.DefaultSession{
						ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.AccessToken: time.Now().UTC().Add(time.Hour)},
					},
					RequestedAt: time.Now().UTC(),
				},
				State:       "superstate",
				RedirectURI: parseUrl("https://asdf.de/cb"),
			},
			expect: func(t *testing.T, requester *oauth2.AuthorizeRequest, responder *oauth2.AuthorizeResponse) {
				assert.Equal(t, strings.Join(requester.GrantedScope, " "), responder.GetParameters().Get(consts.FormParameterScope))
				assert.Equal(t, "", responder.GetParameters().Get(consts.FormParameterState))
				assert.Equal(t, oauth2.ResponseModeQuery, requester.GetResponseMode())
			},
			err: "The requested scope is invalid, unknown, or malformed. The OAuth 2.0 Client is not allowed to request scope 'a'.",
		},
		{
			name: "ShouldPassWithOnlyNoneResponseType",
			requester: &oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{consts.ResponseTypeNone},
				Request: oauth2.Request{
					Client: &oauth2.DefaultClient{
						ResponseTypes: oauth2.Arguments{consts.ResponseTypeNone},
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
				assert.Equal(t, strings.Join(areq.GrantedScope, " "), aresp.GetParameters().Get(consts.FormParameterScope))
				assert.Equal(t, areq.State, aresp.GetParameters().Get(consts.FormParameterState))
				assert.Equal(t, oauth2.ResponseModeQuery, areq.GetResponseMode())
			},
		},
		{
			name: "ShouldPassWithMultipleResponseType",
			requester: &oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{consts.ResponseTypeNone, consts.ResponseTypeAuthorizationCodeFlow},
				Request: oauth2.Request{
					Client: &oauth2.DefaultClient{
						ResponseTypes: oauth2.Arguments{consts.ResponseTypeNone, consts.ResponseTypeAuthorizationCodeFlow},
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
			expect: func(t *testing.T, requester *oauth2.AuthorizeRequest, responder *oauth2.AuthorizeResponse) {
				assert.Equal(t, "", responder.GetParameters().Get(consts.FormParameterScope))
				assert.Equal(t, "", responder.GetParameters().Get(consts.FormParameterState))
				assert.Equal(t, oauth2.ResponseModeType(""), requester.GetResponseMode())
			},
		},
		{
			name: "should pass but no scope in redirect uri",
			handler: &NoneResponseTypeHandler{
				Config: &oauth2.Config{
					ScopeStrategy:            oauth2.HierarchicScopeStrategy,
					AudienceMatchingStrategy: oauth2.DefaultAudienceMatchingStrategy,
					OmitRedirectScopeParam:   true,
				},
			},
			requester: &oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{consts.ResponseTypeNone},
				Request: oauth2.Request{
					Client: &oauth2.DefaultClient{
						ResponseTypes: oauth2.Arguments{consts.ResponseTypeNone, consts.ResponseTypeAuthorizationCodeFlow},
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
				assert.Empty(t, aresp.GetParameters().Get(consts.FormParameterScope))
				assert.Equal(t, areq.State, aresp.GetParameters().Get(consts.FormParameterState))
				assert.Equal(t, oauth2.ResponseModeQuery, areq.GetResponseMode())
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			responder := oauth2.NewAuthorizeResponse()

			var handler *NoneResponseTypeHandler

			if tc.handler == nil {
				handler = &NoneResponseTypeHandler{
					Config: &oauth2.Config{
						ScopeStrategy:            oauth2.HierarchicScopeStrategy,
						AudienceMatchingStrategy: oauth2.DefaultAudienceMatchingStrategy,
					},
				}
			} else {
				handler = tc.handler
			}

			err := handler.HandleAuthorizeEndpointRequest(context.Background(), tc.requester, responder)
			if len(tc.err) != 0 {
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)
			} else {
				assert.NoError(t, err)
			}

			if tc.expect != nil {
				tc.expect(t, tc.requester, responder)
			}
		})
	}
}
