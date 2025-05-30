// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xoauth2 "golang.org/x/oauth2"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestAuthorizeFormPostResponseMode(t *testing.T) {
	testCases := []struct {
		name         string
		setup        func(t *testing.T, client *xoauth2.Config, server *httptest.Server)
		check        checkFunc
		responseType string
		state        string
	}{
		{
			name:         "ShouldHandleImplicitFlowBoth",
			responseType: consts.ResponseTypeImplicitFlowBoth,
			state:        testState,
			setup:        func(t *testing.T, client *xoauth2.Config, server *httptest.Server) {},
			check: func(t *testing.T, expectedState, actualState string, code string, token xoauth2.Token, iDToken string, cparam url.Values, err map[string]string) {
				assert.Equal(t, expectedState, actualState)
				assert.NotEmpty(t, token.TokenType)
				assert.NotEmpty(t, token.AccessToken)
				assert.NotEmpty(t, token.Expiry)
				assert.NotEmpty(t, iDToken)
			},
		},
		{
			name:         "ShouldHandleImplicitFlowIDToken",
			responseType: consts.ResponseTypeImplicitFlowIDToken,
			state:        testState,
			setup:        func(t *testing.T, client *xoauth2.Config, server *httptest.Server) {},
			check: func(t *testing.T, expectedState, actualState string, code string, token xoauth2.Token, iDToken string, cparam url.Values, err map[string]string) {
				assert.Equal(t, expectedState, actualState)
				assert.NotEmpty(t, iDToken)
			},
		},
		{
			name:         "ShouldHandleAuthorizationCodeFlow",
			responseType: consts.ResponseTypeAuthorizationCodeFlow,
			state:        testState,
			setup:        func(t *testing.T, client *xoauth2.Config, server *httptest.Server) {},
			check: func(t *testing.T, expectedState, actualState string, code string, token xoauth2.Token, iDToken string, cparam url.Values, err map[string]string) {
				assert.Equal(t, expectedState, actualState)
				assert.NotEmpty(t, code)
			},
		},
		{
			name:         "ShouldHandleHybridFlowToken",
			responseType: consts.ResponseTypeHybridFlowToken,
			state:        testState,
			setup:        func(t *testing.T, client *xoauth2.Config, server *httptest.Server) {},
			check: func(t *testing.T, expectedState, actualState string, code string, token xoauth2.Token, iDToken string, cparam url.Values, err map[string]string) {
				assert.Equal(t, expectedState, actualState)
				assert.NotEmpty(t, code)
				assert.NotEmpty(t, token.TokenType)
				assert.NotEmpty(t, token.AccessToken)
				assert.NotEmpty(t, token.Expiry)
			},
		},
		{
			name:         "ShouldHandleHybridFlowBoth",
			responseType: consts.ResponseTypeHybridFlowBoth,
			state:        testState,
			setup:        func(t *testing.T, client *xoauth2.Config, server *httptest.Server) {},
			check: func(t *testing.T, expectedState, actualState string, code string, token xoauth2.Token, iDToken string, cparam url.Values, err map[string]string) {
				assert.Equal(t, expectedState, actualState)
				assert.NotEmpty(t, code)
				assert.NotEmpty(t, iDToken)
				assert.NotEmpty(t, token.TokenType)
				assert.NotEmpty(t, token.AccessToken)
				assert.NotEmpty(t, token.Expiry)
			},
		},
		{
			name:         "ShouldHandleHybridFlowIDToken",
			responseType: consts.ResponseTypeHybridFlowIDToken,
			state:        testState,
			setup:        func(t *testing.T, client *xoauth2.Config, server *httptest.Server) {},
			check: func(t *testing.T, expectedState, actualState string, code string, token xoauth2.Token, iDToken string, cparam url.Values, err map[string]string) {
				assert.Equal(t, expectedState, actualState)
				assert.NotEmpty(t, code)
				assert.NotEmpty(t, iDToken)
			},
		},
		{
			name:         "ShouldHandleFailure",
			responseType: "foo",
			state:        testState,
			setup:        func(t *testing.T, client *xoauth2.Config, server *httptest.Server) {},
			check: func(t *testing.T, expectedState, actualState string, code string, token xoauth2.Token, iDToken string, cparam url.Values, err map[string]string) {
				assert.Equal(t, expectedState, actualState)
				assert.NotEmpty(t, err["ErrorField"])
				assert.NotEmpty(t, err["DescriptionField"])
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("Canonical", func(t *testing.T) {
				session := &defaultSession{
					DefaultSession: &openid.DefaultSession{
						Claims: &jwt.IDTokenClaims{
							Subject: "peter",
						},
						Headers: &jwt.Headers{},
					},
				}

				config := &oauth2.Config{GlobalSecret: []byte("some-secret-thats-random-some-secret-thats-random-")}
				config.ResponseModeHandlers = []oauth2.ResponseModeHandler{&oauth2.DefaultResponseModeHandler{Config: config}, &DecoratedFormPostResponse{}}

				f := compose.ComposeAllEnabled(config, store, gen.MustRSAKey())
				server := mockServer(t, f, session)

				defer server.Close()

				store.Clients[testClientIDResponseMode] = &oauth2.DefaultResponseModeClient{
					DefaultClient: &oauth2.DefaultClient{
						ID:            testClientIDResponseMode,
						ClientSecret:  oauth2.NewBCryptClientSecret(`$2a$04$6i/O2OM9CcEVTRLq9uFDtOze4AtISH79iYkZeEUsos4WzWtCnJ52y`), // = "foobar"
						RedirectURIs:  []string{server.URL + "/callback"},
						ResponseTypes: []string{consts.ResponseTypeImplicitFlowIDToken, consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeImplicitFlowBoth, consts.ResponseTypeHybridFlowIDToken, consts.ResponseTypeHybridFlowToken, consts.ResponseTypeHybridFlowBoth},
						GrantTypes:    []string{consts.GrantTypeImplicit, consts.GrantTypeRefreshToken, consts.GrantTypeAuthorizationCode, consts.GrantTypeResourceOwnerPasswordCredentials, consts.GrantTypeClientCredentials},
						Scopes:        []string{"oauth2", consts.ScopeOffline, consts.ScopeOpenID},
						Audience:      []string{tokenURL},
					},
					ResponseModes: []oauth2.ResponseModeType{oauth2.ResponseModeFormPost, oauth2.ResponseModeFormPost, "decorated_form_post"},
				}

				client := newOAuth2Client(server)
				client.ClientID = testClientIDResponseMode
				client.Scopes = []string{consts.ScopeOpenID}

				authURL := client.AuthCodeURL(
					tc.state,
					xoauth2.SetAuthURLParam(consts.FormParameterResponseMode, "decorated_form_post"),
					xoauth2.SetAuthURLParam(consts.FormParameterNonce, "111111111"),
					xoauth2.SetAuthURLParam(consts.FormParameterResponseType, tc.responseType),
				)

				c := &http.Client{
					CheckRedirect: func(req *http.Request, via []*http.Request) error {
						return errors.New("Dont follow redirects")
					},
				}

				resp, err := c.Get(authURL)
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, resp.StatusCode)
				code, actualState, token, iDToken, cparam, errResp, err := internal.ParseFormPostResponse(store.Clients[testClientIDResponseMode].GetRedirectURIs()[0], resp.Body)
				require.NoError(t, err)

				tc.check(t, tc.state, actualState, code, iDToken, token, cparam, errResp)
			})

			t.Run("Decorated", func(t *testing.T) {
				session := &defaultSession{
					DefaultSession: &openid.DefaultSession{
						Claims: &jwt.IDTokenClaims{
							Subject: "peter",
						},
						Headers: &jwt.Headers{},
					},
				}

				config := &oauth2.Config{GlobalSecret: []byte("some-secret-thats-random-some-secret-thats-random-")}
				config.ResponseModeHandlers = []oauth2.ResponseModeHandler{&oauth2.DefaultResponseModeHandler{Config: config}, &DecoratedFormPostResponse{}}

				f := compose.ComposeAllEnabled(config, store, gen.MustRSAKey())
				server := mockServer(t, f, session)

				defer server.Close()

				store.Clients[testClientIDResponseMode] = &oauth2.DefaultResponseModeClient{
					DefaultClient: &oauth2.DefaultClient{
						ID:            testClientIDResponseMode,
						ClientSecret:  oauth2.NewBCryptClientSecret(`$2a$04$6i/O2OM9CcEVTRLq9uFDtOze4AtISH79iYkZeEUsos4WzWtCnJ52y`), // = "foobar"
						RedirectURIs:  []string{server.URL + "/callback"},
						ResponseTypes: []string{consts.ResponseTypeImplicitFlowIDToken, consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeImplicitFlowBoth, consts.ResponseTypeHybridFlowIDToken, consts.ResponseTypeHybridFlowToken, consts.ResponseTypeHybridFlowBoth},
						GrantTypes:    []string{consts.GrantTypeImplicit, consts.GrantTypeRefreshToken, consts.GrantTypeAuthorizationCode, consts.GrantTypeResourceOwnerPasswordCredentials, consts.GrantTypeClientCredentials},
						Scopes:        []string{"oauth2", consts.ScopeOffline, consts.ScopeOpenID},
						Audience:      []string{tokenURL},
					},
					ResponseModes: []oauth2.ResponseModeType{oauth2.ResponseModeFormPost, oauth2.ResponseModeFormPost, "decorated_form_post"},
				}

				client := newOAuth2Client(server)
				client.ClientID = testClientIDResponseMode
				client.Scopes = []string{consts.ScopeOpenID}

				authURL := client.AuthCodeURL(
					tc.state,
					xoauth2.SetAuthURLParam(consts.FormParameterResponseMode, "decorated_form_post"),
					xoauth2.SetAuthURLParam(consts.FormParameterNonce, "111111111"),
					xoauth2.SetAuthURLParam(consts.FormParameterResponseType, tc.responseType),
				)

				c := &http.Client{
					CheckRedirect: func(req *http.Request, via []*http.Request) error {
						return errors.New("Dont follow redirects")
					},
				}

				resp, err := c.Get(authURL)
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, resp.StatusCode)
				code, actualState, token, iDToken, cparam, errResp, err := internal.ParseFormPostResponse(store.Clients[testClientIDResponseMode].GetRedirectURIs()[0], resp.Body)
				require.NoError(t, err)

				tc.check(t, tc.state, actualState, code, iDToken, token, cparam, errResp)

				if len(errResp) > 0 {
					assert.Contains(t, cparam, "custom_err_param")
					return
				}
				assert.Contains(t, cparam, "custom_param")
			})
		})
	}
}

// This test type provides an example implementation
// of a custom response mode handler.
// In this case it decorates the `form_post` response mode
// with some additional custom parameters
type DecoratedFormPostResponse struct{}

func (m *DecoratedFormPostResponse) ResponseModes() oauth2.ResponseModeTypes {
	return oauth2.ResponseModeTypes{"decorated_form_post"}
}

func (m *DecoratedFormPostResponse) WriteAuthorizeResponse(ctx context.Context, rw http.ResponseWriter, requester oauth2.AuthorizeRequester, responder oauth2.AuthorizeResponder) {
	rw.Header().Add(consts.HeaderContentType, consts.ContentTypeTextHTML)
	responder.AddParameter("custom_param", "foo")
	oauth2.DefaultFormPostResponseWriter(rw, oauth2.GetPostFormHTMLTemplate(ctx, new(oauth2.Config)), requester.GetRedirectURI().String(), responder.GetParameters())
}

func (m *DecoratedFormPostResponse) WriteAuthorizeError(ctx context.Context, rw http.ResponseWriter, requester oauth2.AuthorizeRequester, err error) {
	rfc := oauth2.ErrorToRFC6749Error(err)
	errors := rfc.ToValues()
	errors.Set(consts.FormParameterState, requester.GetState())
	errors.Add("custom_err_param", "bar")
	oauth2.DefaultFormPostResponseWriter(rw, oauth2.GetPostFormHTMLTemplate(ctx, new(oauth2.Config)), requester.GetRedirectURI().String(), errors)
}

type checkFunc func(t *testing.T, expectedState, actualState string, code string, token xoauth2.Token, iDToken string, cparam url.Values, err map[string]string)
