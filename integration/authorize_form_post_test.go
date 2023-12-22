// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

type formPostTestCase struct {
	name         string
	setup        func(t *testing.T, server *httptest.Server) (state string, client *xoauth2.Config)
	check        checkFunc
	responseType string
}

type checkFunc func(t *testing.T, expectedState, actualState string, code string, token xoauth2.Token, iDToken string, cparam url.Values, err map[string]string)

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
			responseType: "id_token%20token",
			state:        "12345678901234567890",
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
			state:        "12345678901234567890",
			setup:        func(t *testing.T, client *xoauth2.Config, server *httptest.Server) {},
			check: func(t *testing.T, expectedState, actualState string, code string, token xoauth2.Token, iDToken string, cparam url.Values, err map[string]string) {
				assert.Equal(t, expectedState, actualState)
				assert.NotEmpty(t, iDToken)
			},
		},
		{
			name:         "ShouldHandleAuthorizationCodeFlow",
			responseType: consts.ResponseTypeAuthorizationCodeFlow,
			state:        "12345678901234567890",
			setup:        func(t *testing.T, client *xoauth2.Config, server *httptest.Server) {},
			check: func(t *testing.T, expectedState, actualState string, code string, token xoauth2.Token, iDToken string, cparam url.Values, err map[string]string) {
				assert.Equal(t, expectedState, actualState)
				assert.NotEmpty(t, code)
			},
		},
		{
			name:         "ShouldHandleHybridFlowToken",
			responseType: "token%20code",
			state:        "12345678901234567890",
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
			responseType: "token%20id_token%20code",
			state:        "12345678901234567890",
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
			responseType: "id_token%20code",
			state:        "12345678901234567890",
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
			state:        "12345678901234567890",
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

				store.Clients["response-mode-client"] = &oauth2.DefaultResponseModeClient{
					DefaultClient: &oauth2.DefaultClient{
						ID:            "response-mode-client",
						Secret:        []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`), // = "foobar"
						RedirectURIs:  []string{server.URL + "/callback"},
						ResponseTypes: []string{consts.ResponseTypeImplicitFlowIDToken, consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeImplicitFlowBoth, consts.ResponseTypeHybridFlowIDToken, consts.ResponseTypeHybridFlowToken, consts.ResponseTypeHybridFlowBoth},
						GrantTypes:    []string{consts.GrantTypeImplicit, consts.GrantTypeRefreshToken, consts.GrantTypeAuthorizationCode, consts.GrantTypeResourceOwnerPasswordCredentials, consts.GrantTypeClientCredentials},
						Scopes:        []string{"oauth2", consts.ScopeOffline, consts.ScopeOpenID},
						Audience:      []string{tokenURL},
					},
					ResponseModes: []oauth2.ResponseModeType{oauth2.ResponseModeFormPost, oauth2.ResponseModeFormPost, "decorated_form_post"},
				}

				client := newOAuth2Client(server)
				client.ClientID = "response-mode-client"
				client.Scopes = []string{consts.ScopeOpenID}

				authURL := strings.Replace(client.AuthCodeURL(tc.state, xoauth2.SetAuthURLParam(consts.FormParameterResponseMode, consts.ResponseModeFormPost), xoauth2.SetAuthURLParam("nonce", "111111111")), "response_type=code", "response_type="+tc.responseType, -1)

				c := &http.Client{
					CheckRedirect: func(req *http.Request, via []*http.Request) error {
						return errors.New("Dont follow redirects")
					},
				}

				resp, err := c.Get(authURL)
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, resp.StatusCode)
				code, actualState, token, iDToken, cparam, errResp, err := internal.ParseFormPostResponse(store.Clients["response-mode-client"].GetRedirectURIs()[0], resp.Body)
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

				store.Clients["response-mode-client"] = &oauth2.DefaultResponseModeClient{
					DefaultClient: &oauth2.DefaultClient{
						ID:            "response-mode-client",
						Secret:        []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`), // = "foobar"
						RedirectURIs:  []string{server.URL + "/callback"},
						ResponseTypes: []string{consts.ResponseTypeImplicitFlowIDToken, consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeImplicitFlowBoth, consts.ResponseTypeHybridFlowIDToken, consts.ResponseTypeHybridFlowToken, consts.ResponseTypeHybridFlowBoth},
						GrantTypes:    []string{consts.GrantTypeImplicit, consts.GrantTypeRefreshToken, consts.GrantTypeAuthorizationCode, consts.GrantTypeResourceOwnerPasswordCredentials, consts.GrantTypeClientCredentials},
						Scopes:        []string{"oauth2", consts.ScopeOffline, consts.ScopeOpenID},
						Audience:      []string{tokenURL},
					},
					ResponseModes: []oauth2.ResponseModeType{oauth2.ResponseModeFormPost, oauth2.ResponseModeFormPost, "decorated_form_post"},
				}

				client := newOAuth2Client(server)
				client.ClientID = "response-mode-client"
				client.Scopes = []string{consts.ScopeOpenID}

				authURL := strings.Replace(client.AuthCodeURL(tc.state, xoauth2.SetAuthURLParam(consts.FormParameterResponseMode, "decorated_form_post"), xoauth2.SetAuthURLParam("nonce", "111111111")), "response_type=code", "response_type="+tc.responseType, -1)

				c := &http.Client{
					CheckRedirect: func(req *http.Request, via []*http.Request) error {
						return errors.New("Dont follow redirects")
					},
				}

				resp, err := c.Get(authURL)
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, resp.StatusCode)
				code, actualState, token, iDToken, cparam, errResp, err := internal.ParseFormPostResponse(store.Clients["response-mode-client"].GetRedirectURIs()[0], resp.Body)
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

func (m *DecoratedFormPostResponse) WriteAuthorizeResponse(ctx context.Context, rw http.ResponseWriter, ar oauth2.AuthorizeRequester, resp oauth2.AuthorizeResponder) {
	rw.Header().Add(consts.HeaderContentType, consts.ContentTypeTextHTML)
	resp.AddParameter("custom_param", "foo")
	oauth2.WriteAuthorizeFormPostResponse(ar.GetRedirectURI().String(), resp.GetParameters(), oauth2.GetPostFormHTMLTemplate(ctx,
		new(oauth2.Config)), rw)
}

func (m *DecoratedFormPostResponse) WriteAuthorizeError(ctx context.Context, rw http.ResponseWriter, ar oauth2.AuthorizeRequester, err error) {
	rfcerr := oauth2.ErrorToRFC6749Error(err)
	errors := rfcerr.ToValues()
	errors.Set(consts.FormParameterState, ar.GetState())
	errors.Add("custom_err_param", "bar")
	oauth2.WriteAuthorizeFormPostResponse(ar.GetRedirectURI().String(), errors, oauth2.GetPostFormHTMLTemplate(ctx,
		new(oauth2.Config)), rw)
}
