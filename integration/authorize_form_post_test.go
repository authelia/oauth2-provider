// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	goauth "golang.org/x/oauth2"

	"github.com/authelia/goauth2"
	"github.com/authelia/goauth2/compose"
	"github.com/authelia/goauth2/handler/openid"
	"github.com/authelia/goauth2/internal"
	"github.com/authelia/goauth2/internal/gen"
	"github.com/authelia/goauth2/token/jwt"
)

type formPostTestCase struct {
	description  string
	setup        func()
	check        checkFunc
	responseType string
}

type checkFunc func(t *testing.T, stateFromServer string, code string, token goauth.Token, iDToken string, cparam url.Values, err map[string]string)

func TestAuthorizeFormPostResponseMode(t *testing.T) {
	session := &defaultSession{
		DefaultSession: &openid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Subject: "peter",
			},
			Headers: &jwt.Headers{},
		},
	}
	config := &goauth2.Config{ResponseModeHandlerExtension: &decoratedFormPostResponse{}, GlobalSecret: []byte("some-secret-thats-random-some-secret-thats-random-")}
	f := compose.ComposeAllEnabled(config, fositeStore, gen.MustRSAKey())
	ts := mockServer(t, f, session)
	defer ts.Close()

	oauthClient := newOAuth2Client(ts)
	defaultClient := fositeStore.Clients["my-client"].(*goauth2.DefaultClient)
	defaultClient.RedirectURIs[0] = ts.URL + "/callback"
	responseModeClient := &goauth2.DefaultResponseModeClient{
		DefaultClient: defaultClient,
		ResponseModes: []goauth2.ResponseModeType{goauth2.ResponseModeFormPost, goauth2.ResponseModeFormPost, "decorated_form_post"},
	}
	fositeStore.Clients["response-mode-client"] = responseModeClient
	oauthClient.ClientID = "response-mode-client"

	var state string
	for k, c := range []formPostTestCase{
		{
			description:  "implicit grant #1 test with form_post",
			responseType: "id_token%20token",
			setup: func() {
				state = "12345678901234567890"
				oauthClient.Scopes = []string{"openid"}
			},
			check: func(t *testing.T, stateFromServer string, code string, token goauth.Token, iDToken string, cparam url.Values, err map[string]string) {
				assert.EqualValues(t, state, stateFromServer)
				assert.NotEmpty(t, token.TokenType)
				assert.NotEmpty(t, token.AccessToken)
				assert.NotEmpty(t, token.Expiry)
				assert.NotEmpty(t, iDToken)
			},
		},
		{
			description:  "implicit grant #2 test with form_post",
			responseType: "id_token",
			setup: func() {
				state = "12345678901234567890"
				oauthClient.Scopes = []string{"openid"}
			},
			check: func(t *testing.T, stateFromServer string, code string, token goauth.Token, iDToken string, cparam url.Values, err map[string]string) {
				assert.EqualValues(t, state, stateFromServer)
				assert.NotEmpty(t, iDToken)
			},
		},
		{
			description:  "Authorization code grant test with form_post",
			responseType: "code",
			setup: func() {
				state = "12345678901234567890"
			},
			check: func(t *testing.T, stateFromServer string, code string, token goauth.Token, iDToken string, cparam url.Values, err map[string]string) {
				assert.EqualValues(t, state, stateFromServer)
				assert.NotEmpty(t, code)
			},
		},
		{
			description:  "Hybrid #1 grant test with form_post",
			responseType: "token%20code",
			setup: func() {
				state = "12345678901234567890"
				oauthClient.Scopes = []string{"openid"}
			},
			check: func(t *testing.T, stateFromServer string, code string, token goauth.Token, iDToken string, cparam url.Values, err map[string]string) {
				assert.EqualValues(t, state, stateFromServer)
				assert.NotEmpty(t, code)
				assert.NotEmpty(t, token.TokenType)
				assert.NotEmpty(t, token.AccessToken)
				assert.NotEmpty(t, token.Expiry)
			},
		},
		{
			description:  "Hybrid #2 grant test with form_post",
			responseType: "token%20id_token%20code",
			setup: func() {
				state = "12345678901234567890"
				oauthClient.Scopes = []string{"openid"}
			},
			check: func(t *testing.T, stateFromServer string, code string, token goauth.Token, iDToken string, cparam url.Values, err map[string]string) {
				assert.EqualValues(t, state, stateFromServer)
				assert.NotEmpty(t, code)
				assert.NotEmpty(t, iDToken)
				assert.NotEmpty(t, token.TokenType)
				assert.NotEmpty(t, token.AccessToken)
				assert.NotEmpty(t, token.Expiry)
			},
		},
		{
			description:  "Hybrid #3 grant test with form_post",
			responseType: "id_token%20code",
			setup: func() {
				state = "12345678901234567890"
				oauthClient.Scopes = []string{"openid"}
			},
			check: func(t *testing.T, stateFromServer string, code string, token goauth.Token, iDToken string, cparam url.Values, err map[string]string) {
				assert.EqualValues(t, state, stateFromServer)
				assert.NotEmpty(t, code)
				assert.NotEmpty(t, iDToken)
			},
		},
		{
			description:  "error message test for form_post response",
			responseType: "foo",
			setup: func() {
				state = "12345678901234567890"
			},
			check: func(t *testing.T, stateFromServer string, code string, token goauth.Token, iDToken string, cparam url.Values, err map[string]string) {
				assert.EqualValues(t, state, stateFromServer)
				assert.NotEmpty(t, err["ErrorField"])
				assert.NotEmpty(t, err["DescriptionField"])
			},
		},
	} {
		// Test canonical form_post
		t.Run(fmt.Sprintf("case=%d/description=%s", k, c.description), testFormPost(&state, false, c, oauthClient, "form_post"))

		// Test decorated form_post response
		c.check = decorateCheck(c.check)
		t.Run(fmt.Sprintf("case=%d/description=decorated_%s", k, c.description), testFormPost(&state, true, c, oauthClient, "decorated_form_post"))
	}
}

func testFormPost(state *string, customResponse bool, c formPostTestCase, oauthClient *goauth.Config, responseMode string) func(t *testing.T) {
	return func(t *testing.T) {
		c.setup()
		authURL := strings.Replace(oauthClient.AuthCodeURL(*state, goauth.SetAuthURLParam("response_mode", responseMode), goauth.SetAuthURLParam("nonce", "111111111")), "response_type=code", "response_type="+c.responseType, -1)
		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return errors.New("Dont follow redirects")
			},
		}
		resp, err := client.Get(authURL)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		code, state, token, iDToken, cparam, errResp, err := internal.ParseFormPostResponse(fositeStore.Clients["response-mode-client"].GetRedirectURIs()[0], resp.Body)
		require.NoError(t, err)
		c.check(t, state, code, iDToken, token, cparam, errResp)
	}
}

func decorateCheck(cf checkFunc) checkFunc {
	return func(t *testing.T, stateFromServer string, code string, token goauth.Token, iDToken string, cparam url.Values, err map[string]string) {
		cf(t, stateFromServer, code, token, iDToken, cparam, err)
		if len(err) > 0 {
			assert.Contains(t, cparam, "custom_err_param")
			return
		}
		assert.Contains(t, cparam, "custom_param")
	}
}

// This test type provides an example implementation
// of a custom response mode handler.
// In this case it decorates the `form_post` response mode
// with some additional custom parameters
type decoratedFormPostResponse struct {
}

func (m *decoratedFormPostResponse) ResponseModes() goauth2.ResponseModeTypes {
	return goauth2.ResponseModeTypes{"decorated_form_post"}
}

func (m *decoratedFormPostResponse) WriteAuthorizeResponse(ctx context.Context, rw http.ResponseWriter, ar goauth2.AuthorizeRequester, resp goauth2.AuthorizeResponder) {
	rw.Header().Add("Content-Type", "text/html;charset=UTF-8")
	resp.AddParameter("custom_param", "foo")
	goauth2.WriteAuthorizeFormPostResponse(ar.GetRedirectURI().String(), resp.GetParameters(), goauth2.GetPostFormHTMLTemplate(ctx,
		goauth2.NewOAuth2Provider(nil, new(goauth2.Config))), rw)
}

func (m *decoratedFormPostResponse) WriteAuthorizeError(ctx context.Context, rw http.ResponseWriter, ar goauth2.AuthorizeRequester, err error) {
	rfcerr := goauth2.ErrorToRFC6749Error(err)
	errors := rfcerr.ToValues()
	errors.Set("state", ar.GetState())
	errors.Add("custom_err_param", "bar")
	goauth2.WriteAuthorizeFormPostResponse(ar.GetRedirectURI().String(), errors, goauth2.GetPostFormHTMLTemplate(ctx,
		goauth2.NewOAuth2Provider(nil, new(goauth2.Config))), rw)
}
