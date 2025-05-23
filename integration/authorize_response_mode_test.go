// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/pkg/errors"
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

func TestAuthorizeResponseModes(t *testing.T) {
	session := &defaultSession{
		DefaultSession: &openid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Subject: "peter",
			},
			Headers: &jwt.Headers{},
		},
	}
	provider := compose.ComposeAllEnabled(&oauth2.Config{
		UseLegacyErrorFormat: true,
		GlobalSecret:         []byte("some-secret-thats-random-some-secret-thats-random-"),
	}, store, gen.MustRSAKey())
	ts := mockServer(t, provider, session)
	defer ts.Close()

	oauthClient := newOAuth2Client(ts)
	defaultClient := store.Clients["my-client"].(*oauth2.DefaultClient)
	defaultClient.RedirectURIs[0] = ts.URL + "/callback"
	responseModeClient := &oauth2.DefaultResponseModeClient{
		DefaultClient: defaultClient,
		ResponseModes: []oauth2.ResponseModeType{},
	}
	store.Clients[testClientIDResponseMode] = responseModeClient
	oauthClient.ClientID = testClientIDResponseMode

	var state string
	for k, c := range []struct {
		description  string
		setup        func()
		check        func(t *testing.T, stateFromServer string, code string, token xoauth2.Token, iDToken string, err map[string]string)
		responseType string
		responseMode string
	}{
		{
			description:  "Should give err because implicit grant with response mode query",
			responseType: consts.ResponseTypeImplicitFlowBoth,
			responseMode: consts.ResponseModeQuery,
			setup: func() {
				state = testState
				oauthClient.Scopes = []string{consts.ScopeOpenID}
				responseModeClient.ResponseModes = []oauth2.ResponseModeType{oauth2.ResponseModeQuery}
			},
			check: func(t *testing.T, stateFromServer string, code string, token xoauth2.Token, iDToken string, err map[string]string) {
				assert.NotEmpty(t, err["ErrorField"])
				assert.NotEmpty(t, err["DescriptionField"])
				assert.Equal(t, "Insecure response_mode 'query' for the response_type '[id_token token]'.", err["HintField"])
			},
		},
		{
			description:  "Should pass implicit grant with response mode form_post",
			responseType: consts.ResponseTypeImplicitFlowBoth,
			responseMode: consts.ResponseModeFormPost,
			setup: func() {
				state = testState
				oauthClient.Scopes = []string{consts.ScopeOpenID}
				responseModeClient.ResponseModes = []oauth2.ResponseModeType{oauth2.ResponseModeFormPost}
			},
			check: func(t *testing.T, stateFromServer string, code string, token xoauth2.Token, iDToken string, err map[string]string) {
				assert.EqualValues(t, state, stateFromServer)
				assert.NotEmpty(t, token.TokenType)
				assert.NotEmpty(t, token.AccessToken)
				assert.NotEmpty(t, token.Expiry)
				assert.NotEmpty(t, iDToken)
			},
		},
		{
			description:  "Should fail because response mode form_post is not allowed by the client",
			responseType: consts.ResponseTypeImplicitFlowBoth,
			responseMode: consts.ResponseModeFormPost,
			setup: func() {
				state = testState
				oauthClient.Scopes = []string{consts.ScopeOpenID}
				responseModeClient.ResponseModes = []oauth2.ResponseModeType{oauth2.ResponseModeQuery}
			},
			check: func(t *testing.T, stateFromServer string, code string, token xoauth2.Token, iDToken string, err map[string]string) {
				assert.NotEmpty(t, err["ErrorField"])
				assert.NotEmpty(t, err["DescriptionField"])
				assert.Equal(t, "The 'response_mode' requested was 'form_post', but the Authorization Server or registered OAuth 2.0 client doesn't allow or support this mode.", err["HintField"])
			},
		},
		{
			description:  "Should fail because response mode form_post is not allowed by the client without legacy format",
			responseType: consts.ResponseTypeImplicitFlowBoth,
			responseMode: consts.ResponseModeFormPost,
			setup: func() {
				state = testState
				oauthClient.Scopes = []string{consts.ScopeOpenID}
				responseModeClient.ResponseModes = []oauth2.ResponseModeType{oauth2.ResponseModeQuery}
				provider.(*oauth2.Fosite).Config.(*oauth2.Config).UseLegacyErrorFormat = false
			},
			check: func(t *testing.T, stateFromServer string, code string, token xoauth2.Token, iDToken string, err map[string]string) {
				provider.(*oauth2.Fosite).Config.(*oauth2.Config).UseLegacyErrorFormat = true // reset
				assert.NotEmpty(t, err["ErrorField"])
				assert.Equal(t, "The authorization server does not support obtaining a response using this response mode. The 'response_mode' requested was 'form_post', but the Authorization Server or registered OAuth 2.0 client doesn't allow or support this mode.", err["DescriptionField"])
				assert.Empty(t, err["HintField"])
			},
		},
		{
			description:  "Should pass Authorization code grant test with response mode fragment",
			responseType: consts.ResponseTypeAuthorizationCodeFlow,
			responseMode: consts.ResponseModeFragment,
			setup: func() {
				state = testState
				responseModeClient.ResponseModes = []oauth2.ResponseModeType{oauth2.ResponseModeFragment}
			},
			check: func(t *testing.T, stateFromServer string, code string, token xoauth2.Token, iDToken string, err map[string]string) {
				assert.EqualValues(t, state, stateFromServer)
				assert.NotEmpty(t, code)
			},
		},
		{
			description:  "Should pass Authorization code grant test with response mode form_post",
			responseType: consts.ResponseTypeAuthorizationCodeFlow,
			responseMode: consts.ResponseModeFormPost,
			setup: func() {
				state = testState
				responseModeClient.ResponseModes = []oauth2.ResponseModeType{oauth2.ResponseModeFormPost}
			},
			check: func(t *testing.T, stateFromServer string, code string, token xoauth2.Token, iDToken string, err map[string]string) {
				assert.EqualValues(t, state, stateFromServer)
				assert.NotEmpty(t, code)
			},
		},
		{
			description:  "Should fail Hybrid grant test with query",
			responseType: consts.ResponseTypeHybridFlowToken,
			responseMode: consts.ResponseModeQuery,
			setup: func() {
				state = testState
				oauthClient.Scopes = []string{consts.ScopeOpenID}
				responseModeClient.ResponseModes = []oauth2.ResponseModeType{oauth2.ResponseModeQuery}
			},
			check: func(t *testing.T, stateFromServer string, code string, token xoauth2.Token, iDToken string, err map[string]string) {
				assert.NotEmpty(t, err["ErrorField"])
				assert.NotEmpty(t, err["DescriptionField"])
				assert.Equal(t, "Insecure response_mode 'query' for the response_type '[code token]'.", err["HintField"])
			},
		},
		{
			description:  "Should fail Hybrid grant test with query without legacy fields",
			responseType: consts.ResponseTypeHybridFlowToken,
			responseMode: consts.ResponseModeQuery,
			setup: func() {
				state = testState
				oauthClient.Scopes = []string{consts.ScopeOpenID}
				responseModeClient.ResponseModes = []oauth2.ResponseModeType{oauth2.ResponseModeQuery}
				provider.(*oauth2.Fosite).Config.(*oauth2.Config).UseLegacyErrorFormat = false
			},
			check: func(t *testing.T, stateFromServer string, code string, token xoauth2.Token, iDToken string, err map[string]string) {
				provider.(*oauth2.Fosite).Config.(*oauth2.Config).UseLegacyErrorFormat = true // reset

				assert.NotEmpty(t, err["ErrorField"])
				assert.Equal(t, "The authorization server does not support obtaining a response using this response mode. Insecure response_mode 'query' for the response_type '[code token]'.", err["DescriptionField"])
				assert.Empty(t, err["HintField"])
				assert.Empty(t, err["DebugField"])
			},
		},
		{
			description:  "Should pass Hybrid grant test with form_post",
			responseType: consts.ResponseTypeHybridFlowToken,
			responseMode: consts.ResponseModeFormPost,
			setup: func() {
				state = testState
				oauthClient.Scopes = []string{consts.ScopeOpenID}
				responseModeClient.ResponseModes = []oauth2.ResponseModeType{oauth2.ResponseModeFormPost}
			},
			check: func(t *testing.T, stateFromServer string, code string, token xoauth2.Token, iDToken string, err map[string]string) {
				assert.EqualValues(t, state, stateFromServer)
				assert.NotEmpty(t, code)
				assert.NotEmpty(t, token.TokenType)
				assert.NotEmpty(t, token.AccessToken)
				assert.NotEmpty(t, token.Expiry)
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, c.description), func(t *testing.T) {
			c.setup()

			authURL := oauthClient.AuthCodeURL(
				state,
				xoauth2.SetAuthURLParam(consts.FormParameterResponseType, c.responseType),
				xoauth2.SetAuthURLParam(consts.FormParameterResponseMode, c.responseMode),
				xoauth2.SetAuthURLParam(consts.FormParameterNonce, "111111111"))

			var (
				callbackURL *url.URL
				redirErr    = errors.New("Dont follow redirects")
			)

			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					callbackURL = req.URL
					return redirErr
				},
			}

			var (
				code, state, iDToken string
				token                xoauth2.Token
				errResp              map[string]string
			)

			resp, err := client.Get(authURL)

			switch oauth2.ResponseModeType(c.responseMode) {
			case oauth2.ResponseModeFragment:
				// fragment
				require.EqualError(t, errors.Unwrap(err), redirErr.Error())
				fragment, err := url.ParseQuery(callbackURL.Fragment)
				require.NoError(t, err)
				code, state, iDToken, token, errResp = getParameters(t, fragment)
			case oauth2.ResponseModeQuery:
				// query
				require.EqualError(t, errors.Unwrap(err), redirErr.Error())
				query, err := url.ParseQuery(callbackURL.RawQuery)
				require.NoError(t, err)
				code, state, iDToken, token, errResp = getParameters(t, query)
			case oauth2.ResponseModeFormPost:
				// form_post
				require.NoError(t, err)
				code, state, iDToken, token, _, errResp, err = internal.ParseFormPostResponse(store.Clients[testClientIDResponseMode].GetRedirectURIs()[0], resp.Body)
				assert.NoError(t, err)
			default:
				t.FailNow()
			}

			c.check(t, state, code, token, iDToken, errResp)
		})
	}
}

func getParameters(t *testing.T, param url.Values) (code, state, iDToken string, token xoauth2.Token, errResp map[string]string) {
	errResp = make(map[string]string)
	if param.Get(consts.FormParameterError) != "" {
		errResp["ErrorField"] = param.Get(consts.FormParameterError)
		errResp["DescriptionField"] = param.Get(consts.FormParameterErrorDescription)
		errResp["HintField"] = param.Get(consts.FormParameterErrorHint)
	} else {
		code = param.Get(consts.FormParameterAuthorizationCode)
		state = param.Get(consts.FormParameterState)
		iDToken = param.Get(consts.AccessResponseIDToken)
		token = xoauth2.Token{
			AccessToken:  param.Get(consts.AccessResponseAccessToken),
			TokenType:    param.Get(consts.AccessResponseTokenType),
			RefreshToken: param.Get(consts.AccessResponseRefreshToken),
		}
		if param.Get(consts.AccessResponseExpiresIn) != "" {
			expires, err := strconv.Atoi(param.Get(consts.AccessResponseExpiresIn))
			require.NoError(t, err)
			token.Expiry = time.Now().UTC().Add(time.Duration(expires) * time.Second)
		}
	}
	return
}
