// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/token/jwt"
)

// RFC 9126 Section 2.1.
func TestPushedAuthorizeRequestRejectsWhatTheAuthorizationEndpointWould(t *testing.T) {
	f := compose.ComposeAllEnabled(&oauth2.Config{
		RedirectSecureChecker:                 oauth2.IsRedirectURISecure,
		GlobalSecret:                          []byte("some-secret-thats-random-some-secret-thats-random-"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
		EnforcePKCE:                           true,
	}, store, gen.MustRSAKey())

	ts := mockServer(t, f, newIDSession(&jwt.IDTokenClaims{Subject: "peter"}))
	defer ts.Close()

	oauthClient := newOAuth2Client(ts)

	client := store.Clients["my-client"].(*oauth2.DefaultClient)
	client.RedirectURIs = []string{ts.URL + "/callback"}

	challenge := func() string {
		sum := sha256.Sum256([]byte(newTestNonce() + newTestNonce()))

		return base64.RawURLEncoding.EncodeToString(sum[:])
	}

	testCases := []struct {
		name     string
		params   url.Values
		setup    func(t *testing.T)
		status   int
		expected string
	}{
		{
			name:   "ShouldAcceptAValidRequest",
			status: http.StatusCreated,
		},
		{
			name:     "ShouldRejectAnUnknownCodeChallengeMethod",
			params:   url.Values{consts.FormParameterCodeChallengeMethod: {"bogus"}},
			status:   http.StatusBadRequest,
			expected: "invalid_request",
		},
		{
			name:     "ShouldRejectAMissingCodeChallengeWhenPKCEIsEnforced",
			params:   url.Values{consts.FormParameterCodeChallenge: {""}, consts.FormParameterCodeChallengeMethod: {""}},
			status:   http.StatusBadRequest,
			expected: "invalid_request",
		},
		{
			name:     "ShouldRejectAMalformedCodeChallenge",
			params:   url.Values{consts.FormParameterCodeChallenge: {strings.Repeat("a", 43)}},
			status:   http.StatusBadRequest,
			expected: "invalid_request",
		},
		{
			name:     "ShouldRejectAnUnknownPromptValue",
			params:   url.Values{consts.FormParameterPrompt: {"nonsense"}},
			status:   http.StatusBadRequest,
			expected: "invalid_request",
		},
		{
			name:     "ShouldRejectPromptNoneWithOtherValues",
			params:   url.Values{consts.FormParameterPrompt: {"none login"}},
			status:   http.StatusBadRequest,
			expected: "invalid_request",
		},
		{
			name:     "ShouldRejectAMalformedMaxAge",
			params:   url.Values{consts.FormParameterMaximumAge: {"abc"}},
			status:   http.StatusBadRequest,
			expected: "invalid_request",
		},
		{
			name:     "ShouldRejectAnImplicitIDTokenRequestWithoutANonce",
			params:   url.Values{consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowIDToken}, consts.FormParameterNonce: {""}},
			status:   http.StatusBadRequest,
			expected: "invalid_request",
		},
		{
			name:     "ShouldRejectAHybridIDTokenRequestWithoutANonce",
			params:   url.Values{consts.FormParameterResponseType: {consts.ResponseTypeHybridFlowIDToken}, consts.FormParameterNonce: {""}},
			status:   http.StatusBadRequest,
			expected: "invalid_request",
		},
		{
			name:     "ShouldRejectAHybridIDTokenRequestWithoutTheOpenIDScope",
			params:   url.Values{consts.FormParameterResponseType: {consts.ResponseTypeHybridFlowIDToken}, consts.FormParameterScope: {"oauth2"}},
			status:   http.StatusBadRequest,
			expected: "invalid_scope",
		},
		{
			name:     "ShouldRejectAnImplicitIDTokenRequestWithoutTheOpenIDScope",
			params:   url.Values{consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowIDToken}, consts.FormParameterScope: {"oauth2"}},
			status:   http.StatusBadRequest,
			expected: "invalid_scope",
		},
		{
			name:   "ShouldRejectAHybridRequestFromAClientWithoutTheAuthorizationCodeGrant",
			params: url.Values{consts.FormParameterResponseType: {consts.ResponseTypeHybridFlowIDToken}},
			setup: func(t *testing.T) {
				grants := client.GrantTypes
				client.GrantTypes = []string{consts.GrantTypeImplicit}

				t.Cleanup(func() { client.GrantTypes = grants })
			},
			status:   http.StatusBadRequest,
			expected: "invalid_grant",
		},
		{
			name:   "ShouldRejectAnImplicitRequestFromAClientWithoutTheImplicitGrant",
			params: url.Values{consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowIDToken}},
			setup: func(t *testing.T) {
				grants := client.GrantTypes
				client.GrantTypes = []string{consts.GrantTypeAuthorizationCode}

				t.Cleanup(func() { client.GrantTypes = grants })
			},
			status:   http.StatusBadRequest,
			expected: "invalid_grant",
		},
		{
			name:   "ShouldRejectAnImplicitTokenRequestFromAClientWithoutTheImplicitGrant",
			params: url.Values{consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterScope: {"oauth2"}},
			setup: func(t *testing.T) {
				grants := client.GrantTypes
				client.GrantTypes = []string{consts.GrantTypeAuthorizationCode}

				t.Cleanup(func() { client.GrantTypes = grants })
			},
			status:   http.StatusBadRequest,
			expected: "unauthorized_client",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setup != nil {
				tc.setup(t)
			}

			data := url.Values{
				consts.FormParameterClientID:            {oauthClient.ClientID},
				consts.FormParameterClientSecret:        {oauthClient.ClientSecret},
				consts.FormParameterResponseType:        {consts.ResponseTypeAuthorizationCodeFlow},
				consts.FormParameterState:               {testState},
				consts.FormParameterScope:               {consts.ScopeOpenID},
				consts.FormParameterRedirectURI:         {oauthClient.RedirectURL},
				consts.FormParameterCodeChallenge:       {challenge()},
				consts.FormParameterCodeChallengeMethod: {consts.PKCEChallengeMethodSHA256},
				consts.FormParameterNonce:               {newTestNonce()},
			}

			for key, values := range tc.params {
				if len(values) == 1 && values[0] == "" {
					data.Del(key)

					continue
				}

				data[key] = values
			}

			resp, err := http.PostForm(ts.URL+"/par", data)
			require.NoError(t, err)

			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			assert.Equal(t, tc.status, resp.StatusCode, string(body))

			if tc.expected == "" {
				return
			}

			m := map[string]any{}
			require.NoError(t, json.Unmarshal(body, &m))
			assert.Equal(t, tc.expected, m[consts.FormParameterError])
			assert.Nil(t, m[consts.FormParameterRequestURI])
		})
	}
}
