// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/token/jwt"
)

// OAuth 2.1 draft-17 Section 4.1.1 and Section 4.1.2.
func TestAuthorizeOptionalState(t *testing.T) {
	session := &defaultSession{
		DefaultSession: &openid.DefaultSession{
			Claims:  &jwt.IDTokenClaims{Subject: "peter"},
			Headers: &jwt.Headers{},
		},
	}

	provider := compose.ComposeAllEnabled(&oauth2.Config{
		GlobalSecret:                          []byte("some-secret-thats-random-some-secret-thats-random-"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
	}, store, gen.MustRSAKey())

	ts := mockServer(t, provider, session)
	defer ts.Close()

	store.Clients["my-client"].(*oauth2.DefaultClient).RedirectURIs[0] = ts.URL + "/callback"

	testCases := []struct {
		name         string
		responseType string
		scope        string
		state        string
		fragment     bool
		expected     string
		err          string
	}{
		{
			name:         "ShouldOmitStateAuthorizationCode",
			responseType: consts.ResponseTypeAuthorizationCodeFlow,
			scope:        "oauth2",
			expected:     consts.FormParameterAuthorizationCode,
		},
		{
			name:         "ShouldOmitStateImplicitToken",
			responseType: consts.ResponseTypeImplicitFlowToken,
			scope:        "oauth2",
			fragment:     true,
			expected:     consts.AccessResponseAccessToken,
		},
		{
			name:         "ShouldOmitStateImplicitIDToken",
			responseType: consts.ResponseTypeImplicitFlowIDToken,
			scope:        consts.ScopeOpenID,
			fragment:     true,
			expected:     consts.AccessResponseIDToken,
		},
		{
			name:         "ShouldOmitStateImplicitBoth",
			responseType: consts.ResponseTypeImplicitFlowBoth,
			scope:        consts.ScopeOpenID,
			fragment:     true,
			expected:     consts.AccessResponseIDToken,
		},
		{
			name:         "ShouldOmitStateHybridIDToken",
			responseType: consts.ResponseTypeHybridFlowIDToken,
			scope:        consts.ScopeOpenID,
			fragment:     true,
			expected:     consts.FormParameterAuthorizationCode,
		},
		{
			name:         "ShouldOmitStateHybridBoth",
			responseType: consts.ResponseTypeHybridFlowBoth,
			scope:        consts.ScopeOpenID,
			fragment:     true,
			expected:     consts.FormParameterAuthorizationCode,
		},
		{
			name:         "ShouldOmitStateError",
			responseType: consts.ResponseTypeAuthorizationCodeFlow,
			scope:        "not-exist",
			err:          "invalid_scope",
		},
		{
			name:         "ShouldRejectShortState",
			responseType: consts.ResponseTypeAuthorizationCodeFlow,
			scope:        "oauth2",
			state:        "short",
			err:          "invalid_request",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			query := url.Values{
				consts.FormParameterClientID:     {"my-client"},
				consts.FormParameterRedirectURI:  {ts.URL + "/callback"},
				consts.FormParameterResponseType: {tc.responseType},
				consts.FormParameterScope:        {tc.scope},
				consts.FormParameterNonce:        {"nonce-" + tc.name},
			}

			if tc.state != "" {
				query.Set(consts.FormParameterState, tc.state)
			}

			var location *url.URL

			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					location = req.URL

					return http.ErrUseLastResponse
				},
			}

			resp, err := client.Get(ts.URL + "/auth?" + query.Encode())
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			require.NotNil(t, location)

			raw := location.RawQuery
			if tc.fragment {
				raw = location.Fragment
			}

			values, err := url.ParseQuery(raw)
			require.NoError(t, err)

			if tc.err != "" {
				assert.Equal(t, tc.err, values.Get(consts.FormParameterError))
			} else {
				assert.Empty(t, values.Get(consts.FormParameterError))
				assert.NotEmpty(t, values.Get(tc.expected))
			}

			if tc.state != "" {
				assert.Equal(t, tc.state, values.Get(consts.FormParameterState))
			} else {
				assert.NotContains(t, values, consts.FormParameterState)
			}
		})
	}
}
