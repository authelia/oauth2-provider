// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/internal/consts"
)

// FAPI 2.0 Security Profile Section 5.3.4.
func TestValidateBearerAuthorizationURIQueryAccessToken(t *testing.T) {
	const queryRejection = "An access token in the URI query is not accepted under the FAPI 2.0 Security Profile."

	fapi2 := &DefaultRegisteredClient{DefaultClient: &DefaultClient{ID: "client"}, FAPI2SecurityProfile: true}

	testCases := []struct {
		name      string
		transport string
		profile   bool
		recorded  Client
		store     ClientGetter
		err       error
		debug     string
	}{
		{name: "ShouldAcceptAQueryTokenOfAnotherClient", transport: "query", recorded: &DefaultClient{ID: "client"}},
		{name: "ShouldRejectAQueryTokenOfAFAPI2Client", transport: "query", recorded: fapi2, err: ErrInvalidRequest, debug: queryRejection},
		{name: "ShouldRejectAQueryTokenOfAFAPI2Registration", transport: "query", recorded: &DefaultClient{ID: "client"}, store: bearerClients{"client": fapi2}, err: ErrInvalidRequest, debug: queryRejection},
		{name: "ShouldRejectAQueryTokenOfAFAPI2Server", transport: "query", profile: true, recorded: &DefaultClient{ID: "client"}, err: ErrInvalidRequest, debug: queryRejection},
		{name: "ShouldRejectAQueryTokenWithABasicHeaderOfAFAPI2Client", transport: "basic", recorded: fapi2, err: ErrInvalidRequest, debug: queryRejection},
		{name: "ShouldPassAHeaderTokenOfAFAPI2ClientToTheBindingCheck", transport: "header", recorded: fapi2, err: ErrInvalidToken, debug: "is not sender-constrained"},
		{name: "ShouldPassABodyTokenOfAFAPI2ClientToTheBindingCheck", transport: "body", recorded: fapi2, err: ErrInvalidToken, debug: "is not sender-constrained"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			const token = "the-token"

			var r *http.Request

			switch tc.transport {
			case "query":
				r = httptest.NewRequest(http.MethodGet, "https://as.example.com/introspect?access_token="+token, nil)
			case "basic":
				r = httptest.NewRequest(http.MethodGet, "https://as.example.com/introspect?access_token="+token, nil)
				r.SetBasicAuth("client", "secret")
			case "header":
				r = httptest.NewRequest(http.MethodGet, "https://as.example.com/introspect", nil)
				r.Header.Set(consts.HeaderAuthorization, "Bearer "+token)
			case "body":
				r = httptest.NewRequest(http.MethodPost, "https://as.example.com/introspect", strings.NewReader(url.Values{consts.FormParameterAccessToken: {token}}.Encode()))
				r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
			}

			require.NoError(t, r.ParseForm())

			requester := newBearerRequester([]string{"read"}, []string{"urn:aud"}).(*Request)
			requester.Client = tc.recorded

			_, err := ValidateBearerAuthorization(t.Context(), &Config{FAPI2SecurityProfile: tc.profile}, tc.store, r, requester, token, BearerAuthorization{Audiences: []string{"urn:aud"}, Scopes: []string{"read"}})

			if tc.err == nil {
				require.NoError(t, ErrorToDebugRFC6749Error(err))

				return
			}

			require.ErrorIs(t, err, tc.err)
			assert.Contains(t, ErrorToDebugRFC6749Error(err).Error(), tc.debug)
		})
	}
}

// FAPI 2.0 Security Profile Section 5.3.4.
func TestAccessTokenCredentialFromRequestFAPI2SecurityProfile(t *testing.T) {
	testCases := []struct {
		name     string
		profile  bool
		expected string
	}{
		{name: "ShouldReadTheQueryTokenWhenEnabled", expected: "the-token"},
		{name: "ShouldIgnoreTheQueryTokenOfAFAPI2Server", profile: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := &Fosite{Config: &Config{AccessTokenURIQueryParameterEnabled: true, FAPI2SecurityProfile: tc.profile}}

			r := httptest.NewRequest(http.MethodGet, "https://as.example.com/userinfo?access_token=the-token", nil)
			require.NoError(t, r.ParseForm())

			token, _, err := f.accessTokenCredentialFromRequest(t.Context(), r)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, token)
		})
	}
}
