// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestDefaultResponseModeHandlerJWTRedirectURIQuery(t *testing.T) {
	testCases := []struct {
		name string
		mode ResponseModeType
	}{
		{
			name: "ShouldHandleQueryJWT",
			mode: ResponseModeQueryJWT,
		},
		{
			name: "ShouldHandleJWT",
			mode: ResponseModeJWT,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{IDTokenIssuer: "https://auth.example.com"}
			config.JWTSecuredAuthorizeResponseModeStrategy = &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())}

			handler := &DefaultResponseModeHandler{Config: config}

			redirectURI, err := url.Parse("https://client.example.com/callback?sub=victim&foo=bar")
			require.NoError(t, err)

			request := NewAuthorizeRequest()
			request.RedirectURI = redirectURI
			request.ResponseMode = tc.mode
			request.ResponseTypes = Arguments{consts.ResponseTypeAuthorizationCodeFlow}
			request.Client = &DefaultRegisteredClient{DefaultClient: &DefaultClient{ID: "client"}, AuthorizationSignedResponseAlg: "RS256"}

			response := NewAuthorizeResponse()
			response.AddParameter(consts.FormParameterAuthorizationCode, "code-value")
			response.AddParameter(consts.FormParameterState, "state-value")

			rw := httptest.NewRecorder()

			handler.WriteAuthorizeResponse(context.Background(), rw, request, response)

			require.Equal(t, http.StatusSeeOther, rw.Code)

			location, err := url.Parse(rw.Header().Get(consts.HeaderLocation))
			require.NoError(t, err)

			query := location.Query()

			// RFC 6749 Section 3.1.2: the query component of the redirection URI MUST be retained.
			assert.Equal(t, "victim", query.Get("sub"))
			assert.Equal(t, "bar", query.Get("foo"))
			assert.Empty(t, query.Get(consts.FormParameterAuthorizationCode))
			require.NotEmpty(t, query.Get(consts.FormParameterResponse))

			claims := testDecodeJWTPayload(t, query.Get(consts.FormParameterResponse))

			assert.Equal(t, "code-value", claims[consts.FormParameterAuthorizationCode])
			assert.Equal(t, "state-value", claims[consts.FormParameterState])
			assert.Equal(t, "https://auth.example.com", claims[jwt.ClaimIssuer])
			assert.NotContains(t, claims, jwt.ClaimSubject)
			assert.NotContains(t, claims, "foo")
		})
	}
}

func testDecodeJWTPayload(t *testing.T, token string) map[string]any {
	t.Helper()

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	claims := map[string]any{}

	require.NoError(t, json.Unmarshal(payload, &claims))

	return claims
}
