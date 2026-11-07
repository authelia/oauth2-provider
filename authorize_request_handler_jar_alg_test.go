// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestRequestObjectRejectsUnadvertisedAlg(t *testing.T) {
	const secret = "foobarfoobarfoobarfoobarfoobarfoobar"

	testCases := []struct {
		name    string
		allowed []string
		err     bool
	}{
		{name: "ShouldRejectWhenNotAdvertised", allowed: []string{"ES256"}, err: true},
		{name: "ShouldAcceptWhenAdvertised", allowed: []string{"HS256"}},
		{name: "ShouldAcceptByDefault"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := storage.NewMemoryStore()
			store.Clients["test"] = &oauth2.DefaultJARClient{
				DefaultClient: &oauth2.DefaultClient{
					ID:            "test",
					ClientSecret:  oauth2.NewPlainTextClientSecret(secret),
					RedirectURIs:  []string{"https://client.example.com/callback"},
					ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
					Scopes:        []string{consts.ScopeOpenID},
				},
				RequestObjectSigningAlg: string(jose.HS256),
			}

			config := &oauth2.Config{Issuer: "https://auth.example.com", RequestObjectSigningAlgValues: tc.allowed}
			config.JWTStrategy = &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{})}

			provider := &oauth2.Fosite{Store: store, Config: config}

			client := store.Clients["test"].(*oauth2.DefaultJARClient)

			request, _, err := config.JWTStrategy.Encode(t.Context(), jwt.MapClaims{
				consts.ClaimIssuer:               "test",
				consts.ClaimAudience:             "https://auth.example.com",
				consts.FormParameterClientID:     "test",
				consts.FormParameterResponseType: consts.ResponseTypeAuthorizationCodeFlow,
				consts.FormParameterScope:        consts.ScopeOpenID,
				consts.FormParameterRedirectURI:  "https://client.example.com/callback",
				consts.FormParameterState:        "abcdefghijkl",
				consts.ClaimExpirationTime:       time.Now().Add(time.Minute).Unix(),
			}, jwt.WithHeaders(&jwt.Headers{Extra: map[string]any{consts.JSONWebTokenHeaderType: consts.JSONWebTokenTypeJWT}}), jwt.WithJARClient(client))
			require.NoError(t, err)

			query := url.Values{
				consts.FormParameterClientID:     {"test"},
				consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow},
				consts.FormParameterScope:        {consts.ScopeOpenID},
				consts.FormParameterRedirectURI:  {"https://client.example.com/callback"},
				consts.FormParameterState:        {"abcdefghijkl"},
				consts.FormParameterRequest:      {request},
			}

			r := &http.Request{Method: http.MethodGet, URL: &url.URL{Path: "/authorize", RawQuery: query.Encode()}, Header: http.Header{}}

			_, err = provider.NewAuthorizeRequest(t.Context(), r)

			if !tc.err {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				return
			}

			require.ErrorIs(t, err, oauth2.ErrInvalidRequestObject)
			assert.NotErrorIs(t, err, oauth2.ErrServerError)
		})
	}
}
