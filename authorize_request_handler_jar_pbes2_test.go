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

func TestRequestObjectPasswordBasedEncryption(t *testing.T) {
	testCases := []struct {
		name    string
		encAlg  string
		maximum int
		err     string
	}{
		{"ShouldRejectWhenNotRegistered", "", 0, "jwe header 'alg' value 'PBES2-HS256+A128KW' is a password based algorithm the client has not registered"},
		{"ShouldRejectWhenAnotherAlgorithmIsRegistered", string(jose.A128KW), 0, "jwe header 'alg' value 'PBES2-HS256+A128KW' is a password based algorithm the client has not registered"},
		{"ShouldRejectAboveConfiguredMaximum", string(jose.PBES2_HS256_A128KW), 300000, "jwe header 'p2c' has an invalid value '600000': more than 300000"},
		{"ShouldAcceptWhenRegistered", string(jose.PBES2_HS256_A128KW), 0, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := storage.NewMemoryStore()
			store.Clients["test"] = &oauth2.DefaultJARClient{
				DefaultClient: &oauth2.DefaultClient{
					ID:            "test",
					ClientSecret:  oauth2.NewPlainTextClientSecret(testPBES2RequestObjectSecret),
					RedirectURIs:  []string{"https://client.example.com/callback"},
					ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
					Scopes:        []string{consts.ScopeOpenID},
				},
				RequestObjectSigningAlg:    string(jose.HS256),
				RequestObjectEncryptionAlg: tc.encAlg,
			}

			config := &oauth2.Config{IDTokenIssuer: "https://auth.example.com", JWEPBES2CountMaximum: tc.maximum}
			config.JWTStrategy = &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{})}

			provider := &oauth2.Fosite{Store: store, Config: config}

			query := url.Values{
				consts.FormParameterClientID:     {"test"},
				consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow},
				consts.FormParameterScope:        {consts.ScopeOpenID},
				consts.FormParameterRedirectURI:  {"https://client.example.com/callback"},
				consts.FormParameterState:        {"abcdefghijkl"},
				consts.FormParameterRequest:      {testPBES2RequestObject(t)},
			}

			r := &http.Request{Method: http.MethodGet, URL: &url.URL{Path: "/authorize", RawQuery: query.Encode()}, Header: http.Header{}}

			_, err := provider.NewAuthorizeRequest(t.Context(), r)

			if tc.err == "" {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				return
			}

			require.ErrorIs(t, err, oauth2.ErrInvalidRequestObject)
			assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), tc.err)
		})
	}
}

const testPBES2RequestObjectSecret = "foobarfoobarfoobarfoobarfoobarfoobar"

func testPBES2RequestObject(t *testing.T) string {
	t.Helper()

	client := &oauth2.DefaultJARClient{
		DefaultClient:              &oauth2.DefaultClient{ID: "test", ClientSecret: oauth2.NewPlainTextClientSecret(testPBES2RequestObjectSecret)},
		RequestObjectSigningAlg:    string(jose.HS256),
		RequestObjectEncryptionAlg: string(jose.PBES2_HS256_A128KW),
		RequestObjectEncryptionEnc: string(jose.A128GCM),
	}

	config := &oauth2.Config{}
	strategy := &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{})}

	token, _, err := strategy.Encode(t.Context(), jwt.MapClaims{
		consts.ClaimIssuer:               "test",
		consts.ClaimAudience:             "https://auth.example.com",
		consts.FormParameterClientID:     "test",
		consts.FormParameterResponseType: consts.ResponseTypeAuthorizationCodeFlow,
		consts.FormParameterScope:        consts.ScopeOpenID,
		consts.FormParameterRedirectURI:  "https://client.example.com/callback",
		consts.FormParameterState:        "abcdefghijkl",
		consts.ClaimExpirationTime:       time.Now().Add(time.Minute).Unix(),
	}, jwt.WithHeaders(&jwt.Headers{Extra: map[string]any{consts.JSONWebTokenHeaderType: consts.JSONWebTokenTypeJWT}}), jwt.WithHeadersJWE(&jwt.Headers{}), jwt.WithJARClient(client))
	require.NoError(t, err)
	require.True(t, jwt.IsEncryptedJWT(token))

	return token
}
