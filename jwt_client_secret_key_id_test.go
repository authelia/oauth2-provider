// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestClientAssertionClientSecretAlgorithmWithKeyID(t *testing.T) {
	for _, alg := range []jose.SignatureAlgorithm{jose.HS256, jose.HS384, jose.HS512} {
		t.Run(string(alg), func(t *testing.T) {
			store := storage.NewMemoryStore()
			store.Clients["test"] = &oauth2.DefaultRegisteredClient{
				DefaultClient: &oauth2.DefaultClient{
					ID:           "test",
					ClientSecret: oauth2.NewPlainTextClientSecret(testClientSecretKeyIDSecret),
				},
				TokenEndpointAuthMethod: consts.ClientAuthMethodClientSecretJWT,
			}

			config := &oauth2.Config{AllowedJWTAssertionAudiences: []string{"token-url"}}
			config.JWTStrategy = &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{})}

			provider := &oauth2.Fosite{Store: store, Config: config}

			form := url.Values{
				consts.FormParameterClientAssertionType: {consts.ClientAssertionTypeJWTBearer},
				consts.FormParameterClientAssertion: {testClientSecretKeyIDToken(t, alg, jwt.MapClaims{
					consts.ClaimIssuer:         "test",
					consts.ClaimSubject:        "test",
					consts.ClaimAudience:       "token-url",
					consts.ClaimJWTID:          uuid.NewString(),
					consts.ClaimIssuedAt:       time.Now().Unix(),
					consts.ClaimExpirationTime: time.Now().Add(time.Minute).Unix(),
				})},
			}

			_, _, err := provider.AuthenticateClient(t.Context(), &http.Request{Header: http.Header{}}, form)

			require.ErrorIs(t, err, oauth2.ErrInvalidClient)
			assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "'kid' header value 'abc'")
		})
	}
}

func TestRequestObjectClientSecretAlgorithmWithKeyID(t *testing.T) {
	for _, alg := range []jose.SignatureAlgorithm{jose.HS256, jose.HS384, jose.HS512} {
		t.Run(string(alg), func(t *testing.T) {
			store := storage.NewMemoryStore()
			store.Clients["test"] = &oauth2.DefaultJARClient{
				DefaultClient: &oauth2.DefaultClient{
					ID:            "test",
					ClientSecret:  oauth2.NewPlainTextClientSecret(testClientSecretKeyIDSecret),
					RedirectURIs:  []string{"https://client.example.com/callback"},
					ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
					Scopes:        []string{consts.ScopeOpenID},
				},
				RequestObjectSigningAlg: string(alg),
			}

			config := &oauth2.Config{IDTokenIssuer: "https://auth.example.com"}
			config.JWTStrategy = &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{})}

			provider := &oauth2.Fosite{Store: store, Config: config}

			query := url.Values{
				consts.FormParameterClientID:     {"test"},
				consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow},
				consts.FormParameterScope:        {consts.ScopeOpenID},
				consts.FormParameterRedirectURI:  {"https://client.example.com/callback"},
				consts.FormParameterRequest: {testClientSecretKeyIDToken(t, alg, jwt.MapClaims{
					consts.ClaimIssuer:               "test",
					consts.ClaimAudience:             "https://auth.example.com",
					consts.FormParameterClientID:     "test",
					consts.FormParameterResponseType: consts.ResponseTypeAuthorizationCodeFlow,
					consts.FormParameterScope:        consts.ScopeOpenID,
					consts.FormParameterRedirectURI:  "https://client.example.com/callback",
					consts.ClaimExpirationTime:       time.Now().Add(time.Minute).Unix(),
				})},
			}

			r := &http.Request{Method: http.MethodGet, URL: &url.URL{Path: "/authorize", RawQuery: query.Encode()}, Header: http.Header{}}

			_, err := provider.NewAuthorizeRequest(t.Context(), r)

			require.ErrorIs(t, err, oauth2.ErrInvalidRequestObject)
			assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "'kid' header value 'abc'")
		})
	}
}

const testClientSecretKeyIDSecret = "foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoob"

func testClientSecretKeyIDToken(t *testing.T, alg jose.SignatureAlgorithm, claims jwt.MapClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(alg, claims)
	token.Header[consts.JSONWebTokenHeaderKeyIdentifier] = "abc"

	signed, err := token.CompactSignedString([]byte(testClientSecretKeyIDSecret))
	require.NoError(t, err)

	return signed
}
