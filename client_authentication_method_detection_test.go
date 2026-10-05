// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestAuthenticateClientDetectsEveryPresentedMethod(t *testing.T) {
	const (
		audience = "https://as.example.com"
		secret   = "0123456789abcdef0123456789abcdef"
	)

	key := gen.MustRSAKey()

	set := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{KeyID: "kid-foo", Use: "sig", Algorithm: "RS256", Key: &key.PublicKey}},
	}

	newClient := func(method string, multiple bool) Client {
		return &TestClientAuthenticationPolicyClient{
			DefaultJARClient: &DefaultJARClient{
				DefaultClient:           &DefaultClient{ID: "test", ClientSecret: NewPlainTextClientSecret(secret)},
				JSONWebKeys:             set,
				TokenEndpointAuthMethod: method,
			},
			AllowMultipleAuthenticationMethods: multiple,
		}
	}

	assertion := func() string {
		return mustGenerateClientAssertion(t, jwt.MapClaims{
			consts.ClaimSubject:        "test",
			consts.ClaimIssuer:         "test",
			consts.ClaimJWTID:          "12345",
			consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
			consts.ClaimAudience:       []string{audience},
		}, jose.RS256, jwt.JSONWebTokenTypeClientAuthentication, "kid-foo", key)
	}

	testCases := []struct {
		name   string
		client Client
		header http.Header
		form   url.Values
		method string
		err    string
	}{
		{
			name:   "ShouldRejectClientAssertionWithClientSecret",
			client: newClient(consts.ClientAuthMethodPrivateKeyJWT, false),
			form: url.Values{
				consts.FormParameterClientSecret:        []string{secret},
				consts.FormParameterClientAssertion:     []string{assertion()},
				consts.FormParameterClientAssertionType: []string{consts.ClientAssertionTypeJWTBearer},
			},
			err: "more than one known authentication method",
		},
		{
			name:   "ShouldRejectClientSecretBasicWithClientSecretInTheBody",
			client: newClient(consts.ClientAuthMethodClientSecretBasic, false),
			header: clientBasicAuthHeader("test", secret),
			form:   url.Values{consts.FormParameterClientSecret: []string{secret}},
			err:    "more than one known authentication method",
		},
		{
			name:   "ShouldRejectClientSecretWithoutClientID",
			client: newClient(consts.ClientAuthMethodClientSecretPost, false),
			form:   url.Values{consts.FormParameterClientSecret: []string{secret}},
			err:    "The Client ID was missing from the request",
		},
		{
			name:   "ShouldCompareTheBodySecretForClientSecretPostWhenMultipleMethodsAllowed",
			client: newClient(consts.ClientAuthMethodClientSecretPost, true),
			header: clientBasicAuthHeader("test", "wrong"),
			form:   url.Values{consts.FormParameterClientID: []string{"test"}, consts.FormParameterClientSecret: []string{secret}},
			method: consts.ClientAuthMethodClientSecretPost,
		},
		{
			name:   "ShouldRejectAnInvalidBodySecretForClientSecretPostWhenMultipleMethodsAllowed",
			client: newClient(consts.ClientAuthMethodClientSecretPost, true),
			header: clientBasicAuthHeader("test", secret),
			form:   url.Values{consts.FormParameterClientID: []string{"test"}, consts.FormParameterClientSecret: []string{"wrong"}},
			err:    "secrets don't match",
		},
		{
			name:   "ShouldCompareTheHeaderSecretForClientSecretBasicWhenMultipleMethodsAllowed",
			client: newClient(consts.ClientAuthMethodClientSecretBasic, true),
			header: clientBasicAuthHeader("test", secret),
			form:   url.Values{consts.FormParameterClientID: []string{"test"}, consts.FormParameterClientSecret: []string{"wrong"}},
			method: consts.ClientAuthMethodClientSecretBasic,
		},
		{
			name:   "ShouldRejectAnInvalidHeaderSecretForClientSecretBasicWhenMultipleMethodsAllowed",
			client: newClient(consts.ClientAuthMethodClientSecretBasic, true),
			header: clientBasicAuthHeader("test", "wrong"),
			form:   url.Values{consts.FormParameterClientID: []string{"test"}, consts.FormParameterClientSecret: []string{secret}},
			err:    "secrets don't match",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{
				JWKSFetcherStrategy:          NewDefaultJWKSFetcherStrategy(),
				AllowedJWTAssertionAudiences: []string{audience},
			}

			config.JWTStrategy = &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

			store := storage.NewMemoryStore()
			store.Clients["test"] = tc.client

			provider := &Fosite{Store: store, Config: config}

			r := &http.Request{Header: http.Header{}}

			if tc.header != nil {
				r.Header = tc.header
			}

			client, method, err := provider.AuthenticateClientWithAuthHandler(context.Background(), r, tc.form, &TokenEndpointClientAuthStrategy{})

			if tc.err != "" {
				assert.Nil(t, client)
				require.Error(t, err)
				assert.Contains(t, ErrorToDebugRFC6749Error(err).Error(), tc.err)

				return
			}

			require.NoError(t, ErrorToDebugRFC6749Error(err))
			require.NotNil(t, client)
			assert.Equal(t, tc.method, method)
		})
	}
}
