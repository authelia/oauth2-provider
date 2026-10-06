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

func TestDefaultJARClientTokenEndpointAuthDefaults(t *testing.T) {
	const (
		audience = "https://as.example.com"
		secret   = "0123456789abcdef0123456789abcdef"
	)

	key := gen.MustES256Key()

	set := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{KeyID: "kid-foo", Use: "sig", Algorithm: "ES256", Key: &key.PublicKey}},
	}

	claims := jwt.MapClaims{
		consts.ClaimSubject:        "test",
		consts.ClaimIssuer:         "test",
		consts.ClaimJWTID:          "12345",
		consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
		consts.ClaimAudience:       []string{audience},
	}

	formAssertion := func(assertion string) url.Values {
		return url.Values{
			consts.FormParameterClientAssertion:     []string{assertion},
			consts.FormParameterClientAssertionType: []string{consts.ClientAssertionTypeJWTBearer},
		}
	}

	testCases := []struct {
		name   string
		client *DefaultJARClient
		header http.Header
		form   url.Values
		method string
		err    string
	}{
		{
			// RFC 7591 Section 2.
			name:   "ShouldAuthenticateClientSecretBasicWithoutARegisteredMethod",
			client: &DefaultJARClient{DefaultClient: &DefaultClient{ID: "test", ClientSecret: NewPlainTextClientSecret(secret)}},
			header: clientBasicAuthHeader("test", secret),
			form:   url.Values{},
			method: consts.ClientAuthMethodClientSecretBasic,
		},
		{
			name:   "ShouldRejectClientSecretPostWithoutARegisteredMethod",
			client: &DefaultJARClient{DefaultClient: &DefaultClient{ID: "test", ClientSecret: NewPlainTextClientSecret(secret)}},
			form:   url.Values{consts.FormParameterClientID: []string{"test"}, consts.FormParameterClientSecret: []string{secret}},
			err:    "is configured to only support 'token_endpoint_auth_method' method 'client_secret_basic'",
		},
		{
			// OpenID Connect Dynamic Client Registration 1.0 Section 2.
			name: "ShouldAuthenticateClientSecretJWTWithoutARegisteredSigningAlg",
			client: &DefaultJARClient{
				DefaultClient:           &DefaultClient{ID: "test", ClientSecret: NewPlainTextClientSecret(secret)},
				TokenEndpointAuthMethod: consts.ClientAuthMethodClientSecretJWT,
			},
			form:   formAssertion(mustGenerateHSAssertion(t, claims, []byte(secret))),
			method: consts.ClientAuthMethodClientSecretJWT,
		},
		{
			name: "ShouldAuthenticatePrivateKeyJWTWithoutARegisteredSigningAlg",
			client: &DefaultJARClient{
				DefaultClient:           &DefaultClient{ID: "test"},
				JSONWebKeys:             set,
				TokenEndpointAuthMethod: consts.ClientAuthMethodPrivateKeyJWT,
			},
			form:   formAssertion(mustGenerateClientAssertion(t, claims, jose.ES256, jwt.JSONWebTokenTypeClientAuthentication, "kid-foo", key)),
			method: consts.ClientAuthMethodPrivateKeyJWT,
		},
		{
			name: "ShouldRejectAnAlgorithmOtherThanTheRegisteredSigningAlg",
			client: &DefaultJARClient{
				DefaultClient:               &DefaultClient{ID: "test"},
				JSONWebKeys:                 set,
				TokenEndpointAuthMethod:     consts.ClientAuthMethodPrivateKeyJWT,
				TokenEndpointAuthSigningAlg: string(jose.RS256),
			},
			form: formAssertion(mustGenerateClientAssertion(t, claims, jose.ES256, jwt.JSONWebTokenTypeClientAuthentication, "kid-foo", key)),
			err:  "expects client assertions to be signed with the 'alg' header value 'RS256'",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{
				JWKSFetcherStrategy:          NewDefaultJWKSFetcherStrategy(),
				AllowedJWTAssertionAudiences: []string{audience},
			}

			config.JWTStrategy = &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())}

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
