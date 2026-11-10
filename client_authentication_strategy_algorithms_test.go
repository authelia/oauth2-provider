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

func TestClientAssertionRejectsUnadvertisedAlg(t *testing.T) {
	const issuer = "https://as.example.com"

	key := gen.MustRSAKey()

	config, provider := newUnadvertisedAlgProvider(t, key, &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{KeyID: "kid-foo", Use: "sig", Algorithm: "RS256", Key: &key.PublicKey}},
	}, "RS256", []string{"ES256"})

	assertion := mustGenerateClientAssertion(t, jwt.MapClaims{
		consts.ClaimSubject:        "bar",
		consts.ClaimIssuer:         "bar",
		consts.ClaimJWTID:          "12345",
		consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
		consts.ClaimAudience:       issuer,
	}, jose.RS256, jwt.JSONWebTokenTypeClientAuthentication, "kid-foo", key)

	form := url.Values{
		consts.FormParameterClientAssertion:     {assertion},
		consts.FormParameterClientAssertionType: {consts.ClientAssertionTypeJWTBearer},
	}

	_, _, err := provider.AuthenticateClientWithAuthHandler(context.Background(), new(http.Request), form, config.GetTokenEndpointClientAuthStrategy(context.Background()))

	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidClient)
	assert.NotErrorIs(t, err, ErrServerError)

	config.ClientAssertionSigningAlgValues = []string{"RS256"}

	client, _, err := provider.AuthenticateClientWithAuthHandler(context.Background(), new(http.Request), form, config.GetTokenEndpointClientAuthStrategy(context.Background()))

	require.NoError(t, ErrorToDebugRFC6749Error(err))
	assert.NotNil(t, client)
}

func TestClientAssertionRejectsUnadvertisedJWE(t *testing.T) {
	const issuer = "https://as.example.com"

	key := gen.MustRSAKey()

	config, provider := newUnadvertisedAlgProvider(t, key, &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{KeyID: "kid-foo", Use: "sig", Algorithm: "RS256", Key: &key.PublicKey}},
	}, "RS256", nil)

	config.ClientAssertionEncryptionAlgValues = []string{"ECDH-ES"}

	signed := mustGenerateClientAssertion(t, jwt.MapClaims{
		consts.ClaimSubject:        "bar",
		consts.ClaimIssuer:         "bar",
		consts.ClaimJWTID:          "12345",
		consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
		consts.ClaimAudience:       issuer,
	}, jose.RS256, jwt.JSONWebTokenTypeClientAuthentication, "kid-foo", key)

	encrypter, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: jose.RSA_OAEP_256, Key: &key.PublicKey}, (&jose.EncrypterOptions{}).WithContentType(jwt.JSONWebTokenTypeJWT))
	require.NoError(t, err)

	object, err := encrypter.Encrypt([]byte(signed))
	require.NoError(t, err)

	assertion, err := object.CompactSerialize()
	require.NoError(t, err)

	form := url.Values{
		consts.FormParameterClientAssertion:     {assertion},
		consts.FormParameterClientAssertionType: {consts.ClientAssertionTypeJWTBearer},
	}

	_, _, err = provider.AuthenticateClientWithAuthHandler(context.Background(), new(http.Request), form, config.GetTokenEndpointClientAuthStrategy(context.Background()))

	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidClient)
	assert.NotErrorIs(t, err, ErrServerError)
	assert.Contains(t, ErrorToDebugRFC6749Error(err).Error(), "RSA-OAEP-256")
}

func newUnadvertisedAlgProvider(t *testing.T, key any, set *jose.JSONWebKeySet, registered string, allowed []string) (config *Config, provider *Fosite) {
	t.Helper()

	config = &Config{
		JWKSFetcherStrategy:             NewDefaultJWKSFetcherStrategy(),
		Issuer:                          "https://as.example.com",
		ClientAssertionSigningAlgValues: allowed,
	}

	config.JWTStrategy = &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

	store := storage.NewMemoryStore()
	store.Clients["bar"] = &DefaultJARClient{
		DefaultClient:               &DefaultClient{ID: "bar", ClientSecret: testClientSecretBar},
		JSONWebKeys:                 set,
		TokenEndpointAuthMethod:     consts.ClientAuthMethodPrivateKeyJWT,
		TokenEndpointAuthSigningAlg: registered,
	}

	return config, &Fosite{Store: store, Config: config}
}
