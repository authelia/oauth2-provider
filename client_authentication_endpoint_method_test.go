// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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

func TestEndpointClientAuthStrategyFallsBackToTheTokenEndpoint(t *testing.T) {
	const (
		audience = "https://as.example.com"
		secret   = "0123456789abcdef0123456789abcdef"
	)

	var (
		introspection = &IntrospectionEndpointClientAuthStrategy{}
		revocation    = &RevocationEndpointClientAuthStrategy{}
	)

	key := gen.MustRSAKey()
	cert := gen.MustCertificate(gen.CertificateOptions{Subject: pkix.Name{CommonName: "test"}, DNSNames: []string{"client.example.com"}})

	set := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{KeyID: "kid-foo", Use: "sig", Algorithm: "RS256", Key: &key.PublicKey}},
	}

	claims := jwt.MapClaims{
		consts.ClaimSubject:        "test",
		consts.ClaimIssuer:         "test",
		consts.ClaimJWTID:          "12345",
		consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
		consts.ClaimAudience:       []string{audience},
	}

	formID := url.Values{consts.FormParameterClientID: []string{"test"}}
	formPost := url.Values{consts.FormParameterClientID: []string{"test"}, consts.FormParameterClientSecret: []string{secret}}

	formAssertion := func(assertion string) url.Values {
		return url.Values{
			consts.FormParameterClientAssertion:     []string{assertion},
			consts.FormParameterClientAssertionType: []string{consts.ClientAssertionTypeJWTBearer},
		}
	}

	testCases := []struct {
		name     string
		client   Client
		strategy EndpointClientAuthStrategy
		header   http.Header
		form     url.Values
		cert     *x509.Certificate
		method   string
		err      string
	}{
		{
			name: "ShouldRejectClientSecretBasicAtRevocationForPrivateKeyJWTClient",
			client: &DefaultJARClient{
				DefaultClient:           &DefaultClient{ID: "test", ClientSecret: NewPlainTextClientSecret(secret)},
				JSONWebKeys:             set,
				TokenEndpointAuthMethod: consts.ClientAuthMethodPrivateKeyJWT,
			},
			strategy: revocation,
			header:   clientBasicAuthHeader("test", secret),
			form:     url.Values{},
			err:      "is configured to only support 'revocation_endpoint_auth_method' method 'private_key_jwt'",
		},
		{
			name: "ShouldRejectClientSecretBasicAtIntrospectionForPrivateKeyJWTClient",
			client: &DefaultJARClient{
				DefaultClient:           &DefaultClient{ID: "test", ClientSecret: NewPlainTextClientSecret(secret)},
				JSONWebKeys:             set,
				TokenEndpointAuthMethod: consts.ClientAuthMethodPrivateKeyJWT,
			},
			strategy: introspection,
			header:   clientBasicAuthHeader("test", secret),
			form:     url.Values{},
			err:      "is configured to only support 'introspection_endpoint_auth_method' method 'private_key_jwt'",
		},
		{
			name: "ShouldAuthenticatePrivateKeyJWTAtIntrospection",
			client: &DefaultJARClient{
				DefaultClient:           &DefaultClient{ID: "test"},
				JSONWebKeys:             set,
				TokenEndpointAuthMethod: consts.ClientAuthMethodPrivateKeyJWT,
			},
			strategy: introspection,
			form:     formAssertion(mustGenerateClientAssertion(t, claims, jose.RS256, jwt.JSONWebTokenTypeClientAuthentication, "kid-foo", key)),
			method:   consts.ClientAuthMethodPrivateKeyJWT,
		},
		{
			// RFC 7009 Section 2.1.
			name: "ShouldAuthenticatePublicClientAtRevocation",
			client: &DefaultJARClient{
				DefaultClient:           &DefaultClient{ID: "test", Public: true},
				TokenEndpointAuthMethod: consts.ClientAuthMethodNone,
			},
			strategy: revocation,
			form:     formID,
			method:   consts.ClientAuthMethodNone,
		},
		{
			name: "ShouldRejectPublicClientAtIntrospection",
			client: &DefaultJARClient{
				DefaultClient:           &DefaultClient{ID: "test", Public: true},
				TokenEndpointAuthMethod: consts.ClientAuthMethodNone,
			},
			strategy: introspection,
			form:     formID,
			err:      "the introspection endpoint does not permit clients to authenticate using this method",
		},
		{
			name: "ShouldAuthenticateTLSClientAuthAtRevocation",
			client: &DefaultMTLSClient{
				DefaultJARClient: &DefaultJARClient{
					DefaultClient:           &DefaultClient{ID: "test"},
					TokenEndpointAuthMethod: consts.ClientAuthMethodTLSClientAuth,
				},
				TLSClientAuthSANDNS: "client.example.com",
			},
			strategy: revocation,
			form:     formID,
			cert:     cert,
			method:   consts.ClientAuthMethodTLSClientAuth,
		},
		{
			name: "ShouldRejectTLSClientAuthClientWithoutCertificateAtIntrospection",
			client: &DefaultMTLSClient{
				DefaultJARClient: &DefaultJARClient{
					DefaultClient:           &DefaultClient{ID: "test"},
					TokenEndpointAuthMethod: consts.ClientAuthMethodTLSClientAuth,
				},
				TLSClientAuthSANDNS: "client.example.com",
			},
			strategy: introspection,
			form:     formID,
			err:      "no known authentication method",
		},
		{
			name: "ShouldPreferTheRegisteredRevocationMethod",
			client: &DefaultJARClient{
				DefaultClient:                &DefaultClient{ID: "test", ClientSecret: NewPlainTextClientSecret(secret)},
				JSONWebKeys:                  set,
				TokenEndpointAuthMethod:      consts.ClientAuthMethodPrivateKeyJWT,
				RevocationEndpointAuthMethod: consts.ClientAuthMethodClientSecretPost,
			},
			strategy: revocation,
			form:     formPost,
			method:   consts.ClientAuthMethodClientSecretPost,
		},
		{
			name: "ShouldRejectTheTokenEndpointMethodWhenARevocationMethodIsRegistered",
			client: &DefaultJARClient{
				DefaultClient:                &DefaultClient{ID: "test", ClientSecret: NewPlainTextClientSecret(secret)},
				JSONWebKeys:                  set,
				TokenEndpointAuthMethod:      consts.ClientAuthMethodPrivateKeyJWT,
				RevocationEndpointAuthMethod: consts.ClientAuthMethodClientSecretPost,
			},
			strategy: revocation,
			form:     formAssertion(mustGenerateClientAssertion(t, claims, jose.RS256, jwt.JSONWebTokenTypeClientAuthentication, "kid-foo", key)),
			err:      "is configured to only support 'revocation_endpoint_auth_method' method 'client_secret_post'",
		},
		{
			name: "ShouldRejectAnAlgorithmOtherThanTheTokenEndpointSigningAlg",
			client: &DefaultJARClient{
				DefaultClient:               &DefaultClient{ID: "test", ClientSecret: NewPlainTextClientSecret(secret)},
				TokenEndpointAuthMethod:     consts.ClientAuthMethodClientSecretJWT,
				TokenEndpointAuthSigningAlg: string(jose.HS512),
			},
			strategy: revocation,
			form:     formAssertion(mustGenerateHSAssertion(t, claims, []byte(secret))),
			err:      "expects client assertions to be signed with the 'alg' header value 'HS512'",
		},
		{
			name: "ShouldNotApplyTheTokenEndpointSigningAlgToARegisteredRevocationMethod",
			client: &DefaultJARClient{
				DefaultClient:                &DefaultClient{ID: "test", ClientSecret: NewPlainTextClientSecret(secret)},
				JSONWebKeys:                  set,
				TokenEndpointAuthMethod:      consts.ClientAuthMethodPrivateKeyJWT,
				TokenEndpointAuthSigningAlg:  string(jose.RS256),
				RevocationEndpointAuthMethod: consts.ClientAuthMethodClientSecretJWT,
			},
			strategy: revocation,
			form:     formAssertion(mustGenerateHSAssertion(t, claims, []byte(secret))),
			method:   consts.ClientAuthMethodClientSecretJWT,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{
				JWKSFetcherStrategy:          NewDefaultJWKSFetcherStrategy(),
				AllowedJWTAssertionAudiences: []string{audience},
				MTLSEnabled:                  true,
			}

			config.JWTStrategy = &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

			store := storage.NewMemoryStore()
			store.Clients["test"] = tc.client

			provider := &Fosite{Store: store, Config: config}

			r := &http.Request{Header: http.Header{}}

			if tc.header != nil {
				r.Header = tc.header
			}

			if tc.cert != nil {
				r.TLS = &tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{tc.cert},
					VerifiedChains:   [][]*x509.Certificate{{tc.cert}},
				}
			}

			client, method, err := provider.AuthenticateClientWithAuthHandler(context.Background(), r, tc.form, tc.strategy)

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
