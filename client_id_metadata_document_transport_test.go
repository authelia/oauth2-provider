// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestHTTPClientForClient(t *testing.T) {
	base := retryablehttp.NewClient()
	guarded := NewSpecialUseAddressGuardedHTTPClient()

	registered := &DefaultRegisteredClient{DefaultClient: &DefaultClient{ID: "registered"}}
	document := &documentTestClient{DefaultRegisteredClient: &DefaultRegisteredClient{DefaultClient: &DefaultClient{ID: "https://client.example.com/c"}}}

	t.Run("ShouldUseBaseForRegisteredClient", func(t *testing.T) {
		hc, err := httpClientForClient(t.Context(), &Config{ClientIDMetadataDocumentHTTPClient: guarded}, base, registered)

		require.NoError(t, err)
		assert.Same(t, base, hc)
	})

	t.Run("ShouldUseGuardedForDocumentClient", func(t *testing.T) {
		hc, err := httpClientForClient(t.Context(), &Config{ClientIDMetadataDocumentHTTPClient: guarded}, base, document)

		require.NoError(t, err)
		assert.Same(t, guarded, hc)
	})

	t.Run("ShouldFailClosedWithoutGuardedClient", func(t *testing.T) {
		hc, err := httpClientForClient(t.Context(), &Config{}, base, document)

		require.ErrorIs(t, err, ErrServerError)
		assert.Nil(t, hc)
	})

	t.Run("ShouldFailClosedWhenConfigIsNotAProvider", func(t *testing.T) {
		hc, err := httpClientForClient(t.Context(), struct{}{}, base, document)

		require.ErrorIs(t, err, ErrServerError)
		assert.Nil(t, hc)
	})
}

func TestEndpointClientAuthJWTClientForwardsTheMarker(t *testing.T) {
	document := &documentTestClient{DefaultRegisteredClient: &DefaultRegisteredClient{DefaultClient: &DefaultClient{}}}

	assert.True(t, jwt.IsClientIDMetadataDocumentClient(&EndpointClientAuthJWTClient{client: document, strategy: &TokenEndpointClientAuthStrategy{}}))
	assert.False(t, jwt.IsClientIDMetadataDocumentClient(&EndpointClientAuthJWTClient{client: document.DefaultRegisteredClient, strategy: &TokenEndpointClientAuthStrategy{}}))
}

func TestConfigGetClientJWKSFetcherStrategy(t *testing.T) {
	guarded := NewDefaultJWKSFetcherStrategy()
	document := &documentTestClient{DefaultRegisteredClient: &DefaultRegisteredClient{DefaultClient: &DefaultClient{}}}

	config := &Config{ClientIDMetadataDocumentJWKSFetcherStrategy: guarded}

	var provider jwt.ClientJWKSFetcherStrategyProvider = config

	assert.Equal(t, guarded, provider.GetClientJWKSFetcherStrategy(t.Context(), document))
	assert.Equal(t, config.GetJWKSFetcherStrategy(t.Context()), provider.GetClientJWKSFetcherStrategy(t.Context(), document.DefaultRegisteredClient))
	assert.NotEqual(t, guarded, provider.GetClientJWKSFetcherStrategy(t.Context(), document.DefaultRegisteredClient))

	assert.Nil(t, (&Config{}).GetClientJWKSFetcherStrategy(t.Context(), document))
}

func TestAuthorizeRequestFetchesTheRequestURIOfADocumentClientOverTheGuardedClient(t *testing.T) {
	const issuer = "https://auth.example.com"

	object, _, err := jwt.EncodeCompactSigned(t.Context(), jwt.MapClaims{
		consts.ClaimIssuer:               "foo",
		consts.ClaimAudience:             []string{issuer},
		consts.ClaimClientIdentifier:     "foo",
		consts.FormParameterResponseType: consts.ResponseTypeAuthorizationCodeFlow,
		consts.FormParameterRedirectURI:  "https://client.example.com/cb",
		consts.FormParameterScope:        consts.ScopeOpenID,
		consts.FormParameterState:        "some-state-some-state",
	}, nil, &jose.JSONWebKey{Key: jwt.UnsafeAllowNoneSignatureType})
	require.NoError(t, err)

	testCases := []struct {
		name     string
		document bool
		guarded  bool
		hits     int64
		err      error
	}{
		{name: "ShouldFetchForARegisteredClientOverTheSharedClient", hits: 1},
		{name: "ShouldNotFetchForADocumentClientWithoutTheGuardedClient", document: true, err: ErrServerError},
		{name: "ShouldFetchForADocumentClientOverTheGuardedClient", document: true, guarded: true, hits: 1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int64

			server := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				hits.Add(1)

				_, _ = rw.Write([]byte(object))
			}))
			defer server.Close()

			shared := retryablehttp.NewClient()
			shared.HTTPClient = server.Client()
			shared.RetryMax = 0
			shared.Logger = nil

			registered := &DefaultJARClient{
				RequestObjectSigningAlg: consts.JSONWebTokenAlgNone,
				RequestURIs:             []string{server.URL + "/request.jwt"},
				DefaultClient: &DefaultClient{
					ID:            "foo",
					RedirectURIs:  []string{"https://client.example.com/cb"},
					ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
					Scopes:        []string{consts.ScopeOpenID},
				},
			}

			var client Client = registered

			if tc.document {
				client = &documentJARTestClient{DefaultJARClient: registered}
			}

			config := &Config{
				HTTPClient:    shared,
				IDTokenIssuer: issuer,
			}

			config.JWTStrategy = &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{})}

			if tc.guarded {
				guarded := NewSpecialUseAddressGuardedHTTPClient(WithSpecialUseAddressGuardAllowLoopback(netip.MustParseAddr("127.0.0.1")))
				guarded.HTTPClient.Transport.(*http.Transport).TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()

				config.ClientIDMetadataDocumentHTTPClient = guarded
			}

			provider := &Fosite{Store: &stubClientStorage{client: client}, Config: config}

			request := &http.Request{Header: http.Header{}, Method: http.MethodGet, URL: &url.URL{RawQuery: url.Values{
				consts.FormParameterClientID:     {"foo"},
				consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow},
				consts.FormParameterScope:        {consts.ScopeOpenID},
				consts.FormParameterRequestURI:   {server.URL + "/request.jwt"},
			}.Encode()}}

			_, err := provider.NewAuthorizeRequest(t.Context(), request)

			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, ErrorToDebugRFC6749Error(err))
			}

			assert.Equal(t, tc.hits, hits.Load())
		})
	}
}

func TestAuthenticateClientSelfSignedMTLSFetchesTheJWKSURIOfADocumentClientOverTheGuardedFetcher(t *testing.T) {
	cert := gen.MustCertificate(gen.CertificateOptions{Subject: pkix.Name{CommonName: "registered"}})

	jwks := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: cert.PublicKey, Certificates: []*x509.Certificate{cert}, KeyID: cert.Subject.CommonName}}}

	testCases := []struct {
		name     string
		document bool
		guarded  bool
		shared   bool
		err      bool
	}{
		{name: "ShouldFetchForARegisteredClientWithTheSharedFetcher", shared: true},
		{name: "ShouldNotFetchForADocumentClientWithoutTheGuardedFetcher", document: true, err: true},
		{name: "ShouldFetchForADocumentClientWithTheGuardedFetcher", document: true, guarded: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			registered := &DefaultMTLSClient{
				DefaultJARClient: &DefaultJARClient{
					DefaultClient:           &DefaultClient{ID: "test"},
					TokenEndpointAuthMethod: consts.ClientAuthMethodSelfSignedTLSClientAuth,
					JSONWebKeysURI:          "https://client.example.com/jwks.json",
				},
			}

			var client Client = registered

			if tc.document {
				client = &documentMTLSTestClient{DefaultMTLSClient: registered}
			}

			store := newMTLSClientStore()
			store.clients["test"] = client

			shared, guarded := &staticJWKSFetcher{jwks: jwks}, &staticJWKSFetcher{jwks: jwks}

			config := &Config{MTLSEnabled: true, JWKSFetcherStrategy: shared}

			if tc.guarded {
				config.ClientIDMetadataDocumentJWKSFetcherStrategy = guarded
			}

			strategy := &DefaultClientAuthenticationStrategy{Store: store, Config: config}

			form := url.Values{consts.FormParameterClientID: []string{"test"}}

			r := &http.Request{Header: http.Header{}, PostForm: form, Form: form, TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}}

			actual, method, err := strategy.AuthenticateClient(t.Context(), r, form, &TokenEndpointClientAuthStrategy{})

			if tc.err {
				require.Error(t, err)
				assert.Nil(t, actual)
			} else {
				require.NoError(t, ErrorToDebugRFC6749Error(err))
				assert.Equal(t, consts.ClientAuthMethodSelfSignedTLSClientAuth, method)
			}

			assert.Equal(t, tc.shared, shared.location != "")
			assert.Equal(t, tc.guarded, guarded.location != "")
		})
	}
}

type documentTestClient struct {
	*DefaultRegisteredClient
}

func (c *documentTestClient) IsClientIDMetadataDocumentClient() bool { return true }

type documentJARTestClient struct {
	*DefaultJARClient
}

func (c *documentJARTestClient) IsClientIDMetadataDocumentClient() bool { return true }

type stubClientStorage struct {
	Storage

	client Client
}

func (s *stubClientStorage) GetClient(_ context.Context, _ string) (Client, error) {
	return s.client, nil
}

type documentMTLSTestClient struct {
	*DefaultMTLSClient
}

func (c *documentMTLSTestClient) IsClientIDMetadataDocumentClient() bool { return true }
