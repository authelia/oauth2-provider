// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net"
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

func TestGuardHTTPClient(t *testing.T) {
	var hits atomic.Int64

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		rw.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	t.Run("ShouldRefuseLoopback", func(t *testing.T) {
		hits.Store(0)

		guarded, err := GuardHTTPClient(sharedGuardTestClient(nil))
		require.NoError(t, err)

		_, err = guarded.Get(server.URL) //nolint:bodyclose

		assert.ErrorIs(t, err, ErrSpecialUseAddress)
		assert.Zero(t, hits.Load())
	})

	t.Run("ShouldRefuseNameResolvingToLoopback", func(t *testing.T) {
		hits.Store(0)

		guarded, err := GuardHTTPClient(sharedGuardTestClient(nil))
		require.NoError(t, err)

		u, err := url.Parse(server.URL)
		require.NoError(t, err)

		u.Host = net.JoinHostPort("localhost", u.Port())

		_, err = guarded.Get(u.String()) //nolint:bodyclose

		assert.ErrorIs(t, err, ErrSpecialUseAddress)
		assert.Zero(t, hits.Load())
	})

	t.Run("ShouldReachLoopbackWhenAllowed", func(t *testing.T) {
		guarded, err := GuardHTTPClient(sharedGuardTestClient(nil), WithSpecialUseAddressGuardAllowLoopback(netip.MustParseAddr("127.0.0.1")))
		require.NoError(t, err)

		response, err := guarded.Get(server.URL)
		require.NoError(t, err)

		defer response.Body.Close()

		assert.Equal(t, http.StatusOK, response.StatusCode)
	})

	t.Run("ShouldReachAnAllowedNetwork", func(t *testing.T) {
		guarded, err := GuardHTTPClient(sharedGuardTestClient(nil), WithSpecialUseAddressGuardAllowedNetworks(mustParseNetworks("127.0.0.0/8", "::1/128")...))
		require.NoError(t, err)

		response, err := guarded.Get(server.URL)
		require.NoError(t, err)

		defer response.Body.Close()

		assert.Equal(t, http.StatusOK, response.StatusCode)
	})

	t.Run("ShouldRefuseWhenOnlyAnotherNetworkIsAllowed", func(t *testing.T) {
		hits.Store(0)

		guarded, err := GuardHTTPClient(sharedGuardTestClient(nil), WithSpecialUseAddressGuardAllowedNetworks(mustParseNetworks("10.0.0.0/8")...))
		require.NoError(t, err)

		_, err = guarded.Get(server.URL) //nolint:bodyclose

		assert.ErrorIs(t, err, ErrSpecialUseAddress)
		assert.Zero(t, hits.Load())
	})

	t.Run("ShouldCheckTheConnectionOfACustomTLSDialerAgainstAllowedNetworks", func(t *testing.T) {
		dialer := &net.Dialer{}

		base := sharedGuardTestClient(&http.Transport{DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, server.Listener.Addr().String())
		}})

		guarded, err := GuardHTTPClient(base, WithSpecialUseAddressGuardAllowedNetworks(mustParseNetworks("10.0.0.0/8")...))
		require.NoError(t, err)

		_, err = guarded.Get("https://public.example.com/") //nolint:bodyclose

		assert.ErrorIs(t, err, ErrSpecialUseAddress)
	})

	t.Run("ShouldNotMutateBase", func(t *testing.T) {
		base := sharedGuardTestClient(nil)
		transport := base.HTTPClient.Transport

		_, err := GuardHTTPClient(base)
		require.NoError(t, err)

		assert.Same(t, transport, base.HTTPClient.Transport)

		response, err := base.Get(server.URL)
		require.NoError(t, err)

		defer response.Body.Close()

		assert.Equal(t, http.StatusOK, response.StatusCode)
	})

	t.Run("ShouldUseTheDialerOfBase", func(t *testing.T) {
		var dials atomic.Int64

		dialer := &net.Dialer{}

		base := sharedGuardTestClient(&http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			dials.Add(1)

			return dialer.DialContext(ctx, network, address)
		}})

		guarded, err := GuardHTTPClient(base, WithSpecialUseAddressGuardAllowLoopback(netip.MustParseAddr("127.0.0.1")))
		require.NoError(t, err)

		response, err := guarded.Get(server.URL)
		require.NoError(t, err)

		defer response.Body.Close()

		assert.Equal(t, int64(1), dials.Load())
	})

	t.Run("ShouldCheckTheConnectionOfACustomTLSDialer", func(t *testing.T) {
		var dials atomic.Int64

		dialer := &net.Dialer{}

		base := sharedGuardTestClient(&http.Transport{DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			dials.Add(1)

			return dialer.DialContext(ctx, network, server.Listener.Addr().String())
		}})

		guarded, err := GuardHTTPClient(base)
		require.NoError(t, err)

		_, err = guarded.Get("https://public.example.com/") //nolint:bodyclose

		assert.ErrorIs(t, err, ErrSpecialUseAddress)
		assert.Equal(t, int64(1), dials.Load())
	})

	t.Run("ShouldIgnoreTheProxy", func(t *testing.T) {
		guarded, err := GuardHTTPClient(sharedGuardTestClient(&http.Transport{Proxy: http.ProxyFromEnvironment}))
		require.NoError(t, err)

		transport, ok := guarded.HTTPClient.Transport.(*http.Transport)
		require.True(t, ok)

		assert.Nil(t, transport.Proxy)
	})

	t.Run("ShouldGuardTheDefaultTransport", func(t *testing.T) {
		guarded, err := GuardHTTPClient(&retryablehttp.Client{})
		require.NoError(t, err)

		_, err = guarded.HTTPClient.Get(server.URL) //nolint:bodyclose,noctx

		assert.ErrorIs(t, err, ErrSpecialUseAddress)
	})

	t.Run("ShouldRefuseATransportThatCannotBeGuarded", func(t *testing.T) {
		guarded, err := GuardHTTPClient(&retryablehttp.Client{HTTPClient: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) { return nil, nil })}})

		assert.ErrorIs(t, err, ErrSpecialUseAddress)
		assert.Nil(t, guarded)
	})

	t.Run("ShouldRefuseNil", func(t *testing.T) {
		guarded, err := GuardHTTPClient(nil)

		assert.ErrorIs(t, err, ErrSpecialUseAddress)
		assert.Nil(t, guarded)
	})
}

func TestSpecialUseAddressGuardHTTPClient(t *testing.T) {
	base := sharedGuardTestClient(nil)

	t.Run("ShouldReturnBaseWhenDisabled", func(t *testing.T) {
		hc, err := SpecialUseAddressGuardHTTPClient(t.Context(), &Config{DisableSpecialUseAddressGuard: true}, base)

		require.NoError(t, err)
		assert.Same(t, base, hc)
	})

	t.Run("ShouldGuardByDefault", func(t *testing.T) {
		hc, err := SpecialUseAddressGuardHTTPClient(t.Context(), &Config{}, base)

		require.NoError(t, err)
		assert.NotSame(t, base, hc)
	})

	t.Run("ShouldGuardWhenConfigIsNotAProvider", func(t *testing.T) {
		hc, err := SpecialUseAddressGuardHTTPClient(t.Context(), struct{}{}, base)

		require.NoError(t, err)
		assert.NotSame(t, base, hc)
	})

	t.Run("ShouldNotReuseTheGuardedClientForAnotherAllowList", func(t *testing.T) {
		loopback, err := SpecialUseAddressGuardHTTPClient(t.Context(), &Config{SpecialUseAddressGuardAllowedNetworks: mustParseNetworks("127.0.0.0/8")}, base)
		require.NoError(t, err)

		other, err := SpecialUseAddressGuardHTTPClient(t.Context(), &Config{SpecialUseAddressGuardAllowedNetworks: mustParseNetworks("10.0.0.0/8")}, base)
		require.NoError(t, err)

		none, err := SpecialUseAddressGuardHTTPClient(t.Context(), &Config{}, base)
		require.NoError(t, err)

		again, err := SpecialUseAddressGuardHTTPClient(t.Context(), &Config{SpecialUseAddressGuardAllowedNetworks: mustParseNetworks("127.0.0.0/8")}, base)
		require.NoError(t, err)

		assert.NotSame(t, loopback, other)
		assert.NotSame(t, loopback, none)
		assert.NotSame(t, other, none)
		assert.Same(t, loopback, again)
	})

	t.Run("ShouldReuseTheGuardedClient", func(t *testing.T) {
		config := &Config{}

		first, err := SpecialUseAddressGuardHTTPClient(t.Context(), config, base)
		require.NoError(t, err)

		second, err := SpecialUseAddressGuardHTTPClient(t.Context(), config, base)
		require.NoError(t, err)

		assert.NotSame(t, base, first)
		assert.Same(t, first, second)
	})

	t.Run("ShouldFailWhenTheTransportCannotBeGuarded", func(t *testing.T) {
		hc, err := SpecialUseAddressGuardHTTPClient(t.Context(), &Config{}, &retryablehttp.Client{HTTPClient: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) { return nil, nil })}})

		assert.ErrorIs(t, err, ErrSpecialUseAddress)
		assert.Nil(t, hc)
	})
}

func TestSpecialUseAddressGuardAuthenticateClientSelfSignedMTLS(t *testing.T) {
	cert := gen.MustCertificate(gen.CertificateOptions{Subject: pkix.Name{CommonName: "registered"}})

	jwks := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: cert.PublicKey, Certificates: []*x509.Certificate{cert}, KeyID: cert.Subject.CommonName}}}

	testCases := []struct {
		name      string
		disable   bool
		allowed   []*net.IPNet
		permitted bool
	}{
		{name: "ShouldFetchWhenDisabled", disable: true},
		{name: "ShouldRefuseByDefault"},
		{name: "ShouldFetchWhenTheNetworkIsAllowed", allowed: mustParseNetworks("127.0.0.0/8", "::1/128"), permitted: true},
		{name: "ShouldRefuseWhenOnlyAnotherNetworkIsAllowed", allowed: mustParseNetworks("10.0.0.0/8")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int64

			server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				require.NoError(t, json.NewEncoder(rw).Encode(jwks))
			}))
			defer server.Close()

			store := newMTLSClientStore()
			store.clients["test"] = &DefaultMTLSClient{
				DefaultJARClient: &DefaultJARClient{
					DefaultClient:           &DefaultClient{ID: "test"},
					TokenEndpointAuthMethod: consts.ClientAuthMethodSelfSignedTLSClientAuth,
					JSONWebKeysURI:          server.URL,
				},
			}

			config := &Config{
				MTLSEnabled:                           true,
				JWKSFetcherStrategy:                   NewDefaultJWKSFetcherStrategy(JWKSFetcherWithHTTPClient(sharedGuardTestClient(nil))),
				DisableSpecialUseAddressGuard:         tc.disable,
				SpecialUseAddressGuardAllowedNetworks: tc.allowed,
			}

			strategy := &DefaultClientAuthenticationStrategy{Store: store, Config: config}

			form := url.Values{consts.FormParameterClientID: []string{"test"}}

			r := &http.Request{Header: http.Header{}, PostForm: form, Form: form, TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}}

			_, _, err := strategy.AuthenticateClient(t.Context(), r, form, &TokenEndpointClientAuthStrategy{})

			if !tc.disable && !tc.permitted {
				assert.ErrorIs(t, err, ErrSpecialUseAddress)
				assert.Zero(t, hits.Load())
			} else {
				require.NoError(t, ErrorToDebugRFC6749Error(err))
				assert.Equal(t, int64(1), hits.Load())
			}
		})
	}
}

func TestSpecialUseAddressGuardAuthorizeRequestURI(t *testing.T) {
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
		name      string
		disable   bool
		allowed   []*net.IPNet
		permitted bool
	}{
		{name: "ShouldFetchWhenDisabled", disable: true},
		{name: "ShouldRefuseByDefault"},
		{name: "ShouldFetchWhenTheNetworkIsAllowed", allowed: mustParseNetworks("127.0.0.0/8", "::1/128"), permitted: true},
		{name: "ShouldRefuseWhenOnlyAnotherNetworkIsAllowed", allowed: mustParseNetworks("10.0.0.0/8")},
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

			client := &DefaultJARClient{
				RequestObjectSigningAlg: consts.JSONWebTokenAlgNone,
				RequestURIs:             []string{server.URL + "/request.jwt"},
				DefaultClient: &DefaultClient{
					ID:            "foo",
					RedirectURIs:  []string{"https://client.example.com/cb"},
					ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
					Scopes:        []string{consts.ScopeOpenID},
				},
			}

			config := &Config{HTTPClient: shared, Issuer: issuer, DisableSpecialUseAddressGuard: tc.disable, SpecialUseAddressGuardAllowedNetworks: tc.allowed}

			config.JWTStrategy = &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{})}

			provider := &Fosite{Store: &stubClientStorage{client: client}, Config: config}

			request := &http.Request{Header: http.Header{}, Method: http.MethodGet, URL: &url.URL{RawQuery: url.Values{
				consts.FormParameterClientID:     {"foo"},
				consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow},
				consts.FormParameterScope:        {consts.ScopeOpenID},
				consts.FormParameterRequestURI:   {server.URL + "/request.jwt"},
			}.Encode()}}

			_, err := provider.NewAuthorizeRequest(t.Context(), request)

			if !tc.disable && !tc.permitted {
				assert.ErrorIs(t, err, ErrSpecialUseAddress)
				assert.Zero(t, hits.Load())
			} else {
				require.NoError(t, ErrorToDebugRFC6749Error(err))
				assert.Equal(t, int64(1), hits.Load())
			}
		})
	}
}

func sharedGuardTestClient(transport *http.Transport) *retryablehttp.Client {
	client := retryablehttp.NewClient()
	client.RetryMax = 0
	client.Logger = nil

	if transport != nil {
		client.HTTPClient = &http.Client{Transport: transport}
	}

	return client
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func mustParseNetworks(cidrs ...string) (networks []*net.IPNet) {
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}

		networks = append(networks, network)
	}

	return networks
}
