// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/token/jwt"
)

type discoveryServer struct {
	*httptest.Server

	fetches atomic.Int64
	issuer  string
	jwksURI func(server *httptest.Server) string
	status  int
}

func newDiscoveryServer(t *testing.T, jwks *jose.JSONWebKeySet, configure func(d *discoveryServer)) (d *discoveryServer) {
	t.Helper()

	d = &discoveryServer{
		jwksURI: func(server *httptest.Server) string { return server.URL + "/jwks" },
		status:  http.StatusOK,
	}

	d.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)

		switch r.URL.Path {
		case consts.WellKnownOpenIDConfiguration:
			d.fetches.Add(1)

			if d.status != http.StatusOK {
				w.WriteHeader(d.status)

				return
			}

			issuer := d.issuer
			if issuer == "" {
				issuer = d.URL
			}

			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "jwks_uri": d.jwksURI(d.Server)})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(jwks)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	t.Cleanup(d.Close)

	if configure != nil {
		configure(d)
	}

	return d
}

func TestAuthenticateClientRegistrationJWTDiscovery(t *testing.T) {
	testCases := []struct {
		name      string
		configure func(d *discoveryServer)
		patterns  bool
		err       string
	}{
		{
			name: "ShouldVerifyWithTheDiscoveredKeySet",
		},
		{
			name:     "ShouldPermitPatternsForAPatternIssuer",
			patterns: true,
		},
		{
			name:      "ShouldRejectMetadataNamingAnotherIssuer",
			configure: func(d *discoveryServer) { d.issuer = testJWTOtherIssuer },
			err:       "names the issuer 'https://auth.example.co'",
		},
		{
			name:      "ShouldRejectMetadataWithoutAKeySet",
			configure: func(d *discoveryServer) { d.jwksURI = func(*httptest.Server) string { return "" } },
			err:       "has no 'jwks_uri'",
		},
		{
			name:      "ShouldRejectAnUnsuccessfulStatus",
			configure: func(d *discoveryServer) { d.status = http.StatusNotFound },
			err:       "returned the status code 404",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			auth, config, _, _ := newJWTAuthFixtures(t)

			signer := newJWTAuthKeyedSigner(t, config, gen.MustRSAKey(), "discovered-1")

			server := newDiscoveryServer(t, &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicJWK(t, signer)}}, tc.configure)

			config.RFC7591ClientRegistrationTrustedIssuers = []oauth2.RFC7591TrustedIssuer{{Issuer: server.URL}}

			if tc.patterns {
				config.RFC7591ClientRegistrationPatternIssuers = []string{server.URL}
			}

			for range 2 {
				token := signJWTAuthToken(t, signer, jwt.JSONWebTokenTypeAccessToken, jwt.MapClaims{jwt.ClaimIssuer: server.URL})

				requester, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest(oauth2.BearerAccessToken, token, "", nil), "")

				if tc.err != "" {
					require.Error(t, err)
					assert.ErrorIs(t, err, oauth2.ErrServerError)
					assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), tc.err)

					continue
				}

				require.NoError(t, err)

				pr, ok := requester.(RegistrationPolicyRequester)
				require.True(t, ok)

				assert.Equal(t, tc.patterns, pr.GetRegistrationPolicyPatternsPermitted())
			}

			// A successful discovery is reused, and so is a failed one until it expires.
			assert.Equal(t, int64(1), server.fetches.Load())
		})
	}
}

func TestAuthenticateClientRegistrationJWTReportsAnUnreachableKeySetAsAServerError(t *testing.T) {
	auth, config, _, _ := newJWTAuthFixtures(t)

	signer := newJWTAuthKeyedSigner(t, config, gen.MustRSAKey(), "unreachable-1")

	client := retryablehttp.NewClient()
	client.RetryMax = 0

	config.JWKSFetcherStrategy = oauth2.NewDefaultJWKSFetcherStrategy(oauth2.JWKSFetcherWithHTTPClient(client))
	config.RFC7591ClientRegistrationTrustedIssuers = []oauth2.RFC7591TrustedIssuer{{Issuer: testJWTTrustedIssuer, JSONWebKeysURI: "http://127.0.0.1:1/jwks.json"}}

	token := signJWTAuthToken(t, signer, jwt.JSONWebTokenTypeAccessToken, jwt.MapClaims{jwt.ClaimIssuer: testJWTTrustedIssuer})

	_, err := auth.AuthenticateClientRegistrationRequest(context.Background(), bindingRequest(oauth2.BearerAccessToken, token, "", nil), "")

	require.ErrorIs(t, err, oauth2.ErrServerError)
}

func TestAuthenticateClientRegistrationJWTPrefersTheConfiguredKeySet(t *testing.T) {
	ctx := context.Background()

	auth, config, _, _ := newJWTAuthFixtures(t)

	signer := newJWTAuthKeyedSigner(t, config, gen.MustRSAKey(), "configured-1")

	server := newDiscoveryServer(t, &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicJWK(t, signer)}}, nil)

	config.RFC7591ClientRegistrationTrustedIssuers = []oauth2.RFC7591TrustedIssuer{{Issuer: server.URL, JSONWebKeysURI: server.URL + "/jwks"}}

	token := signJWTAuthToken(t, signer, jwt.JSONWebTokenTypeAccessToken, jwt.MapClaims{jwt.ClaimIssuer: server.URL})

	_, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest(oauth2.BearerAccessToken, token, "", nil), "")
	require.NoError(t, err)

	assert.Equal(t, int64(0), server.fetches.Load())
}

func TestAuthenticateClientRegistrationJWTTrustsOnlyItselfByDefault(t *testing.T) {
	ctx := context.Background()

	auth, config, _, _ := newJWTAuthFixtures(t)

	signer := newJWTAuthKeyedSigner(t, config, gen.MustRSAKey(), "untrusted-1")

	server := newDiscoveryServer(t, &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicJWK(t, signer)}}, nil)

	token := signJWTAuthToken(t, signer, jwt.JSONWebTokenTypeAccessToken, jwt.MapClaims{jwt.ClaimIssuer: server.URL})

	_, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest(oauth2.BearerAccessToken, token, "", nil), "")
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidToken)

	assert.Equal(t, int64(0), server.fetches.Load())
}

func TestJWKSURIDiscoveryMergesConcurrentLookups(t *testing.T) {
	release := make(chan struct{})

	var fetches atomic.Int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)

		<-release

		w.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)

		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": "http://" + r.Host, "jwks_uri": "http://" + r.Host + "/jwks"})
	}))

	t.Cleanup(server.Close)

	var (
		discovery jwksURIDiscovery
		wg        sync.WaitGroup
		uris      = make([]string, 8)
		errs      = make([]error, 8)
	)

	config := &oauth2.Config{}

	for i := range uris {
		wg.Go(func() {
			uris[i], errs[i] = discovery.resolve(t.Context(), config, oauth2.RFC7591TrustedIssuer{Issuer: server.URL})
		})
	}

	require.Eventually(t, func() bool { return fetches.Load() == 1 }, time.Second, time.Millisecond)

	close(release)

	wg.Wait()

	for i := range uris {
		require.NoError(t, errs[i])
		assert.Equal(t, server.URL+"/jwks", uris[i])
	}

	assert.Equal(t, int64(1), fetches.Load())
}

func TestJWKSRefreshLimiter(t *testing.T) {
	var limiter jwksRefreshLimiter

	now := time.Now()

	assert.True(t, limiter.allow("https://a.example.com/jwks", now))
	assert.False(t, limiter.allow("https://a.example.com/jwks", now.Add(jwksRefreshInterval-time.Second)))
	assert.True(t, limiter.allow("https://b.example.com/jwks", now))
	assert.True(t, limiter.allow("https://a.example.com/jwks", now.Add(jwksRefreshInterval)))
}
