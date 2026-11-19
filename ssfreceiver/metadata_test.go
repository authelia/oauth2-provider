// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
)

const testWellKnown = "/.well-known/ssf-configuration"

// testAddressGuard keeps the special-use address guard enabled and permits the given networks.
type testAddressGuard struct {
	networks []*net.IPNet
}

func (g testAddressGuard) GetDisableSpecialUseAddressGuard(context.Context) bool {
	return false
}

func (g testAddressGuard) GetSpecialUseAddressGuardAllowedNetworks(context.Context) []*net.IPNet {
	return g.networks
}

func testLoopbackGuard() testAddressGuard {
	_, network, _ := net.ParseCIDR("127.0.0.0/8")

	return testAddressGuard{networks: []*net.IPNet{network}}
}

func testHTTPClient(server *httptest.Server) *retryablehttp.Client {
	return &retryablehttp.Client{
		HTTPClient: server.Client(),
		RetryMax:   0,
		CheckRetry: retryablehttp.DefaultRetryPolicy,
		Backoff:    retryablehttp.DefaultBackoff,
	}
}

func testReceiver(server *httptest.Server) *Receiver {
	return &Receiver{Config: Config{HTTPClient: testHTTPClient(server), SpecialUseAddressGuard: testLoopbackGuard()}}
}

func testMetadata(issuer string, extra map[string]any) []byte {
	members := map[string]any{
		"spec_version":           "1_0",
		"issuer":                 issuer,
		"jwks_uri":               issuer + "/jwks.json",
		"configuration_endpoint": issuer + "/streams",
		"status_endpoint":        issuer + "/status",
		"verification_endpoint":  issuer + "/verify",
	}

	for name, value := range extra {
		if value == nil {
			delete(members, name)
		} else {
			members[name] = value
		}
	}

	data, _ := json.Marshal(members)

	return data
}

func writeTestJSON(w http.ResponseWriter, data []byte) {
	w.Header().Set("Content-Type", "application/json")

	_, _ = w.Write(data)
}

func TestReceiverDiscover(t *testing.T) {
	testCases := []struct {
		name    string
		path    string
		config  func(config *Config)
		handler func(t *testing.T, issuer string, hits *atomic.Int32) http.HandlerFunc
		err     string
		is      error
		hits    int32
		check   func(t *testing.T, issuer string, configuration *oauth2.SSFConfiguration)
	}{
		{
			name: "ShouldDeriveWellKnownWithPath",
			path: "/issuer1",
			handler: func(t *testing.T, issuer string, hits *atomic.Int32) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)

					// SSF Section 7.2.1 Figure 17: the well-known segment precedes the issuer path.
					if r.Method != http.MethodGet || r.URL.Path != testWellKnown+"/issuer1" || r.Header.Get("Accept") != "application/json" {
						http.NotFound(w, r)

						return
					}

					writeTestJSON(w, testMetadata(issuer, nil))
				}
			},
			hits: 1,
			check: func(t *testing.T, issuer string, configuration *oauth2.SSFConfiguration) {
				assert.Equal(t, issuer, configuration.Issuer)
				assert.Equal(t, issuer+"/jwks.json", configuration.JWKSURI)
				assert.Equal(t, issuer+"/streams", configuration.ConfigurationEndpoint)
				assert.Equal(t, issuer+"/status", configuration.StatusEndpoint)
				assert.Equal(t, issuer+"/verify", configuration.VerificationEndpoint)
				assert.Equal(t, "1_0", configuration.SpecVersion)
			},
		},
		{
			name: "ShouldDeriveWellKnownWithoutPath",
			handler: func(t *testing.T, issuer string, hits *atomic.Int32) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)

					if r.URL.Path != testWellKnown {
						http.NotFound(w, r)

						return
					}

					writeTestJSON(w, testMetadata(issuer, nil))
				}
			},
			hits: 1,
		},
		{
			name: "ShouldAcceptContentTypeParameter",
			handler: func(t *testing.T, issuer string, hits *atomic.Int32) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)

					w.Header().Set("Content-Type", "application/json; charset=utf-8")

					_, _ = w.Write(testMetadata(issuer, nil))
				}
			},
			hits: 1,
		},
		{
			name: "ShouldRejectIssuerMismatch",
			path: "/issuer1",
			handler: func(t *testing.T, issuer string, hits *atomic.Int32) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)

					writeTestJSON(w, testMetadata(strings.TrimSuffix(issuer, "1")+"2", nil))
				}
			},
			err:  "ssfreceiver: the transmitter configuration metadata is not valid: the 'issuer' is not the requested issuer",
			is:   ErrIssuerMismatch,
			hits: 1,
		},
		{
			name: "ShouldRejectIssuerMismatchByTrailingSlash",
			path: "/issuer1",
			handler: func(t *testing.T, issuer string, hits *atomic.Int32) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)

					writeTestJSON(w, testMetadata(issuer+"/", nil))
				}
			},
			is:   ErrIssuerMismatch,
			hits: 1,
		},
		{
			name: "ShouldRejectNonJSONContentType",
			handler: func(t *testing.T, issuer string, hits *atomic.Int32) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)

					w.Header().Set("Content-Type", "text/html")

					_, _ = w.Write(testMetadata(issuer, nil))
				}
			},
			err:  "the content type is not 'application/json'",
			hits: 1,
		},
		{
			name: "ShouldRejectMissingContentType",
			handler: func(t *testing.T, issuer string, hits *atomic.Int32) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)

					w.Header()["Content-Type"] = nil

					_, _ = w.Write(testMetadata(issuer, nil))
				}
			},
			err:  "the content type is not 'application/json'",
			hits: 1,
		},
		{
			name: "ShouldRejectRedirect",
			handler: func(t *testing.T, issuer string, hits *atomic.Int32) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)

					if r.URL.Path == "/moved" {
						writeTestJSON(w, testMetadata(issuer, nil))

						return
					}

					http.Redirect(w, r, "/moved", http.StatusFound)
				}
			},
			err:  "the status code is 302",
			hits: 1,
		},
		{
			name: "ShouldRejectNotFound",
			handler: func(t *testing.T, issuer string, hits *atomic.Int32) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)

					http.NotFound(w, r)
				}
			},
			err:  "the status code is 404",
			hits: 1,
		},
		{
			name: "ShouldRejectNoContentStatus",
			handler: func(t *testing.T, issuer string, hits *atomic.Int32) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)

					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusNoContent)
				}
			},
			err:  "the status code is 204",
			hits: 1,
		},
		{
			name:   "ShouldRejectOversizedBody",
			config: func(config *Config) { config.MaxResponseBytes = 512 },
			handler: func(t *testing.T, issuer string, hits *atomic.Int32) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)

					writeTestJSON(w, testMetadata(issuer, map[string]any{"padding": strings.Repeat("a", 512)}))
				}
			},
			err:  "the body is larger than 512 bytes",
			hits: 1,
		},
		{
			name:   "ShouldAcceptBodyOfTheLimit",
			config: func(config *Config) { config.MaxResponseBytes = 512 },
			handler: func(t *testing.T, issuer string, hits *atomic.Int32) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)

					data := testMetadata(issuer, nil)

					writeTestJSON(w, append(data, []byte(strings.Repeat(" ", 512-len(data)))...))
				}
			},
			hits: 1,
		},
		{
			name: "ShouldRejectMissingJWKSURI",
			handler: func(t *testing.T, issuer string, hits *atomic.Int32) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)

					writeTestJSON(w, testMetadata(issuer, map[string]any{"jwks_uri": nil}))
				}
			},
			err:  "'jwks_uri' is required",
			hits: 1,
		},
		{
			name: "ShouldRejectInsecureEndpoint",
			handler: func(t *testing.T, issuer string, hits *atomic.Int32) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)

					writeTestJSON(w, testMetadata(issuer, map[string]any{"status_endpoint": "http://tx.example.com/status"}))
				}
			},
			err:  "'status_endpoint' must be an absolute https URL",
			hits: 1,
		},
		{
			name: "ShouldIgnoreUnknownMembers",
			handler: func(t *testing.T, issuer string, hits *atomic.Int32) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)

					writeTestJSON(w, testMetadata(issuer, map[string]any{"x_vendor": map[string]any{"a": []int{1}}, "future_endpoint": "not a url"}))
				}
			},
			hits: 1,
			check: func(t *testing.T, issuer string, configuration *oauth2.SSFConfiguration) {
				assert.Equal(t, issuer+"/jwks.json", configuration.JWKSURI)
			},
		},
		{
			name: "ShouldRejectNonObject",
			handler: func(t *testing.T, issuer string, hits *atomic.Int32) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)

					writeTestJSON(w, []byte(`["`+issuer+`"]`))
				}
			},
			err:  "the body is not a JSON object",
			hits: 1,
		},
		{
			name: "ShouldRejectRepeatedMember",
			handler: func(t *testing.T, issuer string, hits *atomic.Int32) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)

					writeTestJSON(w, fmt.Appendf(nil, `{"issuer":"https://other.example.com","issuer":%q,"jwks_uri":%q}`, issuer, issuer+"/jwks.json"))
				}
			},
			err:  "the body is not a JSON object",
			hits: 1,
		},
		{
			name: "ShouldRejectMemberOfWrongType",
			handler: func(t *testing.T, issuer string, hits *atomic.Int32) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)

					writeTestJSON(w, testMetadata(issuer, map[string]any{"jwks_uri": 1}))
				}
			},
			err:  "a member has the wrong type",
			hits: 1,
		},
		{
			name:   "ShouldApplyInteroperabilityProfile",
			config: func(config *Config) { config.EnforceCAEPInteroperabilityProfile = true },
			handler: func(t *testing.T, issuer string, hits *atomic.Int32) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)

					writeTestJSON(w, testMetadata(issuer, nil))
				}
			},
			err:  "'delivery_methods_supported' does not meet the CAEP Interoperability Profile",
			hits: 1,
		},
		{
			name:   "ShouldRefuseSpecialUseAddress",
			config: func(config *Config) { config.SpecialUseAddressGuard = nil },
			handler: func(t *testing.T, issuer string, hits *atomic.Int32) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)

					writeTestJSON(w, testMetadata(issuer, nil))
				}
			},
			is:   oauth2.ErrSpecialUseAddress,
			hits: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var (
				hits    atomic.Int32
				handler http.HandlerFunc
			)

			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler(w, r) }))
			defer server.Close()

			issuer := server.URL + tc.path
			handler = tc.handler(t, issuer, &hits)

			receiver := testReceiver(server)

			if tc.config != nil {
				tc.config(&receiver.Config)
			}

			configuration, err := receiver.Discover(t.Context(), issuer)

			assert.Equal(t, tc.hits, hits.Load())

			if tc.err == "" && tc.is == nil {
				require.NoError(t, err)
				require.NotNil(t, configuration)
				assert.Equal(t, issuer, configuration.Issuer)

				if tc.check != nil {
					tc.check(t, issuer, configuration)
				}

				return
			}

			require.Error(t, err)
			assert.Nil(t, configuration)

			if tc.err != "" {
				assert.ErrorContains(t, err, tc.err)
			}

			if tc.is != nil {
				assert.ErrorIs(t, err, tc.is)
			}

			// A document that is refused is never cached.
			assert.Empty(t, receiver.metadata.entries)
		})
	}

	t.Run("ShouldRejectIssuer", func(t *testing.T) {
		for _, issuer := range []string{"", "http://tx.example.com", "https://tx.example.com?a=b", "https://tx.example.com#a", "https://user@tx.example.com", "tx.example.com"} {
			configuration, err := (&Receiver{}).Discover(t.Context(), issuer)

			assert.Nil(t, configuration)
			assert.ErrorContains(t, err, "ssfreceiver: the issuer of the transmitter is not valid")
		}
	})
}

type testMetadataServer struct {
	*httptest.Server

	hits  atomic.Int32
	extra atomic.Pointer[map[string]any]
}

func newTestMetadataServer(t *testing.T) *testMetadataServer {
	s := &testMetadataServer{}

	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)

		var extra map[string]any

		if p := s.extra.Load(); p != nil {
			extra = *p
		}

		writeTestJSON(w, testMetadata(s.URL+strings.TrimPrefix(r.URL.Path, testWellKnown), extra))
	}))

	t.Cleanup(s.Close)

	return s
}

func TestReceiverDiscoverCache(t *testing.T) {
	t.Run("ShouldCacheUntilTTL", func(t *testing.T) {
		testCases := []struct {
			name string
			ttl  time.Duration
			have time.Duration
		}{
			{"ShouldDefaultToOneHour", 0, time.Hour},
			{"ShouldUseConfiguredValue", time.Minute, time.Minute},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				server := newTestMetadataServer(t)

				now := time.Unix(1700000000, 0)

				receiver := testReceiver(server.Server)
				receiver.Config.MetadataTTL = tc.ttl
				receiver.metadata.now = func() time.Time { return now }

				first, err := receiver.Discover(t.Context(), server.URL)
				require.NoError(t, err)

				now = now.Add(tc.have - time.Second)

				second, err := receiver.Discover(t.Context(), server.URL)
				require.NoError(t, err)

				assert.Equal(t, first, second)
				assert.Equal(t, int32(1), server.hits.Load())

				now = now.Add(time.Second)

				_, err = receiver.Discover(t.Context(), server.URL)
				require.NoError(t, err)

				assert.Equal(t, int32(2), server.hits.Load())
			})
		}
	})

	t.Run("ShouldCachePerIssuer", func(t *testing.T) {
		server := newTestMetadataServer(t)
		receiver := testReceiver(server.Server)

		for range 2 {
			for _, issuer := range []string{server.URL + "/a", server.URL + "/b"} {
				configuration, err := receiver.Discover(t.Context(), issuer)
				require.NoError(t, err)

				assert.Equal(t, issuer, configuration.Issuer)
			}
		}

		assert.Equal(t, int32(2), server.hits.Load())
	})

	t.Run("ShouldNotCacheInvalidDocument", func(t *testing.T) {
		server := newTestMetadataServer(t)

		now := time.Unix(1700000000, 0)

		receiver := testReceiver(server.Server)
		receiver.metadata.now = func() time.Time { return now }

		invalid := map[string]any{"jwks_uri": nil}

		server.extra.Store(&invalid)

		for i := range 2 {
			configuration, err := receiver.Discover(t.Context(), server.URL)

			assert.Nil(t, configuration)
			assert.ErrorContains(t, err, "'jwks_uri' is required")
			assert.Equal(t, int32(i+1), server.hits.Load())
		}

		server.extra.Store(nil)

		configuration, err := receiver.Discover(t.Context(), server.URL)
		require.NoError(t, err)

		assert.Equal(t, server.URL, configuration.Issuer)
		assert.Equal(t, int32(3), server.hits.Load())

		// SSF Section 7.2.4: a document that fails validation is not used, so the expired one is not served instead.
		now = now.Add(2 * time.Hour)

		server.extra.Store(&invalid)

		configuration, err = receiver.Discover(t.Context(), server.URL)

		assert.Nil(t, configuration)
		assert.ErrorContains(t, err, "'jwks_uri' is required")
		assert.Empty(t, receiver.metadata.entries)
	})

	t.Run("ShouldNotAliasCachedDocument", func(t *testing.T) {
		server := newTestMetadataServer(t)

		extra := map[string]any{
			"delivery_methods_supported": []string{oauth2.SSFDeliveryMethodPush},
			"critical_subject_members":   []string{"user"},
			"authorization_schemes":      []map[string]any{{"spec_urn": oauth2.SSFAuthorizationSchemeOAuth2}},
		}

		server.extra.Store(&extra)

		receiver := testReceiver(server.Server)

		// Mutate the result of the fetch, and then the result of a cache hit.
		for range 2 {
			configuration, err := receiver.Discover(t.Context(), server.URL)
			require.NoError(t, err)

			configuration.JWKSURI = "https://attacker.example.com/jwks.json"
			configuration.DeliveryMethodsSupported[0] = "changed"
			configuration.CriticalSubjectMembers[0] = "changed"
			configuration.AuthorizationSchemes[0].SpecURN = "changed"
		}

		configuration, err := receiver.Discover(t.Context(), server.URL)
		require.NoError(t, err)

		assert.Equal(t, server.URL+"/jwks.json", configuration.JWKSURI)
		assert.Equal(t, []string{oauth2.SSFDeliveryMethodPush}, configuration.DeliveryMethodsSupported)
		assert.Equal(t, []string{"user"}, configuration.CriticalSubjectMembers)
		assert.Equal(t, []oauth2.SSFAuthorizationScheme{{SpecURN: oauth2.SSFAuthorizationSchemeOAuth2}}, configuration.AuthorizationSchemes)
		assert.Equal(t, int32(1), server.hits.Load())
	})

	t.Run("ShouldBoundCachedIssuers", func(t *testing.T) {
		server := newTestMetadataServer(t)

		now := time.Unix(1700000000, 0)

		receiver := testReceiver(server.Server)
		receiver.metadata.now = func() time.Time { return now }

		for i := range maxCachedIssuers + 8 {
			now = now.Add(time.Second)

			_, err := receiver.Discover(t.Context(), fmt.Sprintf("%s/%d", server.URL, i))
			require.NoError(t, err)
		}

		assert.Len(t, receiver.metadata.entries, maxCachedIssuers)

		// The entries nearest their expiry made room.
		assert.NotContains(t, receiver.metadata.entries, server.URL+"/0")
		assert.NotContains(t, receiver.metadata.entries, server.URL+"/7")
		assert.Contains(t, receiver.metadata.entries, server.URL+"/8")
		assert.Contains(t, receiver.metadata.entries, fmt.Sprintf("%s/%d", server.URL, maxCachedIssuers+7))
	})

	t.Run("ShouldDropExpiredBeforeLive", func(t *testing.T) {
		now := time.Unix(1700000000, 0)

		cache := &metadataCache{now: func() time.Time { return now }}

		cache.set("https://long.example.com", &oauth2.SSFConfiguration{}, 2*time.Hour)

		for i := range maxCachedIssuers - 1 {
			cache.set(fmt.Sprintf("https://tx.example.com/%d", i), &oauth2.SSFConfiguration{}, time.Hour)
		}

		now = now.Add(90 * time.Minute)

		cache.set("https://new.example.com", &oauth2.SSFConfiguration{}, time.Minute)

		assert.Len(t, cache.entries, 2)
		assert.Contains(t, cache.entries, "https://long.example.com")
		assert.Contains(t, cache.entries, "https://new.example.com")
	})

	t.Run("ShouldDiscoverConcurrently", func(t *testing.T) {
		server := newTestMetadataServer(t)
		receiver := testReceiver(server.Server)

		var wg sync.WaitGroup

		for i := range 16 {
			wg.Go(func() {
				issuer := fmt.Sprintf("%s/%d", server.URL, i%4)

				configuration, err := receiver.Discover(context.Background(), issuer)

				if assert.NoError(t, err) {
					assert.Equal(t, issuer, configuration.Issuer)
				}
			})
		}

		wg.Wait()

		assert.Len(t, receiver.metadata.entries, 4)
	})
}

func TestReceiverBaseHTTPClient(t *testing.T) {
	t.Run("ShouldNotLogWithTheDefaultClient", func(t *testing.T) {
		receiver := &Receiver{}

		client := receiver.baseHTTPClient()

		require.NotNil(t, client)
		assert.Nil(t, client.Logger)
		assert.Same(t, client, receiver.baseHTTPClient())
	})

	t.Run("ShouldUseTheConfiguredClient", func(t *testing.T) {
		configured := retryablehttp.NewClient()

		receiver := &Receiver{Config: Config{HTTPClient: configured}}

		assert.Same(t, configured, receiver.baseHTTPClient())
		assert.NotNil(t, configured.Logger)
	})
}
