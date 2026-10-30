// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/handler/cimd"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestClientIDMetadataDocumentPublicClientAuthorizationCodeFlow(t *testing.T) {
	for name, store := range cimdStores() {
		t.Run(name, func(t *testing.T) {
			env := newCIMDEnv(t, store, true, true)

			id := env.documents.URL + "/public.json"

			env.setDocument("/public.json", map[string]any{
				"client_id":                  id,
				"client_name":                "Public Example",
				"application_type":           "native",
				"redirect_uris":              []string{env.provider.URL + "/callback"},
				"token_endpoint_auth_method": "none",
				"grant_types":                []string{"authorization_code", "refresh_token"},
				"response_types":             []string{"code"},
				"scope":                      "oauth2 offline",
			})

			const verifier = "somechallengesomechallengesomechallengesomechallengesomechallengesomechallenge"

			authorize := env.provider.URL + "/auth?" + url.Values{
				consts.FormParameterClientID:      {id},
				consts.FormParameterResponseType:  {"code"},
				consts.FormParameterRedirectURI:   {env.provider.URL + "/callback"},
				consts.FormParameterScope:         {"oauth2 offline"},
				consts.FormParameterState:         {testState},
				consts.FormParameterCodeChallenge: {verifier},
			}.Encode()

			response, err := http.Get(authorize) //nolint:gosec
			require.NoError(t, err)

			defer response.Body.Close()

			require.Equal(t, http.StatusOK, response.StatusCode)

			code := response.Request.URL.Query().Get(consts.FormParameterAuthorizationCode)
			require.NotEmpty(t, code)

			token := env.token(t, http.StatusOK, url.Values{
				consts.FormParameterGrantType:         {consts.GrantTypeAuthorizationCode},
				consts.FormParameterAuthorizationCode: {code},
				consts.FormParameterClientID:          {id},
				consts.FormParameterRedirectURI:       {env.provider.URL + "/callback"},
				consts.FormParameterCodeVerifier:      {verifier},
			})

			require.NotEmpty(t, token["access_token"])
			require.NotEmpty(t, token["refresh_token"])

			refreshed := env.token(t, http.StatusOK, url.Values{
				consts.FormParameterGrantType:    {consts.GrantTypeRefreshToken},
				consts.FormParameterRefreshToken: {token["refresh_token"].(string)},
				consts.FormParameterClientID:     {id},
			})

			require.NotEmpty(t, refreshed["access_token"])

			assert.Equal(t, int64(1), env.documentHits("/public.json"))
			assert.GreaterOrEqual(t, env.connections(), int64(1))

			_, err = store.GetClient(t.Context(), id)
			assert.ErrorIs(t, err, oauth2.ErrNotFound)
		})
	}
}

func TestClientIDMetadataDocumentPrivateKeyJWTClientCredentialsFlow(t *testing.T) {
	for name, store := range cimdStores() {
		t.Run(name, func(t *testing.T) {
			env := newCIMDEnv(t, store, true, true, withClientCredentialsGrant)

			id := env.documents.URL + "/confidential.json"

			env.setDocument("/confidential.json", map[string]any{ //nolint:gosec
				"client_id":                       id,
				"client_name":                     "Confidential Example",
				"token_endpoint_auth_method":      "private_key_jwt",
				"token_endpoint_auth_signing_alg": "ES256",
				"grant_types":                     []string{"client_credentials"},
				"jwks_uri":                        env.documents.URL + "/jwks.json",
				"scope":                           "oauth2",
			})

			token := env.token(t, http.StatusOK, url.Values{
				consts.FormParameterGrantType:           {consts.GrantTypeClientCredentials},
				consts.FormParameterScope:               {"oauth2"},
				consts.FormParameterClientAssertionType: {consts.ClientAssertionTypeJWTBearer},
				consts.FormParameterClientAssertion:     {env.assertion(t, id, env.provider.URL+tokenRelativePath)},
			})

			require.NotEmpty(t, token["access_token"])

			assert.Equal(t, int64(1), env.documentHits("/confidential.json"))
			assert.Equal(t, int64(1), env.documentHits("/jwks.json"))

			_, err := store.GetClient(t.Context(), id)
			assert.ErrorIs(t, err, oauth2.ErrNotFound)
		})
	}
}

func TestClientIDMetadataDocumentPrivateKeyJWTAuthorizationCodeFlow(t *testing.T) {
	for name, store := range cimdStores() {
		t.Run(name, func(t *testing.T) {
			env := newCIMDEnv(t, store, true, true)

			id := env.documents.URL + "/confidential.json"
			callback := env.provider.URL + "/callback"
			tokenURL := env.provider.URL + tokenRelativePath

			env.setDocument("/confidential.json", map[string]any{ //nolint:gosec
				"client_id":                       id,
				"client_name":                     "Confidential Example",
				"application_type":                "native",
				"redirect_uris":                   []string{callback},
				"token_endpoint_auth_method":      "private_key_jwt",
				"token_endpoint_auth_signing_alg": "ES256",
				"grant_types":                     []string{"authorization_code", "refresh_token"},
				"response_types":                  []string{"code"},
				"jwks_uri":                        env.documents.URL + "/jwks.json",
				"scope":                           "oauth2 offline",
			})

			const verifier = "somechallengesomechallengesomechallengesomechallengesomechallengesomechallenge"

			authorize := env.provider.URL + "/auth?" + url.Values{
				consts.FormParameterClientID:      {id},
				consts.FormParameterResponseType:  {"code"},
				consts.FormParameterRedirectURI:   {callback},
				consts.FormParameterScope:         {"oauth2 offline"},
				consts.FormParameterState:         {testState},
				consts.FormParameterCodeChallenge: {verifier},
			}.Encode()

			response, err := http.Get(authorize) //nolint:gosec
			require.NoError(t, err)

			defer response.Body.Close()

			require.Equal(t, http.StatusOK, response.StatusCode)

			code := response.Request.URL.Query().Get(consts.FormParameterAuthorizationCode)
			require.NotEmpty(t, code)

			token := env.token(t, http.StatusOK, url.Values{
				consts.FormParameterGrantType:           {consts.GrantTypeAuthorizationCode},
				consts.FormParameterAuthorizationCode:   {code},
				consts.FormParameterRedirectURI:         {callback},
				consts.FormParameterCodeVerifier:        {verifier},
				consts.FormParameterClientAssertionType: {consts.ClientAssertionTypeJWTBearer},
				consts.FormParameterClientAssertion:     {env.assertion(t, id, tokenURL)},
			})

			require.NotEmpty(t, token["refresh_token"])

			refreshed := env.token(t, http.StatusOK, url.Values{
				consts.FormParameterGrantType:           {consts.GrantTypeRefreshToken},
				consts.FormParameterRefreshToken:        {token["refresh_token"].(string)},
				consts.FormParameterClientAssertionType: {consts.ClientAssertionTypeJWTBearer},
				consts.FormParameterClientAssertion:     {env.assertion(t, id, tokenURL)},
			})

			require.NotEmpty(t, refreshed["access_token"])

			introspected := env.post(t, "/introspect", http.StatusOK, url.Values{
				consts.FormParameterToken:               {refreshed["access_token"].(string)},
				consts.FormParameterClientAssertionType: {consts.ClientAssertionTypeJWTBearer},
				consts.FormParameterClientAssertion:     {env.assertion(t, id, env.provider.URL+"/introspect")},
			})

			assert.Equal(t, true, introspected["active"])

			assert.Equal(t, int64(1), env.documentHits("/confidential.json"))
			assert.Equal(t, int64(1), env.documentHits("/jwks.json"))

			_, err = store.GetClient(t.Context(), id)
			assert.ErrorIs(t, err, oauth2.ErrNotFound)
		})
	}
}

func TestClientIDMetadataDocumentJWKSURIFailsClosedWithoutGuardedFetcher(t *testing.T) {
	env := newCIMDEnv(t, storage.NewMemoryStore(), true, false, withSharedUnguardedClient, withClientCredentialsGrant)

	id := env.documents.URL + "/confidential.json"

	env.setDocument("/confidential.json", map[string]any{ //nolint:gosec
		"client_id":                       id,
		"token_endpoint_auth_method":      "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"grant_types":                     []string{"client_credentials"},
		"jwks_uri":                        env.documents.URL + "/jwks.json",
		"scope":                           "oauth2",
	})

	form := url.Values{
		consts.FormParameterGrantType:           {consts.GrantTypeClientCredentials},
		consts.FormParameterScope:               {"oauth2"},
		consts.FormParameterClientAssertionType: {consts.ClientAssertionTypeJWTBearer},
		consts.FormParameterClientAssertion:     {env.assertion(t, id, env.provider.URL+tokenRelativePath)},
	}

	token := env.token(t, http.StatusUnauthorized, form)

	assert.Empty(t, token["access_token"])
	assert.Equal(t, int64(1), env.documentHits("/confidential.json"))
	assert.Equal(t, int64(0), env.documentHits("/jwks.json"))
}

func TestClientIDMetadataDocumentDisabled(t *testing.T) {
	env := newCIMDEnv(t, storage.NewMemoryStore(), false, false)

	id := env.documents.URL + "/public.json"

	env.setDocument("/public.json", map[string]any{
		"client_id":                  id,
		"application_type":           "native",
		"redirect_uris":              []string{env.provider.URL + "/callback"},
		"token_endpoint_auth_method": "none",
	})

	authorize := env.provider.URL + "/auth?" + url.Values{
		consts.FormParameterClientID:     {id},
		consts.FormParameterResponseType: {"code"},
		consts.FormParameterRedirectURI:  {env.provider.URL + "/callback"},
		consts.FormParameterScope:        {"oauth2"},
		consts.FormParameterState:        {testState},
	}.Encode()

	response, err := http.Get(authorize) //nolint:gosec
	require.NoError(t, err)

	defer response.Body.Close()

	assert.NotEqual(t, http.StatusOK, response.StatusCode)
	assert.Empty(t, response.Request.URL.Query().Get(consts.FormParameterAuthorizationCode))
	assert.Equal(t, int64(0), env.documentHits("/public.json"))
	assert.Equal(t, int64(0), env.connections())
}

func TestClientIDMetadataDocumentRefusedByAllowedDomainSuffixes(t *testing.T) {
	env := newCIMDEnv(t, storage.NewMemoryStore(), true, true, func(_ *cimdEnv, config *oauth2.Config) {
		config.ClientIDMetadataDocumentAllowedDomainSuffixes = []string{"example.com"}
	})

	id := env.documents.URL + "/public.json"

	env.setDocument("/public.json", map[string]any{
		"client_id":                  id,
		"application_type":           "native",
		"redirect_uris":              []string{env.provider.URL + "/callback"},
		"token_endpoint_auth_method": "none",
	})

	authorize := env.provider.URL + "/auth?" + url.Values{
		consts.FormParameterClientID:     {id},
		consts.FormParameterResponseType: {"code"},
		consts.FormParameterRedirectURI:  {env.provider.URL + "/callback"},
		consts.FormParameterScope:        {"oauth2"},
		consts.FormParameterState:        {testState},
	}.Encode()

	response, err := http.Get(authorize) //nolint:gosec
	require.NoError(t, err)

	defer response.Body.Close()

	assert.NotEqual(t, http.StatusOK, response.StatusCode)
	assert.Empty(t, response.Request.URL.Query().Get(consts.FormParameterAuthorizationCode))
	assert.Equal(t, int64(0), env.documentHits("/public.json"))
	assert.Equal(t, int64(0), env.connections())
}

func TestClientIDMetadataDocumentUnknownDocumentIsAnInvalidClient(t *testing.T) {
	env := newCIMDEnv(t, storage.NewMemoryStore(), true, true)

	authorize := env.provider.URL + "/auth?" + url.Values{
		consts.FormParameterClientID:     {env.documents.URL + "/absent.json"},
		consts.FormParameterResponseType: {"code"},
		consts.FormParameterRedirectURI:  {env.provider.URL + "/callback"},
		consts.FormParameterState:        {testState},
	}.Encode()

	response, err := http.Get(authorize) //nolint:gosec
	require.NoError(t, err)

	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)

	assert.Equal(t, env.provider.URL, response.Request.URL.Scheme+"://"+response.Request.URL.Host)
	assert.Equal(t, "/auth", response.Request.URL.Path)
	assert.NotContains(t, string(body), strings.TrimPrefix(env.documents.URL, "https://"))
	assert.Contains(t, string(body), "invalid_client")
}

type cimdStore interface {
	oauth2.ClientIDMetadataDocumentStorage

	GetClient(ctx context.Context, id string) (oauth2.Client, error)
}

func cimdStores() map[string]cimdStore {
	return map[string]cimdStore{
		"MemoryStore":          storage.NewMemoryStore(),
		"HydratingMemoryStore": storage.NewHydratingMemoryStore(),
	}
}

type cimdEnv struct {
	provider  *httptest.Server
	documents *httptest.Server
	key       *ecdsa.PrivateKey

	conns atomic.Int64

	scopes     []string
	grantTypes []string

	mu   sync.Mutex
	docs map[string][]byte
	hits map[string]*atomic.Int64
}

type cimdOption func(env *cimdEnv, config *oauth2.Config)

func withSharedUnguardedClient(env *cimdEnv, config *oauth2.Config) {
	client := retryablehttp.NewClient()
	client.HTTPClient = env.documents.Client()
	client.RetryMax = 0

	config.HTTPClient = client
	config.JWKSFetcherStrategy = oauth2.NewDefaultJWKSFetcherStrategy(oauth2.JWKSFetcherWithHTTPClient(client))
}

func withClientCredentialsGrant(env *cimdEnv, _ *oauth2.Config) {
	env.grantTypes = []string{consts.GrantTypeClientCredentials}
}

func newCIMDEnv(t *testing.T, store cimdStore, enabled, fetcher bool, options ...cimdOption) *cimdEnv {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	env := &cimdEnv{key: key, docs: map[string][]byte{}, hits: map[string]*atomic.Int64{}, scopes: []string{"oauth2", "offline"}}

	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "cimd-1", Algorithm: "ES256", Use: "sig"}}})
	require.NoError(t, err)

	env.docs["/jwks.json"] = jwks

	env.documents = httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		env.mu.Lock()
		body, ok := env.docs[r.URL.Path]
		env.counter(r.URL.Path).Add(1)
		env.mu.Unlock()

		if !ok {
			http.NotFound(rw, r)

			return
		}

		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write(body)
	}))
	env.documents.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			env.conns.Add(1)
		}
	}
	env.documents.StartTLS()
	t.Cleanup(env.documents.Close)

	config := &oauth2.Config{
		EnforcePKCE:                    true,
		EnablePKCEPlainChallengeMethod: true,
	}

	for _, option := range options {
		option(env, config)
	}

	if enabled {
		client := cimdHTTPClient(env.documents)

		resolver, err := cimd.NewResolver(cimd.Config{Storage: store, HTTPClient: client, ValidatorConfig: config, Scopes: env.scopes, GrantTypes: env.grantTypes})
		require.NoError(t, err)

		config.ClientIDMetadataDocumentResolver = resolver
		config.ClientIDMetadataDocumentHTTPClient = client

		if fetcher {
			config.ClientIDMetadataDocumentJWKSFetcherStrategy = oauth2.NewDefaultJWKSFetcherStrategy(oauth2.JWKSFetcherWithHTTPClient(client))
		}
	}

	provider := compose.Compose(config, store, hmacStrategy,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2PKCEFactory,
		compose.OAuth2TokenIntrospectionFactory,
	)

	env.provider = mockServer(t, provider, &oauth2.DefaultSession{})
	t.Cleanup(env.provider.Close)

	config.AllowedJWTAssertionAudiences = []string{env.provider.URL + tokenRelativePath, env.provider.URL + "/introspect"}

	return env
}

func cimdHTTPClient(server *httptest.Server) *retryablehttp.Client {
	client := oauth2.NewSpecialUseAddressGuardedHTTPClient(oauth2.WithSpecialUseAddressGuardAllowLoopback(netip.MustParseAddr("127.0.0.1")))

	client.HTTPClient.Transport.(*http.Transport).TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()

	return client
}

func (e *cimdEnv) counter(path string) *atomic.Int64 {
	if _, ok := e.hits[path]; !ok {
		e.hits[path] = &atomic.Int64{}
	}

	return e.hits[path]
}

func (e *cimdEnv) connections() int64 {
	return e.conns.Load()
}

func (e *cimdEnv) documentHits(path string) int64 {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.counter(path).Load()
}

func (e *cimdEnv) setDocument(path string, document map[string]any) {
	body, err := json.Marshal(document)
	if err != nil {
		panic(err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.docs[path] = body
}

func (e *cimdEnv) token(t *testing.T, status int, form url.Values) map[string]any {
	t.Helper()

	return e.post(t, tokenRelativePath, status, form)
}

func (e *cimdEnv) post(t *testing.T, path string, status int, form url.Values) map[string]any {
	t.Helper()

	response, err := http.PostForm(e.provider.URL+path, form)
	require.NoError(t, err)

	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)

	require.Equal(t, status, response.StatusCode, "Got body: %s", string(body))

	token := map[string]any{}

	require.NoError(t, json.Unmarshal(body, &token))

	return token
}

func (e *cimdEnv) assertion(t *testing.T, id, audience string) string {
	t.Helper()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: &jose.JSONWebKey{Key: e.key, KeyID: "cimd-1", Algorithm: "ES256", Use: "sig"}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	require.NoError(t, err)

	now := time.Now()

	payload, err := json.Marshal(map[string]any{
		"iss": id,
		"sub": id,
		"aud": audience,
		"jti": fmt.Sprintf("jti-%d", now.UnixNano()),
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
	})
	require.NoError(t, err)

	object, err := signer.Sign(payload)
	require.NoError(t, err)

	assertion, err := object.CompactSerialize()
	require.NoError(t, err)

	return assertion
}
