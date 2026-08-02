// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/rfc7591"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

// dcrResponse captures the wire fields of a successful RFC 7591 client registration or RFC 7592 client
// configuration response this test asserts on. The full response also echoes every submitted (or server-applied)
// ClientRegistrationMetadata field; only the fields this test needs are modeled here, everything else decodes into
// the zero value and is ignored.
type dcrResponse struct {
	ClientID                string `json:"client_id"`
	ClientSecret            string `json:"client_secret"`
	ClientName              string `json:"client_name"`
	Scope                   string `json:"scope"`
	RegistrationAccessToken string `json:"registration_access_token"`
	RegistrationClientURI   string `json:"registration_client_uri"`
}

// dcrErrorResponse captures the 'error' field of an RFC 6749 error response.
type dcrErrorResponse struct {
	Error string `json:"error"`
}

// registrationEndpointHandler adapts the RFC 7591 client registration provider methods to net/http, following the
// same request/response/error shape every other handler in this package uses (see e.g. tokenEndpointHandler in
// helper_endpoints_test.go).
func registrationEndpointHandler(provider oauth2.Provider) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		requester, err := provider.NewRFC7591ClientRegistrationRequest(ctx, r)
		if err != nil {
			provider.WriteRFC7591ClientRegistrationError(ctx, rw, requester, err)

			return
		}

		responder, err := provider.NewRFC7591ClientRegistrationResponse(ctx, requester)
		if err != nil {
			provider.WriteRFC7591ClientRegistrationError(ctx, rw, requester, err)

			return
		}

		provider.WriteRFC7591ClientRegistrationResponse(ctx, rw, requester, responder)
	}
}

// configurationEndpointHandler adapts the RFC 7592 client configuration provider methods to net/http.
func configurationEndpointHandler(provider oauth2.Provider) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		requester, err := provider.NewRFC7592ClientConfigurationRequest(ctx, r)
		if err != nil {
			provider.WriteRFC7592ClientConfigurationError(ctx, rw, requester, err)

			return
		}

		responder, err := provider.NewRFC7592ClientConfigurationResponse(ctx, requester)
		if err != nil {
			provider.WriteRFC7592ClientConfigurationError(ctx, rw, requester, err)

			return
		}

		provider.WriteRFC7592ClientConfigurationResponse(ctx, rw, requester, responder)
	}
}

// doDCRRequest issues an HTTP request against the client registration or client configuration endpoint mounted by
// TestClientRegistration, optionally bearer-authenticated with token, and decodes a JSON response body into out
// (when out is non-nil and the body is non-empty, as for a 204 No Content response). It returns the response status
// code.
func doDCRRequest(t *testing.T, method, url, token string, body any, out any) (status int) {
	t.Helper()

	var reader io.Reader

	if body != nil {
		data, err := json.Marshal(body)
		require.NoError(t, err)

		reader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, url, reader)
	require.NoError(t, err)

	if body != nil {
		req.Header.Set(consts.HeaderContentType, "application/json")
	}

	if token != "" {
		req.Header.Set(consts.HeaderAuthorization, "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	if out != nil && len(data) > 0 {
		require.NoErrorf(t, json.Unmarshal(data, out), "response body: %s", data)
	}

	return resp.StatusCode
}

// TestClientRegistration exercises the RFC 7591 client registration endpoint and the RFC 7592 client configuration
// endpoint together over real HTTP: minting a creation token, registering a client within its scope ceiling,
// rejecting a registration that exceeds it, reading and rotating the client's own management token, rejecting each
// token at the other's endpoint, proving the scope ceiling survives rotation, and finally deleting the client.
//
// The provider is wired with compose.Compose directly, listing only the two RFC 7591 / RFC 7592 factories, rather
// than with compose.ComposeAllEnabled. This is the exact wiring compose.ComposeAllEnabled itself delegates to (see
// compose.ComposeAllEnabled in compose/compose.go), so it exercises the identical handler code path; the only
// difference is the strategy. compose.ComposeAllEnabled always builds its strategy with compose.NewOAuth2HMACStrategy,
// which never applies a token prefix - so under compose.ComposeAllEnabled, a client registration access token is
// indistinguishable by prefix from any other token the provider mints. This test instead builds a prefixed
// hoauth2.NewHMACCoreStrategy (the "authelia_%s_" convention used throughout handler/rfc7591's own tests), so the
// 'registration_access_token' this test receives actually carries a verifiable 'authelia_at_' prefix - proof that it
// is an ordinary access token, not the dedicated 'authelia_dt_' token RFC 7591/7592 minted before this refactor
// (handler/rfc7591/token.go no longer contains that machinery at all).
func TestClientRegistration(t *testing.T) {
	ctx := context.Background()

	config := &oauth2.Config{
		GlobalSecret:                      []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationStrategy: rfc7591.NewDefaultClientRegistrationStrategy(),
		TokenEntropy:                      32,
	}

	store := storage.NewMemoryStore()

	strategy := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

	provider := compose.Compose(config, store, strategy, compose.RFC7591ClientRegistrationFactory, compose.RFC7592ClientConfigurationFactory)

	config.RFC7591ClientRegistrationEndpointAuthStrategy = rfc7591.NewDefaultEndpointAuthStrategy(config, store, strategy)

	router := mux.NewRouter()
	router.HandleFunc("/register", registrationEndpointHandler(provider))
	router.HandleFunc("/register/{id}", configurationEndpointHandler(provider))

	ts := httptest.NewServer(router)
	defer ts.Close()

	config.RFC7591ClientRegistrationEndpointURL = ts.URL + "/register"

	// Step 1: mint a creation token bound to a real client, its grantable scopes ceilinged to {"openid", "profile"}.
	creator := &oauth2.DefaultClient{ID: "initial-access-client"}

	creationToken, err := rfc7591.NewClientCreationToken(ctx, strategy, store, config, creator, oauth2.Arguments{"openid", "profile"})
	require.NoError(t, err)

	// Step 2: registering within the ceiling succeeds, and the returned token is an ordinary access token.
	var created dcrResponse

	status := doDCRRequest(t, http.MethodPost, ts.URL+"/register", creationToken, map[string]any{
		"client_name":                "Test Client",
		"redirect_uris":              []string{"https://client.example.com/callback"},
		"token_endpoint_auth_method": "client_secret_basic",
		"scope":                      "openid",
	}, &created)

	require.Equal(t, http.StatusCreated, status)
	assert.NotEmpty(t, created.ClientID)
	assert.NotEmpty(t, created.ClientSecret)
	assert.NotEmpty(t, created.RegistrationAccessToken)
	assert.Truef(t, strings.HasPrefix(created.RegistrationAccessToken, "authelia_at_"),
		"expected an ordinary access token carrying the 'authelia_at_' prefix, got %q", created.RegistrationAccessToken)
	assert.NotEmpty(t, created.RegistrationClientURI)
	assert.Equal(t, "openid", created.Scope)

	managementToken := created.RegistrationAccessToken
	registrationClientURI := created.RegistrationClientURI

	// Step 3: a second registration requesting a scope outside the ceiling ('email') is rejected.
	var overScoped dcrErrorResponse

	status = doDCRRequest(t, http.MethodPost, ts.URL+"/register", creationToken, map[string]any{
		"client_name":                "Over-Scoped Client",
		"redirect_uris":              []string{"https://client.example.com/callback"},
		"token_endpoint_auth_method": "client_secret_basic",
		"scope":                      "openid profile email",
	}, &overScoped)

	require.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_client_metadata", overScoped.Error)

	// Step 4: reading the client with the management token succeeds and reflects the registered metadata.
	var read dcrResponse

	status = doDCRRequest(t, http.MethodGet, registrationClientURI, managementToken, nil, &read)

	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, created.ClientID, read.ClientID)
	assert.Equal(t, "Test Client", read.ClientName)
	assert.Equal(t, "openid", read.Scope)

	// Step 5: the creation token is rejected at the client configuration endpoint (registration_client_uri).
	status = doDCRRequest(t, http.MethodGet, registrationClientURI, creationToken, nil, nil)
	assert.Equal(t, http.StatusUnauthorized, status)

	// Step 6: the management token is rejected at the client registration endpoint (POST /register).
	status = doDCRRequest(t, http.MethodPost, ts.URL+"/register", managementToken, map[string]any{
		"redirect_uris": []string{"https://client.example.com/callback"},
	}, nil)
	assert.Equal(t, http.StatusUnauthorized, status)

	// Step 7: replacing the metadata applies the replacement and rotates the management token; the old token
	// presented at the endpoint it used to authenticate now fails.
	var updated dcrResponse

	status = doDCRRequest(t, http.MethodPut, registrationClientURI, managementToken, map[string]any{
		"client_name":                "Renamed Client",
		"redirect_uris":              []string{"https://client.example.com/callback"},
		"token_endpoint_auth_method": "client_secret_basic",
		"scope":                      "openid",
	}, &updated)

	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, "Renamed Client", updated.ClientName)
	assert.NotEmpty(t, updated.RegistrationAccessToken)
	assert.NotEqual(t, managementToken, updated.RegistrationAccessToken)

	rotatedToken := updated.RegistrationAccessToken

	status = doDCRRequest(t, http.MethodGet, registrationClientURI, managementToken, nil, nil)
	assert.Equal(t, http.StatusUnauthorized, status, "the token rotated away by the PUT above must no longer authenticate")

	// Step 8: the scope ceiling survives rotation - an update requesting a scope outside it, using the rotated
	// token, is still rejected.
	var overScopedUpdate dcrErrorResponse

	status = doDCRRequest(t, http.MethodPut, registrationClientURI, rotatedToken, map[string]any{
		"redirect_uris":              []string{"https://client.example.com/callback"},
		"token_endpoint_auth_method": "client_secret_basic",
		"scope":                      "email",
	}, &overScopedUpdate)

	require.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_client_metadata", overScopedUpdate.Error)

	// Step 9: deleting with the rotated token succeeds, and the client - and its registration session - is gone.
	status = doDCRRequest(t, http.MethodDelete, registrationClientURI, rotatedToken, nil, nil)
	assert.Equal(t, http.StatusNoContent, status)

	status = doDCRRequest(t, http.MethodGet, registrationClientURI, rotatedToken, nil, nil)
	assert.Equal(t, http.StatusUnauthorized, status, "the session backing the rotated token was deleted by the DELETE above")
}
