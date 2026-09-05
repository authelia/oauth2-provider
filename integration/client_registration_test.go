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
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xoauth2 "golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/rfc7591"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestClientRegistrationCreationTokenFromTheTokenEndpoint(t *testing.T) {
	config := &oauth2.Config{
		GlobalSecret:                                []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationGlobalSecret:       []byte("a-completely-different-secret-at-least-32b"),
		RFC7591ClientRegistrationStrategy:           rfc7591.NewDefaultClientRegistrationStrategy(),
		TokenEntropy:                                32,
		ScopeStrategy:                               oauth2.ExactScopeStrategy,
		AudienceStrategy:                            oauth2.ExactAudienceStrategy,
		ClientCredentialsFlowImplicitGrantRequested: true,
	}

	memory := storage.NewMemoryStore()

	strategy := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

	provider := compose.Compose(config, memory, strategy,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.RFC7591ClientRegistrationFactory,
	)

	config.RFC7591ClientRegistrationEndpointAuthStrategy = rfc7591.NewDefaultEndpointAuthStrategy(config, memory, strategy, strategy)

	router := mux.NewRouter()
	router.HandleFunc("/token", tokenEndpointHandler(t, provider))
	router.HandleFunc("/register", registrationEndpointHandler(provider))

	ts := httptest.NewServer(router)
	defer ts.Close()

	registrationURL := ts.URL + "/register"

	config.RFC7591ClientRegistrationEndpointURL = registrationURL

	newClient := func(id string, scopes, audience []string) *oauth2.DefaultClient {
		return &oauth2.DefaultClient{
			ID:           id,
			ClientSecret: oauth2.NewPlainTextClientSecret("foobar"),
			GrantTypes:   []string{"client_credentials"},
			Scopes:       scopes,
			Audience:     audience,
		}
	}

	memory.Clients["onboarding"] = newClient("onboarding", []string{consts.ScopeClientRegistration, consts.ScopeOpenID}, []string{registrationURL})
	memory.Clients["no-audience"] = newClient("no-audience", []string{consts.ScopeClientRegistration, consts.ScopeOpenID}, []string{"https://api.example.com"})
	memory.Clients["no-scope"] = newClient("no-scope", []string{consts.ScopeOpenID}, []string{registrationURL})

	token := func(t *testing.T, id string, scopes []string, audience string) (*xoauth2.Token, error) {
		t.Helper()

		return (&clientcredentials.Config{
			ClientID:       id,
			ClientSecret:   "foobar",
			Scopes:         scopes,
			TokenURL:       ts.URL + "/token",
			EndpointParams: url.Values{consts.FormParameterAudience: {audience}},
		}).Token(t.Context())
	}

	creation, err := token(t, "onboarding", []string{consts.ScopeClientRegistration, consts.ScopeOpenID}, registrationURL)
	require.NoError(t, err)
	require.NotEmpty(t, creation.AccessToken)
	assert.Truef(t, strings.HasPrefix(creation.AccessToken, "authelia_at_"),
		"a creation token is an ordinary access token and carries the ordinary access token prefix, got %q", creation.AccessToken)

	var created dcrResponse

	status := doDCRRequest(t, http.MethodPost, registrationURL, creation.AccessToken, map[string]any{
		"client_name":                "End To End Client",
		"redirect_uris":              []string{"https://client.example.com/callback"},
		"token_endpoint_auth_method": "client_secret_basic",
		"scope":                      "openid",
	}, &created)

	require.Equal(t, http.StatusCreated, status)
	assert.NotEmpty(t, created.ClientID)
	assert.Equal(t, "openid", created.Scope)
	assert.Truef(t, strings.HasPrefix(created.RegistrationAccessToken, "authelia_cr_"),
		"the management token is still minted through the client registration token strategy, got %q", created.RegistrationAccessToken)

	_, err = token(t, "no-audience", []string{consts.ScopeClientRegistration, consts.ScopeOpenID}, registrationURL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_target")

	_, err = token(t, "no-scope", []string{consts.ScopeClientRegistration}, registrationURL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_scope")

	unscoped, err := token(t, "onboarding", []string{consts.ScopeOpenID}, registrationURL)
	require.NoError(t, err)

	status = doDCRRequest(t, http.MethodPost, registrationURL, unscoped.AccessToken, map[string]any{
		"redirect_uris": []string{"https://client.example.com/callback"},
	}, nil)
	assert.Equal(t, http.StatusForbidden, status)
}

func TestClientRegistration(t *testing.T) {
	ctx := context.Background()

	config := &oauth2.Config{
		GlobalSecret:                          []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
		RFC7591ClientRegistrationStrategy:     rfc7591.NewDefaultClientRegistrationStrategy(),
		TokenEntropy:                          32,
	}

	memory := storage.NewMemoryStore()

	strategy := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

	provider := compose.Compose(config, memory, strategy, compose.RFC7591ClientRegistrationFactory, compose.RFC7592ClientConfigurationFactory)

	config.RFC7591ClientRegistrationEndpointAuthStrategy = rfc7591.NewDefaultEndpointAuthStrategy(config, memory, strategy, strategy)

	router := mux.NewRouter()
	router.HandleFunc("/register", registrationEndpointHandler(provider))
	router.HandleFunc("/register/{id}", configurationEndpointHandler(provider))

	ts := httptest.NewServer(router)
	defer ts.Close()

	config.RFC7591ClientRegistrationEndpointURL = ts.URL + "/register"

	creator := &oauth2.DefaultClient{ID: "initial-access-client"}

	creation := oauth2.NewRequest()
	creation.Client = creator
	creation.Session = &oauth2.DefaultSession{
		ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.AccessToken: time.Now().UTC().Add(time.Hour)},
	}
	creation.GrantScope(consts.ScopeClientRegistration)
	creation.GrantScope(consts.ScopeOpenID)
	creation.GrantScope("profile")
	creation.GrantAudience(config.RFC7591ClientRegistrationEndpointURL)

	creationToken, creationSignature, err := strategy.GenerateAccessToken(ctx, creation)
	require.NoError(t, err)
	require.NoError(t, memory.CreateAccessTokenSession(ctx, creationSignature, creation))

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
	assert.Truef(t, strings.HasPrefix(created.RegistrationAccessToken, "authelia_cr_"),
		"expected a client registration token carrying the 'authelia_cr_' prefix, got %q", created.RegistrationAccessToken)
	assert.NotEmpty(t, created.RegistrationClientURI)
	assert.Equal(t, "openid", created.Scope)

	managementToken := created.RegistrationAccessToken
	registrationClientURI := created.RegistrationClientURI

	var overScoped dcrErrorResponse

	status = doDCRRequest(t, http.MethodPost, ts.URL+"/register", creationToken, map[string]any{
		"client_name":                "Over-Scoped Client",
		"redirect_uris":              []string{"https://client.example.com/callback"},
		"token_endpoint_auth_method": "client_secret_basic",
		"scope":                      "openid profile email",
	}, &overScoped)

	require.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_client_metadata", overScoped.Error)

	var read dcrResponse

	status = doDCRRequest(t, http.MethodGet, registrationClientURI, managementToken, nil, &read)

	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, created.ClientID, read.ClientID)
	assert.Equal(t, "Test Client", read.ClientName)
	assert.Equal(t, "openid", read.Scope)

	status = doDCRRequest(t, http.MethodGet, registrationClientURI, creationToken, nil, nil)
	assert.Equal(t, http.StatusUnauthorized, status)

	status = doDCRRequest(t, http.MethodPost, ts.URL+"/register", managementToken, map[string]any{
		"redirect_uris": []string{"https://client.example.com/callback"},
	}, nil)
	assert.Equal(t, http.StatusUnauthorized, status)

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

	var overScopedUpdate dcrErrorResponse

	status = doDCRRequest(t, http.MethodPut, registrationClientURI, rotatedToken, map[string]any{
		"redirect_uris":              []string{"https://client.example.com/callback"},
		"token_endpoint_auth_method": "client_secret_basic",
		"scope":                      "email",
	}, &overScopedUpdate)

	require.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_client_metadata", overScopedUpdate.Error)

	status = doDCRRequest(t, http.MethodDelete, registrationClientURI, rotatedToken, nil, nil)
	assert.Equal(t, http.StatusNoContent, status)

	status = doDCRRequest(t, http.MethodGet, registrationClientURI, rotatedToken, nil, nil)
	assert.Equal(t, http.StatusUnauthorized, status, "the session backing the rotated token was deleted by the DELETE above")
}

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

type dcrResponse struct {
	ClientID                string `json:"client_id"`
	ClientSecret            string `json:"client_secret"`
	ClientName              string `json:"client_name"`
	Scope                   string `json:"scope"`
	RegistrationAccessToken string `json:"registration_access_token"`
	RegistrationClientURI   string `json:"registration_client_uri"`
}

type dcrErrorResponse struct {
	Error string `json:"error"`
}
