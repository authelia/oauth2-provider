// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/handler/cimd"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/rfc7591"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestClientIDMetadataDocumentCeilingDocumentClientCanNotRegisterClients(t *testing.T) {
	env := newCIMDCeilingEnv(t, cimd.Config{
		Scopes:     []string{consts.ScopeClientRegistration, "openid", "admin"},
		GrantTypes: []string{consts.GrantTypeClientCredentials, consts.GrantTypeAuthorizationCode},
	})

	id := env.setGreedyDocument([]string{"client_credentials"})

	registration := map[string]any{
		"client_name":                "Persisted by an anonymous document client",
		"redirect_uris":              []string{"https://attacker.example.com/callback"},
		"token_endpoint_auth_method": "client_secret_basic",
		"grant_types":                []string{"client_credentials", "authorization_code"},
		"response_types":             []string{"code"},
		"scope":                      "openid admin",
	}

	testCases := []struct {
		name     string
		scope    []string
		audience []string
	}{
		{"ShouldNotGrantTheRegistrationScopeAndAudienceWhenRequested", []string{consts.ScopeClientRegistration + " openid admin"}, []string{env.registrationURL}},
		{"ShouldNotGrantTheRegistrationScopeWhenRequestedAlone", []string{consts.ScopeClientRegistration}, nil},
		{"ShouldNotGrantTheRegistrationAudienceWhenRequestedAlone", nil, []string{env.registrationURL}},
		{"ShouldNotGrantTheRegistrationScopeImplicitly", nil, nil},
		{"ShouldNotGrantTheRegistrationScopeWithThePermittedScopes", []string{"openid admin"}, nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{
				consts.FormParameterGrantType:           {consts.GrantTypeClientCredentials},
				consts.FormParameterClientAssertionType: {consts.ClientAssertionTypeJWTBearer},
				consts.FormParameterClientAssertion:     {env.documents.assertion(t, id, env.tokenURL)},
			}

			if tc.scope != nil {
				form[consts.FormParameterScope] = tc.scope
			}

			if tc.audience != nil {
				form[consts.FormParameterAudience] = tc.audience
			}

			status, token := env.token(t, form)

			assert.NotContains(t, strings.Fields(stringOf(token["scope"])), consts.ScopeClientRegistration)

			access := stringOf(token["access_token"])

			if status != http.StatusOK {
				assert.Empty(t, access)

				access = "authelia_at_not-a-token"
			}

			var created map[string]any

			status = doDCRRequest(t, http.MethodPost, env.registrationURL, access, registration, &created)

			assert.NotEqual(t, http.StatusCreated, status)
			assert.GreaterOrEqual(t, status, http.StatusBadRequest)
			assert.Empty(t, created["client_id"])
			assert.Empty(t, env.store.Clients)
		})
	}

	t.Run("ShouldIssueATokenWithOnlyThePermittedScopes", func(t *testing.T) {
		status, token := env.token(t, url.Values{
			consts.FormParameterGrantType:           {consts.GrantTypeClientCredentials},
			consts.FormParameterScope:               {"openid admin"},
			consts.FormParameterClientAssertionType: {consts.ClientAssertionTypeJWTBearer},
			consts.FormParameterClientAssertion:     {env.documents.assertion(t, id, env.tokenURL)},
		})

		require.Equal(t, http.StatusOK, status)
		assert.NotEmpty(t, token["access_token"])
		assert.ElementsMatch(t, []string{"openid", "admin"}, strings.Fields(stringOf(token["scope"])))
	})
}

func TestClientIDMetadataDocumentCeilingDefaultGrantTypesRefuseClientCredentials(t *testing.T) {
	testCases := []struct {
		name       string
		grantTypes []string
		err        string
	}{
		{"ShouldRefuseADocumentWithOnlyTheClientCredentialsGrant", []string{"client_credentials"}, "invalid_client"},
		{"ShouldRefuseTheClientCredentialsGrantOfAnAuthorizationCodeClient", []string{"authorization_code", "client_credentials"}, "unauthorized_client"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			env := newCIMDCeilingEnv(t, cimd.Config{Scopes: []string{consts.ScopeClientRegistration, "openid", "admin"}})

			id := env.setGreedyDocument(tc.grantTypes)

			status, token := env.token(t, url.Values{
				consts.FormParameterGrantType:           {consts.GrantTypeClientCredentials},
				consts.FormParameterScope:               {"openid"},
				consts.FormParameterClientAssertionType: {consts.ClientAssertionTypeJWTBearer},
				consts.FormParameterClientAssertion:     {env.documents.assertion(t, id, env.tokenURL)},
			})

			assert.GreaterOrEqual(t, status, http.StatusBadRequest)
			assert.Equal(t, tc.err, token["error"])
			assert.Empty(t, token["access_token"])
			assert.Empty(t, env.store.AccessTokens)
		})
	}
}

func TestClientIDMetadataDocumentCeilingReducesScopeAndDropsAudience(t *testing.T) {
	env := newCIMDCeilingEnv(t, cimd.Config{Scopes: []string{"oauth2"}})

	id := env.documents.documents.URL + "/public.json"

	env.documents.setDocument("/public.json", map[string]any{
		"client_id":                   id,
		"redirect_uris":               []string{"https://client.example.com/callback"},
		"scope":                       "oauth2 admin",
		"audience":                    []string{env.registrationURL, "https://api.example.com"},
		"resource":                    []string{"https://resource.example.com"},
		"authorization_details_types": []string{"payment_initiation"},
		"sector_identifier_uri":       "https://victim.example.com/sector.json",
	})

	client, err := oauth2.GetClient(t.Context(), env.config, env.store, id)

	require.NoError(t, err)

	assert.Equal(t, oauth2.Arguments{"oauth2"}, client.GetScopes())
	assert.Empty(t, client.GetAudience())
	assert.Equal(t, oauth2.Arguments{"authorization_code"}, client.GetGrantTypes())

	registered, ok := client.(*cimd.Client)

	require.True(t, ok)

	assert.Empty(t, registered.Resource)
	assert.Empty(t, registered.AuthorizationDetailsTypes)
	assert.Empty(t, registered.SectorIdentifierURI)

	record, err := env.store.GetClientIDMetadataDocument(t.Context(), id)

	require.NoError(t, err)

	assert.Equal(t, "oauth2", record.Metadata.Scope)
	assert.Empty(t, record.Metadata.Audience)
}

type cimdCeilingEnv struct {
	documents       *cimdEnv
	config          *oauth2.Config
	store           *storage.MemoryStore
	tokenURL        string
	registrationURL string
}

func newCIMDCeilingEnv(t *testing.T, resolver cimd.Config) *cimdCeilingEnv {
	t.Helper()

	env := &cimdCeilingEnv{
		documents: newCIMDEnv(t, storage.NewMemoryStore(), false, false),
		store:     storage.NewMemoryStore(),
	}

	env.config = &oauth2.Config{
		GlobalSecret:                                []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationGlobalSecret:       []byte("a-completely-different-secret-at-least-32b"),
		RFC7591ClientRegistrationStrategy:           rfc7591.NewDefaultClientRegistrationStrategy(),
		TokenEntropy:                                32,
		ScopeStrategy:                               oauth2.ExactScopeStrategy,
		AudienceStrategy:                            oauth2.ExactAudienceStrategy,
		ClientCredentialsFlowImplicitGrantRequested: true,
	}

	strategy := hoauth2.NewHMACCoreStrategy(env.config, "authelia_%s_")
	client := cimdHTTPClient(env.documents.documents)

	resolver.Storage = env.store
	resolver.HTTPClient = client
	resolver.ValidatorConfig = env.config

	var err error

	env.config.ClientIDMetadataDocumentResolver, err = cimd.NewResolver(resolver)
	require.NoError(t, err)

	env.config.ClientIDMetadataDocumentHTTPClient = client
	env.config.ClientIDMetadataDocumentJWKSFetcherStrategy = oauth2.NewDefaultJWKSFetcherStrategy(oauth2.JWKSFetcherWithHTTPClient(client))

	provider := compose.Compose(env.config, env.store, strategy,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.RFC7591ClientRegistrationFactory,
	)

	env.config.RFC7591ClientRegistrationEndpointAuthStrategy = rfc7591.NewDefaultEndpointAuthStrategy(env.config, env.store, strategy, strategy)

	router := http.NewServeMux()
	router.HandleFunc("/token", tokenEndpointHandler(t, provider))
	router.HandleFunc("/register", registrationEndpointHandler(provider))

	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	env.tokenURL = server.URL + "/token"
	env.registrationURL = server.URL + "/register"

	env.config.RFC7591ClientRegistrationEndpointURL = env.registrationURL
	env.config.AllowedJWTAssertionAudiences = []string{env.tokenURL}

	return env
}

func (e *cimdCeilingEnv) setGreedyDocument(grantTypes []string) (id string) {
	id = e.documents.documents.URL + "/evil.json"

	e.documents.setDocument("/evil.json", map[string]any{
		"client_id":                       id,
		"token_endpoint_auth_method":      "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"grant_types":                     grantTypes,
		"redirect_uris":                   []string{"https://attacker.example.com/callback"},
		"jwks_uri":                        e.documents.documents.URL + "/jwks.json",
		"scope":                           consts.ScopeClientRegistration + " openid admin",
		"audience":                        []string{e.registrationURL},
	})

	return id
}

func (e *cimdCeilingEnv) token(t *testing.T, form url.Values) (status int, token map[string]any) {
	t.Helper()

	response, err := http.PostForm(e.tokenURL, form)
	require.NoError(t, err)

	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)

	token = map[string]any{}

	require.NoError(t, json.Unmarshal(body, &token), "Got body: %s", string(body))

	return response.StatusCode, token
}

func stringOf(value any) (s string) {
	s, _ = value.(string)

	return s
}
