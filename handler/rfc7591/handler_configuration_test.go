// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/storage"
)

func TestClientConfigurationHandlerReads(t *testing.T) {
	ctx := context.Background()
	handler, registrar, _, _ := newConfigurationHandler(t)

	created := registerClient(t, ctx, registrar)
	id := created["client_id"].(string)

	requester := oauth2.NewClientConfigurationRequest()
	requester.Method = http.MethodGet
	requester.ClientID = id

	responder := oauth2.NewClientRegistrationResponse()

	require.NoError(t, handler.HandleRFC7592ClientConfigurationEndpointRequest(ctx, requester, responder))

	values := responder.ToMap()

	assert.Equal(t, id, values["client_id"])
	assert.Equal(t, "Example", values["client_name"])
	assert.Equal(t, ClientConfigurationURL(testEndpoint, id), values["registration_client_uri"])
	assert.Equal(t, http.StatusOK, responder.GetStatusCode())
}

func TestClientConfigurationHandlerUpdateReplaces(t *testing.T) {
	ctx := context.Background()
	handler, registrar, _, store := newConfigurationHandler(t)

	created := registerClient(t, ctx, registrar)
	id := created["client_id"].(string)
	oldToken := created["registration_access_token"].(string)

	requester := oauth2.NewClientConfigurationRequest()
	requester.Method = http.MethodPut
	requester.ClientID = id
	requester.Signature = handler.Strategy.ClientRegistrationTokenSignature(ctx, oldToken)
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs: []string{"https://example.com/other"},
	}

	responder := oauth2.NewClientRegistrationResponse()

	require.NoError(t, handler.HandleRFC7592ClientConfigurationEndpointRequest(ctx, requester, responder))

	client, err := store.GetClient(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://example.com/other"}, client.GetRedirectURIs())

	registered, ok := client.(*oauth2.DefaultRegisteredClient)
	require.True(t, ok)
	assert.Empty(t, registered.ClientName)
	assert.Empty(t, registered.Contacts)

	newToken := responder.ToMap()["registration_access_token"].(string)
	assert.NotEqual(t, oldToken, newToken)

	_, err = store.GetClientRegistrationTokenSession(ctx, handler.Strategy.ClientRegistrationTokenSignature(ctx, oldToken), &oauth2.DefaultSession{})
	require.Error(t, err)

	_, err = store.GetClientRegistrationTokenSession(ctx, handler.Strategy.ClientRegistrationTokenSignature(ctx, newToken), &oauth2.DefaultSession{})
	require.NoError(t, err)
}

// ClientConfigurationRequester documents GetMetadata as nil for GET and DELETE, which makes a PUT carrying none a
// shape the interface itself admits. It must be answered with an error rather than dereferenced - without the guard
// the nil reaches the validator chain and the handler panics - and the target client must be left untouched, since
// RFC 7592 §2.2 replacement semantics would otherwise read an empty PUT as "replace everything with nothing".
func TestClientConfigurationHandlerUpdateRejectsNilMetadata(t *testing.T) {
	ctx := context.Background()
	handler, registrar, config, store := newConfigurationHandler(t)

	config.RFC7591ClientRegistrationValidators = []oauth2.ClientRegistrationValidator{NewLocalValidator(config)}

	created := registerClient(t, ctx, registrar)
	id := created["client_id"].(string)

	requester := oauth2.NewClientConfigurationRequest()
	requester.Method = http.MethodPut
	requester.ClientID = id

	err := handler.HandleRFC7592ClientConfigurationEndpointRequest(ctx, requester, oauth2.NewClientRegistrationResponse())
	require.Error(t, err)
	assert.Equal(t, "invalid_client_metadata", oauth2.ErrorToRFC6749Error(err).ErrorField)

	client, gerr := store.GetClient(ctx, id)
	require.NoError(t, gerr)
	assert.Equal(t, []string{"https://example.com/cb"}, client.GetRedirectURIs())
}

type failingUpdateClientStore struct {
	Storage
}

func (f *failingUpdateClientStore) UpdateClient(ctx context.Context, id string, client oauth2.Client) (err error) {
	return errTestUpdateClientFailed
}

func TestClientConfigurationHandlerUpdateLeavesClientIntactWhenStoreFails(t *testing.T) {
	ctx := context.Background()
	handler, registrar, _, store := newConfigurationHandler(t)

	created := registerClient(t, ctx, registrar)
	id := created["client_id"].(string)

	handler.Store = &failingUpdateClientStore{Storage: store}

	requester := oauth2.NewClientConfigurationRequest()
	requester.Method = http.MethodPut
	requester.ClientID = id
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs: []string{"https://example.com/other"},
	}

	err := handler.HandleRFC7592ClientConfigurationEndpointRequest(ctx, requester, oauth2.NewClientRegistrationResponse())
	require.Error(t, err)
	assert.Equal(t, "server_error", oauth2.ErrorToRFC6749Error(err).ErrorField)

	client, gerr := store.GetClient(ctx, id)
	require.NoError(t, gerr)

	assert.Equal(t, []string{"https://example.com/cb"}, client.GetRedirectURIs(), "a failed update must not leave the replacement applied to the stored client")

	registered, ok := client.(*oauth2.DefaultRegisteredClient)
	require.True(t, ok)
	assert.Equal(t, "Example", registered.ClientName)
}

func TestClientConfigurationHandlerUpdateRejectsClientIDMismatch(t *testing.T) {
	ctx := context.Background()
	handler, registrar, _, store := newConfigurationHandler(t)

	created := registerClient(t, ctx, registrar)
	id := created["client_id"].(string)

	requester := oauth2.NewClientConfigurationRequest()
	requester.Method = http.MethodPut
	requester.ClientID = id
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs: []string{"https://example.com/other"},
		Extra:        map[string]any{"client_id": "someone-else"},
	}

	err := handler.HandleRFC7592ClientConfigurationEndpointRequest(ctx, requester, oauth2.NewClientRegistrationResponse())
	require.Error(t, err)
	assert.Equal(t, "invalid_client_metadata", oauth2.ErrorToRFC6749Error(err).ErrorField)

	client, gerr := store.GetClient(ctx, id)
	require.NoError(t, gerr)
	assert.Equal(t, []string{"https://example.com/cb"}, client.GetRedirectURIs())
}

func TestClientConfigurationHandlerUpdateRejectsWrongClientSecret(t *testing.T) {
	ctx := context.Background()
	handler, registrar, _, store := newConfigurationHandler(t)

	created := registerClient(t, ctx, registrar)
	id := created["client_id"].(string)

	requester := oauth2.NewClientConfigurationRequest()
	requester.Method = http.MethodPut
	requester.ClientID = id
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs: []string{"https://example.com/other"},
		Extra:        map[string]any{"client_secret": "not-the-secret"},
	}

	err := handler.HandleRFC7592ClientConfigurationEndpointRequest(ctx, requester, oauth2.NewClientRegistrationResponse())
	require.Error(t, err)
	assert.Equal(t, "invalid_client_metadata", oauth2.ErrorToRFC6749Error(err).ErrorField)

	client, gerr := store.GetClient(ctx, id)
	require.NoError(t, gerr)
	assert.Equal(t, []string{"https://example.com/cb"}, client.GetRedirectURIs())
}

func TestClientConfigurationHandlerUpdateAcceptsCorrectClientSecretAndStripsExtra(t *testing.T) {
	ctx := context.Background()
	handler, registrar, _, store := newConfigurationHandler(t)

	created := registerClient(t, ctx, registrar)
	id := created["client_id"].(string)
	secret := created["client_secret"].(string)
	oldToken := created["registration_access_token"].(string)

	requester := oauth2.NewClientConfigurationRequest()
	requester.Method = http.MethodPut
	requester.ClientID = id
	requester.Signature = handler.Strategy.ClientRegistrationTokenSignature(ctx, oldToken)
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs: []string{"https://example.com/other"},
		Extra: map[string]any{
			"client_id":     id,
			"client_secret": secret,
			"custom_field":  "keep-me",
		},
	}

	responder := oauth2.NewClientRegistrationResponse()

	require.NoError(t, handler.HandleRFC7592ClientConfigurationEndpointRequest(ctx, requester, responder))

	client, err := store.GetClient(ctx, id)
	require.NoError(t, err)

	registered, ok := client.(*oauth2.DefaultRegisteredClient)
	require.True(t, ok)

	assert.NotContains(t, registered.Extra, "client_id")
	assert.NotContains(t, registered.Extra, "client_secret")
	assert.Equal(t, "keep-me", registered.Extra["custom_field"])
}

func TestClientConfigurationHandlerDeletes(t *testing.T) {
	ctx := context.Background()
	handler, registrar, _, store := newConfigurationHandler(t)

	created := registerClient(t, ctx, registrar)
	id := created["client_id"].(string)
	token := created["registration_access_token"].(string)

	requester := oauth2.NewClientConfigurationRequest()
	requester.Method = http.MethodDelete
	requester.ClientID = id
	requester.Signature = handler.Strategy.ClientRegistrationTokenSignature(ctx, token)

	responder := oauth2.NewClientRegistrationResponse()

	require.NoError(t, handler.HandleRFC7592ClientConfigurationEndpointRequest(ctx, requester, responder))

	assert.Equal(t, http.StatusNoContent, responder.GetStatusCode())
	assert.Nil(t, responder.GetMetadata())

	_, err := store.GetClient(ctx, id)
	require.Error(t, err)

	_, err = store.GetClientRegistrationTokenSession(ctx, handler.Strategy.ClientRegistrationTokenSignature(ctx, token), &oauth2.DefaultSession{})
	require.Error(t, err)
}

func TestClientConfigurationHandlerRejectsUnsupportedMethod(t *testing.T) {
	ctx := context.Background()
	handler, registrar, _, _ := newConfigurationHandler(t)

	created := registerClient(t, ctx, registrar)

	requester := oauth2.NewClientConfigurationRequest()
	requester.Method = http.MethodPatch
	requester.ClientID = created["client_id"].(string)

	err := handler.HandleRFC7592ClientConfigurationEndpointRequest(ctx, requester, oauth2.NewClientRegistrationResponse())
	require.Error(t, err)
	assert.Equal(t, "invalid_request", oauth2.ErrorToRFC6749Error(err).ErrorField)
}

func TestClientConfigurationHandlerEnforcesScopeCeiling(t *testing.T) {
	ctx := context.Background()
	handler, registrar, config, _ := newConfigurationHandler(t)
	config.ScopeStrategy = oauth2.ExactScopeStrategy

	created := registerClient(t, ctx, registrar)
	id := created["client_id"].(string)

	requester := oauth2.NewClientConfigurationRequest()
	requester.Method = http.MethodPut
	requester.ClientID = id
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs:  []string{"https://example.com/cb"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scope:         "openid profile",
	}
	requester.Authenticated = grantableFixture(id, oauth2.Arguments{"openid"})

	err := handler.HandleRFC7592ClientConfigurationEndpointRequest(ctx, requester, oauth2.NewClientRegistrationResponse())

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidClientMetadata)
}

func TestClientConfigurationHandlerRejectsRegistrationScopeInMetadata(t *testing.T) {
	ctx := context.Background()
	handler, registrar, config, _ := newConfigurationHandler(t)
	config.ScopeStrategy = oauth2.ExactScopeStrategy

	created := registerClient(t, ctx, registrar)
	id := created["client_id"].(string)

	requester := oauth2.NewClientConfigurationRequest()
	requester.Method = http.MethodPut
	requester.ClientID = id
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs:  []string{"https://example.com/cb"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scope:         "client_registration",
	}
	requester.Authenticated = grantableFixture(id, oauth2.Arguments{"client_registration", "openid"})

	err := handler.HandleRFC7592ClientConfigurationEndpointRequest(ctx, requester, oauth2.NewClientRegistrationResponse())

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidClientMetadata)
}

func TestClientConfigurationHandlerRotatedManagementTokenExcludesRegistrationScope(t *testing.T) {
	ctx := context.Background()
	handler, registrar, config, store := newConfigurationHandler(t)
	config.ScopeStrategy = oauth2.ExactScopeStrategy

	created := registerClient(t, ctx, registrar)
	id := created["client_id"].(string)

	requester := oauth2.NewClientConfigurationRequest()
	requester.Method = http.MethodPut
	requester.ClientID = id
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs:  []string{"https://example.com/cb"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scope:         "openid",
	}
	requester.Authenticated = grantableFixture(id, oauth2.Arguments{"client_registration", "openid"})

	responder := oauth2.NewClientRegistrationResponse()
	require.NoError(t, handler.HandleRFC7592ClientConfigurationEndpointRequest(ctx, requester, responder))

	rotated := responder.ToMap()["registration_access_token"].(string)

	tokens := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

	next, err := store.GetClientRegistrationTokenSession(ctx, tokens.ClientRegistrationTokenSignature(ctx, rotated), &oauth2.DefaultSession{})
	require.NoError(t, err)

	granted := next.GetGrantedScopes()
	assert.NotContains(t, granted, "client_registration")
	assert.Contains(t, granted, "openid")
}

func TestClientConfigurationHandlerEnforcesAudienceCeiling(t *testing.T) {
	ctx := context.Background()
	handler, registrar, _, _ := newConfigurationHandler(t)

	created := registerClient(t, ctx, registrar)
	id := created["client_id"].(string)

	requester := oauth2.NewClientConfigurationRequest()
	requester.Method = http.MethodPut
	requester.ClientID = id
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs:  []string{"https://example.com/cb"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Audience:      []string{"https://ceiling.example.com", "https://outside.example.com"},
	}
	requester.Authenticated = grantableFixtureWithAudience(id, nil, oauth2.Arguments{"https://ceiling.example.com"})

	err := handler.HandleRFC7592ClientConfigurationEndpointRequest(ctx, requester, oauth2.NewClientRegistrationResponse())

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidClientMetadata)
}

func TestClientConfigurationHandlerPreservesCeilingAcrossRotation(t *testing.T) {
	ctx := context.Background()
	handler, registrar, config, store := newConfigurationHandler(t)
	config.ScopeStrategy = oauth2.ExactScopeStrategy

	created := registerClient(t, ctx, registrar)
	id := created["client_id"].(string)

	requester := oauth2.NewClientConfigurationRequest()
	requester.Method = http.MethodPut
	requester.ClientID = id
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs:  []string{"https://example.com/cb"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scope:         "openid",
	}
	requester.Authenticated = grantableFixture(id, oauth2.Arguments{"openid", "profile"})

	responder := oauth2.NewClientRegistrationResponse()
	require.NoError(t, handler.HandleRFC7592ClientConfigurationEndpointRequest(ctx, requester, responder))

	rotated := responder.ToMap()["registration_access_token"].(string)

	tokens := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

	next, err := store.GetClientRegistrationTokenSession(ctx, tokens.ClientRegistrationTokenSignature(ctx, rotated), &oauth2.DefaultSession{})
	require.NoError(t, err)

	assert.Equal(t, id, next.GetClient().GetID())
	assert.Equal(t, oauth2.Arguments{"openid", "profile"}, next.GetGrantedScopes())
}

func TestClientConfigurationHandlerPreservesAudienceCeilingAcrossRotation(t *testing.T) {
	ctx := context.Background()
	handler, registrar, config, store := newConfigurationHandler(t)
	config.ScopeStrategy = oauth2.ExactScopeStrategy

	created := registerClient(t, ctx, registrar)
	id := created["client_id"].(string)

	requester := oauth2.NewClientConfigurationRequest()
	requester.Method = http.MethodPut
	requester.ClientID = id
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs:  []string{"https://example.com/cb"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scope:         "openid",
	}
	requester.Authenticated = grantableFixtureWithAudience(id, oauth2.Arguments{"openid"}, oauth2.Arguments{"https://api.example.com"})

	responder := oauth2.NewClientRegistrationResponse()
	require.NoError(t, handler.HandleRFC7592ClientConfigurationEndpointRequest(ctx, requester, responder))

	rotated := responder.ToMap()["registration_access_token"].(string)

	tokens := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

	next, err := store.GetClientRegistrationTokenSession(ctx, tokens.ClientRegistrationTokenSignature(ctx, rotated), &oauth2.DefaultSession{})
	require.NoError(t, err)

	assert.Equal(t, id, next.GetClient().GetID())
	assert.Equal(t, oauth2.Arguments{ClientConfigurationURL(testEndpoint, id), "https://api.example.com"}, next.GetGrantedAudience())
}

func TestClientConfigurationHandlerCeilingIgnoresClientScopeStrategy(t *testing.T) {
	ctx := context.Background()
	handler, registrar, config, store := newConfigurationHandler(t)
	config.ScopeStrategy = oauth2.ExactScopeStrategy

	created := registerClient(t, ctx, registrar)
	id := created["client_id"].(string)

	registered, err := store.GetClient(ctx, id)
	require.NoError(t, err)

	permissive := &scopeStrategyClient{Client: registered}

	requester := oauth2.NewClientConfigurationRequest()
	requester.Method = http.MethodPut
	requester.ClientID = id
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs:  []string{"https://example.com/cb"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scope:         "openid profile",
	}
	requester.Authenticated = grantableFixtureWithClient(permissive, oauth2.Arguments{"openid"}, nil)

	err = handler.HandleRFC7592ClientConfigurationEndpointRequest(ctx, requester, oauth2.NewClientRegistrationResponse())

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidClientMetadata)
}

func TestClientConfigurationHandlerCeilingIgnoresClientAudienceStrategy(t *testing.T) {
	ctx := context.Background()
	handler, registrar, config, store := newConfigurationHandler(t)
	config.AudienceStrategy = oauth2.ExactAudienceStrategy

	created := registerClient(t, ctx, registrar)
	id := created["client_id"].(string)

	registered, err := store.GetClient(ctx, id)
	require.NoError(t, err)

	permissive := &audienceStrategyClient{Client: registered}

	requester := oauth2.NewClientConfigurationRequest()
	requester.Method = http.MethodPut
	requester.ClientID = id
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs:  []string{"https://example.com/cb"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Audience:      []string{"https://other.example.com"},
	}
	requester.Authenticated = grantableFixtureWithClient(permissive, nil, oauth2.Arguments{"https://api.example.com"})

	err = handler.HandleRFC7592ClientConfigurationEndpointRequest(ctx, requester, oauth2.NewClientRegistrationResponse())

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidClientMetadata)
}

func TestClientConfigurationHandlerRejectsUnknownClient(t *testing.T) {
	ctx := context.Background()
	handler, _, _, _ := newConfigurationHandler(t)

	requester := oauth2.NewClientConfigurationRequest()
	requester.Method = http.MethodGet
	requester.ClientID = "missing"

	err := handler.HandleRFC7592ClientConfigurationEndpointRequest(ctx, requester, oauth2.NewClientRegistrationResponse())
	require.Error(t, err)
	assert.Equal(t, http.StatusNotFound, oauth2.ErrorToRFC6749Error(err).CodeField)
}

func TestClientConfigurationHandlerWithholdsDisabledFeatureMetadataOnRead(t *testing.T) {
	ctx := context.Background()
	handler, registrar, config, _ := newConfigurationHandler(t)

	config.MTLSEnabled = true

	requester := oauth2.NewClientRegistrationRequest()
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs:            []string{"https://example.com/cb"},
		TokenEndpointAuthMethod: "tls_client_auth",
		TLSClientAuthSubjectDN:  "CN=client,O=Example",
	}

	created := oauth2.NewClientRegistrationResponse()
	require.NoError(t, registrar.HandleRFC7591ClientRegistrationEndpointRequest(ctx, requester, created))

	id := created.ToMap()["client_id"].(string)
	assert.Equal(t, "CN=client,O=Example", created.ToMap()["tls_client_auth_subject_dn"])

	read := func() map[string]any {
		configuration := oauth2.NewClientConfigurationRequest()
		configuration.Method = http.MethodGet
		configuration.ClientID = id

		responder := oauth2.NewClientRegistrationResponse()

		require.NoError(t, handler.HandleRFC7592ClientConfigurationEndpointRequest(ctx, configuration, responder))

		return responder.ToMap()
	}

	config.MTLSEnabled = false

	assert.NotContains(t, read(), "tls_client_auth_subject_dn")

	config.MTLSEnabled = true

	assert.Equal(t, "CN=client,O=Example", read()["tls_client_auth_subject_dn"])
}

func TestClientConfigurationHandlerIgnoresDisabledFeatureMetadataOnUpdate(t *testing.T) {
	ctx := context.Background()
	handler, registrar, _, store := newConfigurationHandler(t)

	created := registerClient(t, ctx, registrar)
	id := created["client_id"].(string)

	requester := oauth2.NewClientConfigurationRequest()
	requester.Method = http.MethodPut
	requester.ClientID = id
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs:           []string{"https://example.com/cb"},
		TLSClientAuthSubjectDN: "CN=client,O=Example",
		DPoPBoundAccessTokens:  true,
	}

	responder := oauth2.NewClientRegistrationResponse()

	require.NoError(t, handler.HandleRFC7592ClientConfigurationEndpointRequest(ctx, requester, responder))

	assert.NotContains(t, responder.ToMap(), "tls_client_auth_subject_dn")
	assert.NotContains(t, responder.ToMap(), "dpop_bound_access_tokens")

	client, err := store.GetClient(ctx, id)
	require.NoError(t, err)

	registered, ok := client.(*oauth2.DefaultRegisteredClient)
	require.True(t, ok)

	assert.Empty(t, registered.TLSClientAuthSubjectDN)
	assert.False(t, registered.DPoPBoundAccessTokens)
}

func newConfigurationHandler(t *testing.T) (*ClientConfigurationHandler, *ClientRegistrationHandler, *oauth2.Config, *storage.MemoryStore) {
	t.Helper()

	config := &oauth2.Config{
		GlobalSecret:                          []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
		RFC7591ClientRegistrationEndpointURL:  testEndpoint,
		RFC7591ClientRegistrationStrategy:     NewDefaultClientRegistrationStrategy(),
		TokenEntropy:                          32,
	}

	store := storage.NewMemoryStore()
	tokens := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

	return &ClientConfigurationHandler{Store: store, Strategy: tokens, Config: config},
		&ClientRegistrationHandler{Store: store, Strategy: tokens, Config: config},
		config, store
}

func registerClient(t *testing.T, ctx context.Context, handler *ClientRegistrationHandler) map[string]any {
	t.Helper()

	requester := oauth2.NewClientRegistrationRequest()
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs:  []string{"https://example.com/cb"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		ClientName:    "Example",
		Contacts:      []string{"ops@example.com"},
	}

	responder := oauth2.NewClientRegistrationResponse()

	require.NoError(t, handler.HandleRFC7591ClientRegistrationEndpointRequest(ctx, requester, responder))

	return responder.ToMap()
}

type scopeStrategyClient struct {
	oauth2.Client
}

func (c *scopeStrategyClient) GetScopeStrategy(_ context.Context) (strategy oauth2.ScopeStrategy) {
	return func(haystack []string, needle string) bool { return true }
}

type audienceStrategyClient struct {
	oauth2.Client
}

func (c *audienceStrategyClient) GetAudienceStrategy(_ context.Context) (strategy oauth2.AudienceStrategy) {
	return func(haystack, needle []string) error { return nil }
}
