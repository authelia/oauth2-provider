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

func newConfigurationHandler(t *testing.T) (*ClientConfigurationHandler, *ClientRegistrationHandler, *oauth2.Config, *storage.MemoryStore) {
	t.Helper()

	config := &oauth2.Config{
		GlobalSecret:                         []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationEndpointURL: testEndpoint,
		RFC7591ClientRegistrationStrategy:    NewDefaultClientRegistrationStrategy(),
		TokenEntropy:                         32,
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
	// In production this is populated by the Provider method (Task 15) from the authenticated requester's ID, which
	// Task 11's auth strategy sets to the presented token's signature. This test drives the handler directly, so it
	// has to reproduce that wiring by hand.
	requester.Signature = handler.Strategy.AccessTokenSignature(ctx, oldToken)
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs: []string{"https://example.com/other"},
	}

	responder := oauth2.NewClientRegistrationResponse()

	require.NoError(t, handler.HandleRFC7592ClientConfigurationEndpointRequest(ctx, requester, responder))

	client, err := store.GetClient(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://example.com/other"}, client.GetRedirectURIs())

	// Replacement semantics: values absent from the update are removed.
	registered, ok := client.(*oauth2.DefaultRegisteredClient)
	require.True(t, ok)
	assert.Empty(t, registered.ClientName)
	assert.Empty(t, registered.Contacts)

	// The registration access token is rotated and the old session is gone.
	newToken := responder.ToMap()["registration_access_token"].(string)
	assert.NotEqual(t, oldToken, newToken)

	_, err = store.GetAccessTokenSession(ctx, handler.Strategy.AccessTokenSignature(ctx, oldToken), &oauth2.DefaultSession{})
	require.Error(t, err)

	_, err = store.GetAccessTokenSession(ctx, handler.Strategy.AccessTokenSignature(ctx, newToken), &oauth2.DefaultSession{})
	require.NoError(t, err)
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

	// A rejected PUT must not have changed the client.
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

	// A rejected PUT must not have changed the client.
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
	requester.Signature = handler.Strategy.AccessTokenSignature(ctx, oldToken)
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

	// The client_id and client_secret pseudo-metadata must not survive into persisted Extra, but an unrelated
	// unregistered parameter must.
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
	// See the note in TestClientConfigurationHandlerUpdateReplaces: this reproduces the Task 15 Provider wiring by
	// hand since this test drives the handler directly.
	requester.Signature = handler.Strategy.AccessTokenSignature(ctx, token)

	responder := oauth2.NewClientRegistrationResponse()

	require.NoError(t, handler.HandleRFC7592ClientConfigurationEndpointRequest(ctx, requester, responder))

	assert.Equal(t, http.StatusNoContent, responder.GetStatusCode())
	assert.Nil(t, responder.GetMetadata())

	_, err := store.GetClient(ctx, id)
	require.Error(t, err)

	_, err = store.GetAccessTokenSession(ctx, handler.Strategy.AccessTokenSignature(ctx, token), &oauth2.DefaultSession{})
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

// TestClientConfigurationHandlerEnforcesScopeCeiling proves a registered client cannot escalate its own scopes by
// updating itself, which is what carrying the ceiling forward onto the management token exists to prevent.
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
	requester.Authenticated = grantableFixture(KindManage, oauth2.Arguments{"openid"})

	err := handler.HandleRFC7592ClientConfigurationEndpointRequest(ctx, requester, oauth2.NewClientRegistrationResponse())

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidClientMetadata)
}

// TestClientConfigurationHandlerPreservesCeilingAcrossRotation proves the rotated management token carries the same
// ceiling, so the check cannot be escaped by updating twice.
//
// The ceiling and the requested scopes are deliberately different: the update requests only 'openid' while the
// presented token's ceiling is 'openid profile'. Were the two identical the assertion could not tell a ceiling
// carried forward from the session apart from one derived from whatever the request happened to ask for, and a
// regression that narrowed the ceiling to the requested scopes - silently and permanently lowering it on every
// update - would pass unnoticed.
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
	requester.Authenticated = grantableFixture(KindManage, oauth2.Arguments{"openid", "profile"})

	responder := oauth2.NewClientRegistrationResponse()
	require.NoError(t, handler.HandleRFC7592ClientConfigurationEndpointRequest(ctx, requester, responder))

	rotated := responder.ToMap()["registration_access_token"].(string)

	tokens := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

	next, err := store.GetAccessTokenSession(ctx, tokens.AccessTokenSignature(ctx, rotated), NewDefaultSession())
	require.NoError(t, err)

	session, ok := next.GetSession().(Session)
	require.True(t, ok)

	assert.Equal(t, KindManage, session.GetClientRegistrationKind())
	assert.Equal(t, oauth2.Arguments{"openid", "profile"}, session.GetGrantableScopes())
}

// scopeStrategyClient is a client that supplies its own oauth2.ScopeStrategy, one that accepts every scope. Nothing
// in this repository ships such a client type, but oauth2.GetScopeStrategy prefers a client's strategy over the
// configured one whenever a client is passed to it, so a deployment could introduce one.
type scopeStrategyClient struct {
	oauth2.Client
}

func (c *scopeStrategyClient) GetScopeStrategy(_ context.Context) (strategy oauth2.ScopeStrategy) {
	return func(haystack []string, needle string) bool { return true }
}

// TestClientConfigurationHandlerCeilingIgnoresClientScopeStrategy proves the scope ceiling is compared with the
// server's strategy and not the registered client's. The ceiling is a server-side control over what a client may be
// granted, so the controlled party must not get to supply the comparison function; it would also make the
// registration endpoint, which has no client at all, and the configuration endpoint disagree.
func TestClientConfigurationHandlerCeilingIgnoresClientScopeStrategy(t *testing.T) {
	ctx := context.Background()
	handler, registrar, config, store := newConfigurationHandler(t)
	config.ScopeStrategy = oauth2.ExactScopeStrategy

	created := registerClient(t, ctx, registrar)
	id := created["client_id"].(string)

	registered, err := store.GetClient(ctx, id)
	require.NoError(t, err)

	// Replace the stored client with one that would accept any scope if its strategy were consulted.
	store.Clients[id] = &scopeStrategyClient{Client: registered}

	requester := oauth2.NewClientConfigurationRequest()
	requester.Method = http.MethodPut
	requester.ClientID = id
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs:  []string{"https://example.com/cb"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scope:         "openid profile",
	}
	requester.Authenticated = grantableFixture(KindManage, oauth2.Arguments{"openid"})

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
