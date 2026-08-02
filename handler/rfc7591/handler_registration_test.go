// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/storage"
)

func newRegistrationHandler(t *testing.T) (*ClientRegistrationHandler, *oauth2.Config, *storage.MemoryStore) {
	t.Helper()

	config := &oauth2.Config{
		GlobalSecret:                         []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationEndpointURL: testEndpoint,
		RFC7591ClientRegistrationStrategy:    NewDefaultClientRegistrationStrategy(),
		TokenEntropy:                         32,
	}

	store := storage.NewMemoryStore()

	return &ClientRegistrationHandler{
		Store:    store,
		Strategy: hoauth2.NewHMACCoreStrategy(config, "authelia_%s_"),
		Config:   config,
	}, config, store
}

func TestClientRegistrationHandlerCreates(t *testing.T) {
	ctx := context.Background()
	handler, _, store := newRegistrationHandler(t)

	requester := oauth2.NewClientRegistrationRequest()
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs:  []string{"https://example.com/cb"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		ClientName:    "Example",
	}

	responder := oauth2.NewClientRegistrationResponse()

	require.NoError(t, handler.HandleRFC7591ClientRegistrationEndpointRequest(ctx, requester, responder))

	values := responder.ToMap()

	id, ok := values["client_id"].(string)
	require.True(t, ok)
	assert.NotEmpty(t, id)

	secret, ok := values["client_secret"].(string)
	require.True(t, ok)
	assert.NotEmpty(t, secret)

	assert.Equal(t, ClientConfigurationURL(testEndpoint, id), values["registration_client_uri"])

	token, ok := values["registration_access_token"].(string)
	require.True(t, ok)
	assert.NotEmpty(t, token)

	client, err := store.GetClient(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://example.com/cb"}, client.GetRedirectURIs())

	// The registration access token resolves and is bound to the new client.
	session, err := store.GetAccessTokenSession(ctx, handler.Strategy.AccessTokenSignature(ctx, token), &oauth2.DefaultSession{})
	require.NoError(t, err)
	assert.Equal(t, id, session.GetSession().GetSubject())
	assert.Equal(t, oauth2.Arguments{ClientConfigurationURL(testEndpoint, id)}, session.GetGrantedAudience())
}

func TestClientRegistrationHandlerOmitsSecretForNoneAuthMethod(t *testing.T) {
	ctx := context.Background()
	handler, _, _ := newRegistrationHandler(t)

	requester := oauth2.NewClientRegistrationRequest()
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs:            []string{"https://example.com/cb"},
		TokenEndpointAuthMethod: "none",
	}

	responder := oauth2.NewClientRegistrationResponse()

	require.NoError(t, handler.HandleRFC7591ClientRegistrationEndpointRequest(ctx, requester, responder))

	assert.NotContains(t, responder.ToMap(), "client_secret")
}

func TestClientRegistrationHandlerRunsValidators(t *testing.T) {
	ctx := context.Background()
	handler, config, store := newRegistrationHandler(t)

	config.RFC7591ClientRegistrationValidators = []oauth2.ClientRegistrationValidator{NewLocalValidator(config)}

	requester := oauth2.NewClientRegistrationRequest()
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs: []string{"https://example.com/cb#frag"},
	}

	err := handler.HandleRFC7591ClientRegistrationEndpointRequest(ctx, requester, oauth2.NewClientRegistrationResponse())
	require.Error(t, err)
	assert.Equal(t, "invalid_redirect_uri", oauth2.ErrorToRFC6749Error(err).ErrorField)

	// A rejected registration must not have persisted a client.
	assert.Empty(t, store.Clients)
}

func TestClientRegistrationHandlerNilStrategy(t *testing.T) {
	ctx := context.Background()
	handler, config, store := newRegistrationHandler(t)

	config.RFC7591ClientRegistrationStrategy = nil

	requester := oauth2.NewClientRegistrationRequest()
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs: []string{"https://example.com/cb"},
	}

	err := handler.HandleRFC7591ClientRegistrationEndpointRequest(ctx, requester, oauth2.NewClientRegistrationResponse())
	require.Error(t, err)
	assert.Equal(t, oauth2.ErrServerError.ErrorField, oauth2.ErrorToRFC6749Error(err).ErrorField)

	assert.Empty(t, store.Clients)
}

// failingSessionStore wraps a Storage, failing CreateAccessTokenSession so the handler's compensating delete path
// can be exercised. It also records the id of every client it is asked to create, so the test can confirm the
// specific client the handler created is the one it deleted.
type failingSessionStore struct {
	Storage

	createdID string
}

func (f *failingSessionStore) CreateClient(ctx context.Context, client oauth2.Client) (err error) {
	f.createdID = client.GetID()

	return f.Storage.CreateClient(ctx, client)
}

func (f *failingSessionStore) CreateAccessTokenSession(ctx context.Context, signature string, requester oauth2.Requester) (err error) {
	return errTestCreateSessionFailed
}

var errTestCreateSessionFailed = errors.New("create access token session failed")

func TestClientRegistrationHandlerCompensatingDelete(t *testing.T) {
	ctx := context.Background()
	handler, _, store := newRegistrationHandler(t)

	wrapped := &failingSessionStore{Storage: store}
	handler.Store = wrapped

	requester := oauth2.NewClientRegistrationRequest()
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs: []string{"https://example.com/cb"},
	}

	responder := oauth2.NewClientRegistrationResponse()

	err := handler.HandleRFC7591ClientRegistrationEndpointRequest(ctx, requester, responder)
	require.Error(t, err)
	assert.Equal(t, oauth2.ErrServerError.ErrorField, oauth2.ErrorToRFC6749Error(err).ErrorField)

	// The response must not have been populated with a client id the caller could mistake for success.
	assert.Empty(t, responder.ClientID)

	// The client the handler created must have been deleted by the compensating delete: nobody holds a token for
	// it, so leaving it behind would make it permanently unmanageable.
	require.NotEmpty(t, wrapped.createdID)

	_, err = store.GetClient(ctx, wrapped.createdID)
	assert.Error(t, err)

	assert.Empty(t, store.Clients)
}

func TestClientRegistrationHandlerEnforcesScopeCeiling(t *testing.T) {
	ctx := context.Background()
	_, registrar, config, _ := newConfigurationHandler(t)
	config.ScopeStrategy = oauth2.ExactScopeStrategy

	requester := oauth2.NewClientRegistrationRequest()
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs:  []string{"https://example.com/cb"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scope:         "openid profile",
	}
	requester.Authenticated = grantableFixture(KindCreate, oauth2.Arguments{"openid"})

	err := registrar.HandleRFC7591ClientRegistrationEndpointRequest(ctx, requester, oauth2.NewClientRegistrationResponse())

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidClientMetadata)
}
