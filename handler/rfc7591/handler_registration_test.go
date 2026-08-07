// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/storage"
)

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

	tokenRequester, err := store.GetClientRegistrationTokenSession(ctx, handler.Strategy.ClientRegistrationTokenSignature(ctx, token), &oauth2.DefaultSession{})
	require.NoError(t, err)

	assert.Equal(t, id, tokenRequester.GetClient().GetID())
	assert.Equal(t, oauth2.Arguments{ClientConfigurationURL(testEndpoint, id)}, tokenRequester.GetGrantedAudience())
}

func TestClientRegistrationHandlerOmitsSecretForNoneAuthMethod(t *testing.T) {
	ctx := context.Background()
	handler, config, _ := newRegistrationHandler(t)

	config.RFC7591ClientSecretLifespan = time.Hour
	requester := oauth2.NewClientRegistrationRequest()
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs:            []string{"https://example.com/cb"},
		TokenEndpointAuthMethod: "none",
	}

	responder := oauth2.NewClientRegistrationResponse()

	require.NoError(t, handler.HandleRFC7591ClientRegistrationEndpointRequest(ctx, requester, responder))

	assert.NotContains(t, responder.ToMap(), "client_secret")
	assert.NotContains(t, responder.ToMap(), "client_secret_expires_at")
	assert.True(t, responder.ClientSecretExpiresAt.IsZero())
}

func TestClientRegistrationHandlerRejectsNilMetadata(t *testing.T) {
	ctx := context.Background()
	handler, config, store := newRegistrationHandler(t)

	config.RFC7591ClientRegistrationValidators = []oauth2.ClientRegistrationValidator{NewLocalValidator(config)}

	err := handler.HandleRFC7591ClientRegistrationEndpointRequest(ctx, oauth2.NewClientRegistrationRequest(), oauth2.NewClientRegistrationResponse())
	require.Error(t, err)
	assert.Equal(t, "invalid_client_metadata", oauth2.ErrorToRFC6749Error(err).ErrorField)
	assert.Empty(t, store.Clients)
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
	assert.Empty(t, store.Clients)
}

func TestClientRegistrationHandlerFiltersBeforeValidation(t *testing.T) {
	ctx := context.Background()
	handler, config, store := newRegistrationHandler(t)

	config.RFC7591ClientRegistrationValidators = []oauth2.ClientRegistrationValidator{NewLocalValidator(config)}

	requester := oauth2.NewClientRegistrationRequest()
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs:            []string{"https://example.com/cb"},
		TokenEndpointAuthMethod: "client_secret_basic",
		TLSClientAuthSubjectDN:  "CN=client,O=Example",
	}

	responder := oauth2.NewClientRegistrationResponse()

	require.NoError(t, handler.HandleRFC7591ClientRegistrationEndpointRequest(ctx, requester, responder))

	values := responder.ToMap()
	assert.NotContains(t, values, "tls_client_auth_subject_dn")

	id, ok := values["client_id"].(string)
	require.True(t, ok)

	client, err := store.GetClient(ctx, id)
	require.NoError(t, err)

	registered, ok := client.(*oauth2.DefaultRegisteredClient)
	require.True(t, ok)
	assert.Empty(t, registered.TLSClientAuthSubjectDN)
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
	assert.Empty(t, responder.ClientID)
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
	requester.Authenticated = grantableFixture("", oauth2.Arguments{"openid"})

	err := registrar.HandleRFC7591ClientRegistrationEndpointRequest(ctx, requester, oauth2.NewClientRegistrationResponse())

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidClientMetadata)
}

func TestClientRegistrationHandlerRejectsRegistrationScopeInMetadata(t *testing.T) {
	ctx := context.Background()
	handler, config, _ := newRegistrationHandler(t)
	config.ScopeStrategy = oauth2.ExactScopeStrategy

	requester := oauth2.NewClientRegistrationRequest()
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs:  []string{"https://example.com/cb"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scope:         "authelia:oauth2:client_registration",
	}
	requester.Authenticated = grantableFixture("", oauth2.Arguments{"authelia:oauth2:client_registration", "openid"})

	err := handler.HandleRFC7591ClientRegistrationEndpointRequest(ctx, requester, oauth2.NewClientRegistrationResponse())

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidClientMetadata)
}

func TestClientRegistrationHandlerMintedManagementTokenExcludesRegistrationScope(t *testing.T) {
	ctx := context.Background()
	handler, config, store := newRegistrationHandler(t)
	config.ScopeStrategy = oauth2.ExactScopeStrategy

	requester := oauth2.NewClientRegistrationRequest()
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs:  []string{"https://example.com/cb"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scope:         "openid",
	}
	requester.Authenticated = grantableFixture("", oauth2.Arguments{"authelia:oauth2:client_registration", "openid"})

	responder := oauth2.NewClientRegistrationResponse()
	require.NoError(t, handler.HandleRFC7591ClientRegistrationEndpointRequest(ctx, requester, responder))

	token := responder.ToMap()["registration_access_token"].(string)

	tokenRequester, err := store.GetClientRegistrationTokenSession(ctx, handler.Strategy.ClientRegistrationTokenSignature(ctx, token), &oauth2.DefaultSession{})
	require.NoError(t, err)

	granted := tokenRequester.GetGrantedScopes()
	assert.NotContains(t, granted, "authelia:oauth2:client_registration")
	assert.Contains(t, granted, "openid")
}

func TestClientRegistrationHandlerUnauthenticatedExcludesRegistrationScope(t *testing.T) {
	ctx := context.Background()
	handler, _, store := newRegistrationHandler(t)

	requester := oauth2.NewClientRegistrationRequest()
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs:  []string{"https://example.com/cb"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scope:         "authelia:oauth2:client_registration openid",
		Audience:      []string{testEndpoint},
	}

	require.Nil(t, requester.GetAuthenticatedRequester())

	responder := oauth2.NewClientRegistrationResponse()
	require.NoError(t, handler.HandleRFC7591ClientRegistrationEndpointRequest(ctx, requester, responder))

	values := responder.ToMap()
	assert.Equal(t, "openid", values["scope"])

	client, err := store.GetClient(ctx, values["client_id"].(string))
	require.NoError(t, err)
	assert.NotContains(t, client.GetScopes(), "authelia:oauth2:client_registration")
	assert.Contains(t, client.GetScopes(), "openid")

	tokenRequester, err := store.GetClientRegistrationTokenSession(ctx, handler.Strategy.ClientRegistrationTokenSignature(ctx, values["registration_access_token"].(string)), &oauth2.DefaultSession{})
	require.NoError(t, err)
	assert.NotContains(t, tokenRequester.GetGrantedScopes(), "authelia:oauth2:client_registration")
}

func TestClientRegistrationHandlerEnforcesAudienceCeiling(t *testing.T) {
	ctx := context.Background()
	handler, _, _ := newRegistrationHandler(t)

	requester := oauth2.NewClientRegistrationRequest()
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs:  []string{"https://example.com/cb"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Audience:      []string{"https://ceiling.example.com", "https://outside.example.com"},
	}
	requester.Authenticated = grantableFixtureWithAudience("", nil, oauth2.Arguments{"https://ceiling.example.com"})

	err := handler.HandleRFC7591ClientRegistrationEndpointRequest(ctx, requester, oauth2.NewClientRegistrationResponse())

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidClientMetadata)
}

func TestClientRegistrationHandlerMintsAudienceCeiling(t *testing.T) {
	ctx := context.Background()

	t.Run("ShouldUseSessionCeilingWhenAuthenticated", func(t *testing.T) {
		handler, _, store := newRegistrationHandler(t)

		requester := oauth2.NewClientRegistrationRequest()
		requester.Metadata = &oauth2.ClientRegistrationMetadata{
			RedirectURIs:  []string{"https://example.com/cb"},
			GrantTypes:    []string{"authorization_code"},
			ResponseTypes: []string{"code"},
			Audience:      []string{"https://requested.example.com"},
		}
		requester.Authenticated = grantableFixtureWithAudience("", nil, oauth2.Arguments{"https://ceiling.example.com", "https://requested.example.com"})

		responder := oauth2.NewClientRegistrationResponse()
		require.NoError(t, handler.HandleRFC7591ClientRegistrationEndpointRequest(ctx, requester, responder))

		values := responder.ToMap()
		token := values["registration_access_token"].(string)
		id := values["client_id"].(string)

		tokenRequester, err := store.GetClientRegistrationTokenSession(ctx, handler.Strategy.ClientRegistrationTokenSignature(ctx, token), &oauth2.DefaultSession{})
		require.NoError(t, err)
		assert.Equal(t, oauth2.Arguments{ClientConfigurationURL(testEndpoint, id), "https://ceiling.example.com", "https://requested.example.com"}, tokenRequester.GetGrantedAudience())
	})

	t.Run("ShouldFallBackToRequestedAudienceWhenUnauthenticated", func(t *testing.T) {
		handler, _, store := newRegistrationHandler(t)

		requester := oauth2.NewClientRegistrationRequest()
		requester.Metadata = &oauth2.ClientRegistrationMetadata{
			RedirectURIs:  []string{"https://example.com/cb"},
			GrantTypes:    []string{"authorization_code"},
			ResponseTypes: []string{"code"},
			Audience:      []string{"https://requested.example.com"},
		}

		responder := oauth2.NewClientRegistrationResponse()
		require.NoError(t, handler.HandleRFC7591ClientRegistrationEndpointRequest(ctx, requester, responder))

		values := responder.ToMap()
		token := values["registration_access_token"].(string)
		id := values["client_id"].(string)

		tokenRequester, err := store.GetClientRegistrationTokenSession(ctx, handler.Strategy.ClientRegistrationTokenSignature(ctx, token), &oauth2.DefaultSession{})
		require.NoError(t, err)

		assert.Equal(t, oauth2.Arguments{ClientConfigurationURL(testEndpoint, id), "https://requested.example.com"}, tokenRequester.GetGrantedAudience())
	})
}

func TestClientRegistrationHandlerIgnoresDisabledFeatureMetadata(t *testing.T) {
	ctx := context.Background()
	handler, _, store := newRegistrationHandler(t)

	requester := oauth2.NewClientRegistrationRequest()
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs:                          []string{"https://example.com/cb"},
		TokenEndpointAuthMethod:               "tls_client_auth",
		TLSClientAuthSubjectDN:                "CN=client,O=Example",
		TLSClientCertificateBoundAccessTokens: true,
		DPoPBoundAccessTokens:                 true,
	}

	responder := oauth2.NewClientRegistrationResponse()

	require.NoError(t, handler.HandleRFC7591ClientRegistrationEndpointRequest(ctx, requester, responder))

	values := responder.ToMap()
	assert.NotContains(t, values, "tls_client_auth_subject_dn")
	assert.NotContains(t, values, "tls_client_certificate_bound_access_tokens")
	assert.NotContains(t, values, "dpop_bound_access_tokens")
	assert.NotContains(t, values, "token_endpoint_auth_method")

	secret, ok := values["client_secret"].(string)
	require.True(t, ok)
	assert.NotEmpty(t, secret)

	id := values["client_id"].(string)

	client, err := store.GetClient(ctx, id)
	require.NoError(t, err)

	registered, ok := client.(*oauth2.DefaultRegisteredClient)
	require.True(t, ok)

	assert.Empty(t, registered.TLSClientAuthSubjectDN)
	assert.False(t, registered.TLSClientCertificateBoundAccessTokens)
	assert.False(t, registered.DPoPBoundAccessTokens)
	assert.Empty(t, registered.TokenEndpointAuthMethod)
}

func TestClientRegistrationHandlerPropagatesMetadataStrategyError(t *testing.T) {
	ctx := context.Background()
	handler, config, _ := newRegistrationHandler(t)

	config.RFC7591ClientRegistrationMetadataStrategy = &testMetadataStrategy{err: oauth2.ErrInvalidClientMetadata}

	requester := oauth2.NewClientRegistrationRequest()
	requester.Metadata = &oauth2.ClientRegistrationMetadata{RedirectURIs: []string{"https://example.com/cb"}}

	err := handler.HandleRFC7591ClientRegistrationEndpointRequest(ctx, requester, oauth2.NewClientRegistrationResponse())
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidClientMetadata)
}

func newRegistrationHandler(t *testing.T) (*ClientRegistrationHandler, *oauth2.Config, *storage.MemoryStore) {
	t.Helper()

	config := &oauth2.Config{
		GlobalSecret:                          []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
		RFC7591ClientRegistrationEndpointURL:  testEndpoint,
		RFC7591ClientRegistrationStrategy:     NewDefaultClientRegistrationStrategy(),
		TokenEntropy:                          32,
	}

	store := storage.NewMemoryStore()

	return &ClientRegistrationHandler{
		Store:    store,
		Strategy: hoauth2.NewHMACCoreStrategy(config, "authelia_%s_"),
		Config:   config,
	}, config, store
}

type failingSessionStore struct {
	Storage

	createdID string
}

func (f *failingSessionStore) CreateClient(ctx context.Context, client oauth2.Client) (err error) {
	f.createdID = client.GetID()

	return f.Storage.CreateClient(ctx, client)
}

func (f *failingSessionStore) CreateClientRegistrationTokenSession(ctx context.Context, signature string, requester oauth2.Requester) (err error) {
	return errTestCreateSessionFailed
}
