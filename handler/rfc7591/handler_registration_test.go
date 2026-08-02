// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"testing"

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
	assert.Empty(t, store.Clients)
}

// TestClientRegistrationHandlerFiltersBeforeValidation is ordering-regression coverage for the comment in
// HandleRFC7591ClientRegistrationEndpointRequest asserting the metadata strategy filter runs before the configured
// validators. It pins the observable half of that claim: LocalValidator.validateTLSClientAuth rejects a subject
// value registered without 'tls_client_auth', so with mTLS disabled and 'tls_client_auth_subject_dn' submitted
// alongside an unrelated auth method, registration fails if the filter runs after validation (the unfiltered
// subject value trips the validator) and succeeds, with the subject value dropped, if the filter runs first. Without
// this test, moving the filter call below the validator loop leaves the rest of the suite green, because
// newRegistrationHandler otherwise configures no validators.
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
	requester.Authenticated = grantableFixture(KindCreate, oauth2.Arguments{"openid"})

	err := registrar.HandleRFC7591ClientRegistrationEndpointRequest(ctx, requester, oauth2.NewClientRegistrationResponse())

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidClientMetadata)
}

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

	// The cleared method is not "none", so the client is registered confidential (Public is derived from the
	// method) and receives a secret. This does not by itself prove the method was cleared before the secret
	// decision ran: "tls_client_auth" unfiltered would satisfy the same assertion. See
	// TestClientRegistrationHandlerFiltersBeforeValidation for the ordering-specific regression coverage.
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
