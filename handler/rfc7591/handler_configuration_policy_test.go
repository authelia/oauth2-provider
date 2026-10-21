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
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestClientConfigurationHandlerPolicy(t *testing.T) {
	for name, factory := range policyTestStores() {
		t.Run(name, func(t *testing.T) {
			t.Run("ShouldUpdateInPolicyBeyondTheGrantedScope", func(t *testing.T) {
				fixture := newPolicyConfigurationFixture(t, factory, policyHandlerExample(1))

				responder := oauth2.NewClientRegistrationResponse()

				require.NoError(t, fixture.put(t, fixture.token, fixture.inPolicy("b"), responder))
				assert.Equal(t, http.StatusOK, responder.GetStatusCode())
				assert.NotEmpty(t, responder.RegistrationAccessToken)
				assert.NotEqual(t, fixture.token, responder.RegistrationAccessToken)

				client, err := fixture.store.GetClient(context.Background(), fixture.id)
				require.NoError(t, err)
				assert.Equal(t, []string{"https://b.apps.example.com/oauth/callback"}, client.GetRedirectURIs())
			})

			t.Run("ShouldRejectOutOfPolicyUpdateAndLeaveTheClientUnchanged", func(t *testing.T) {
				fixture := newPolicyConfigurationFixture(t, factory, policyHandlerExample(1))

				metadata := fixture.inPolicy("b")
				metadata.GrantTypes = []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeClientCredentials}

				err := fixture.put(t, fixture.token, metadata, oauth2.NewClientRegistrationResponse())

				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), policyErrorPrefix+"The 'grant_types' value 'client_credentials' is not permitted by the registration policy.")

				client, err := fixture.store.GetClient(context.Background(), fixture.id)
				require.NoError(t, err)
				assert.Equal(t, []string{policyHandlerRedirect}, client.GetRedirectURIs())
				assert.Equal(t, oauth2.Arguments{consts.GrantTypeAuthorizationCode}, client.GetGrantTypes())

				require.NoError(t, fixture.put(t, fixture.token, fixture.inPolicy("b"), oauth2.NewClientRegistrationResponse()))
			})

			t.Run("ShouldRejectOutOfPolicyUpdateAfterConsecutiveRotations", func(t *testing.T) {
				fixture := newPolicyConfigurationFixture(t, factory, policyHandlerExample(1))

				token := fixture.token

				for _, label := range []string{"b", "c"} {
					responder := oauth2.NewClientRegistrationResponse()

					require.NoError(t, fixture.put(t, token, fixture.inPolicy(label), responder))

					token = responder.RegistrationAccessToken
				}

				metadata := fixture.inPolicy("a")
				metadata.GrantTypes = []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeClientCredentials}

				err := fixture.put(t, token, metadata, oauth2.NewClientRegistrationResponse())

				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), policyErrorPrefix+"The 'grant_types' value 'client_credentials' is not permitted by the registration policy.")
			})

			t.Run("ShouldNotConsultMaxRegistrationsOnUpdate", func(t *testing.T) {
				fixture := newPolicyConfigurationFixture(t, factory, policyHandlerExample(1))

				token := fixture.token

				for range 3 {
					responder := oauth2.NewClientRegistrationResponse()

					require.NoError(t, fixture.put(t, token, fixture.inPolicy("a"), responder))

					token = responder.RegistrationAccessToken
				}

				assert.Equal(t, int64(1), fixture.memory.ClientRegistrationCounts[policyHandlerKey])
			})

			t.Run("ShouldRejectRegistrationScopeListedByThePolicy", func(t *testing.T) {
				claim := policyHandlerExample(1)
				claim[consts.ClientMetadataScope] = map[string]any{policyRuleSubsetOf: []any{consts.ScopeOpenID, consts.ScopeClientRegistration}}

				fixture := newPolicyConfigurationFixture(t, factory, claim)

				metadata := fixture.inPolicy("a")
				metadata.Scope = consts.ScopeOpenID + " " + consts.ScopeClientRegistration

				err := fixture.put(t, fixture.token, metadata, oauth2.NewClientRegistrationResponse())

				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), policyErrorPrefix+"The request requested the scopes 'authelia:oauth2:dynamic-client-registration' which the presented Client Registration Token is not permitted to grant.")
			})

			t.Run("ShouldUpdateAClientRegisteredWithoutAPolicyAsBefore", func(t *testing.T) {
				fixture := newPolicyConfigurationFixture(t, factory, nil)

				metadata := fixture.inPolicy("b")
				metadata.Scope = ""

				responder := oauth2.NewClientRegistrationResponse()

				require.NoError(t, fixture.put(t, fixture.token, metadata, responder))
				assert.Equal(t, http.StatusOK, responder.GetStatusCode())

				metadata.Scope = consts.ScopeOpenID

				err := fixture.put(t, responder.RegistrationAccessToken, metadata, oauth2.NewClientRegistrationResponse())

				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), policyErrorPrefix+"The request requested the scopes 'openid' which the presented Client Registration Token is not permitted to grant.")
			})
		})
	}
}

type policyConfigurationFixture struct {
	handler *ClientConfigurationHandler
	auth    *DefaultEndpointAuthStrategy
	store   Storage
	memory  *storage.MemoryStore
	id      string
	token   string
}

func newPolicyConfigurationFixture(t *testing.T, factory func() Storage, claim map[string]any) (fixture *policyConfigurationFixture) {
	t.Helper()

	registration, store, memory := newPolicyRegistrationHandler(t, factory)

	requester := policyRegistrationRequest(claim, policyHandlerKey)

	requester.Metadata.Scope = consts.ScopeOpenID

	if claim == nil {
		requester.Metadata.Scope = ""
	}

	responder := oauth2.NewClientRegistrationResponse()

	require.NoError(t, registration.HandleRFC7591ClientRegistrationEndpointRequest(context.Background(), requester, responder))

	return &policyConfigurationFixture{
		handler: &ClientConfigurationHandler{Store: store, Strategy: registration.Strategy, Config: registration.Config},
		auth:    NewDefaultEndpointAuthStrategy(registration.Config.(*oauth2.Config), store, registration.Strategy.(*hoauth2.HMACCoreStrategy), registration.Strategy.(*hoauth2.HMACCoreStrategy)),
		store:   store,
		memory:  memory,
		id:      responder.ClientID,
		token:   responder.RegistrationAccessToken,
	}
}

func (f *policyConfigurationFixture) inPolicy(label string) (metadata *oauth2.ClientRegistrationMetadata) {
	return &oauth2.ClientRegistrationMetadata{
		RedirectURIs:            []string{"https://" + label + ".apps.example.com/oauth/callback"},
		GrantTypes:              []string{consts.GrantTypeAuthorizationCode},
		ResponseTypes:           []string{consts.ResponseTypeAuthorizationCodeFlow},
		TokenEndpointAuthMethod: consts.ClientAuthMethodNone,
		Scope:                   consts.ScopeOpenID + " " + policyTestEmail,
	}
}

func (f *policyConfigurationFixture) put(t *testing.T, token string, metadata *oauth2.ClientRegistrationMetadata, responder oauth2.ClientConfigurationResponder) (err error) {
	t.Helper()

	ctx := context.Background()

	authenticated, err := f.auth.AuthenticateClientRegistrationRequest(ctx, authRequest(t, http.MethodPut, ClientConfigurationURL(testEndpoint, f.id), token), f.id)
	require.NoError(t, err)

	requester := oauth2.NewClientConfigurationRequest()
	requester.Method = http.MethodPut
	requester.ClientID = f.id
	requester.Signature = f.handler.Strategy.ClientRegistrationTokenSignature(ctx, token)
	requester.Metadata = metadata
	requester.Authenticated = authenticated

	return f.handler.HandleRFC7592ClientConfigurationEndpointRequest(ctx, requester, responder)
}
