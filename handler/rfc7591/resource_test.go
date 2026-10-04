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
)

func grantableFixtureWithResource(clientID string, resource oauth2.Arguments) oauth2.Requester {
	requester := oauth2.NewRequest()
	requester.Session = &oauth2.DefaultSession{}

	if clientID != "" {
		requester.Client = &oauth2.DefaultClient{ID: clientID}
	}

	for _, r := range resource {
		requester.GrantResource(r)
	}

	return requester
}

func TestCheckGrantableResource(t *testing.T) {
	testCases := []struct {
		name          string
		config        *oauth2.Config
		authenticated oauth2.Requester
		metadata      *oauth2.ClientRegistrationMetadata
		err           string
	}{
		{
			name:     "ShouldSkipWithoutAnAuthenticatedRequester",
			config:   &oauth2.Config{},
			metadata: &oauth2.ClientRegistrationMetadata{Resource: []string{"https://api.example.com/"}},
		},
		{
			name:          "ShouldAcceptAResourceInsideTheCeiling",
			config:        &oauth2.Config{},
			authenticated: grantableFixtureWithResource("", oauth2.Arguments{"https://api.example.com/"}),
			metadata:      &oauth2.ClientRegistrationMetadata{Resource: []string{"https://api.example.com/"}},
		},
		{
			name:          "ShouldRejectAResourceOutsideTheCeiling",
			config:        &oauth2.Config{},
			authenticated: grantableFixtureWithResource("", oauth2.Arguments{"https://api.example.com/"}),
			metadata:      &oauth2.ClientRegistrationMetadata{Resource: []string{"https://other.example.com/"}},
			err:           "invalid_client_metadata",
		},
		{
			name:          "ShouldRejectEveryResourceWhenTheCeilingIsEmpty",
			config:        &oauth2.Config{},
			authenticated: grantableFixtureWithResource("", nil),
			metadata:      &oauth2.ClientRegistrationMetadata{Resource: []string{"https://api.example.com/"}},
			err:           "invalid_client_metadata",
		},
		{
			name:          "ShouldAcceptWhenNoResourceIsRequested",
			config:        &oauth2.Config{},
			authenticated: grantableFixtureWithResource("", nil),
			metadata:      &oauth2.ClientRegistrationMetadata{},
		},
		{
			name:          "ShouldAcceptANarrowerWildcardUnderAWildcardCeiling",
			config:        &oauth2.Config{ResourceStrategy: oauth2.WildcardResourceStrategy},
			authenticated: grantableFixtureWithResource("", oauth2.Arguments{"https://api.example.com/*"}),
			metadata:      &oauth2.ClientRegistrationMetadata{Resource: []string{"https://api.example.com/v1/*"}},
		},
		{
			name:          "ShouldRejectAWildcardTheExactCeilingDoesNotCover",
			config:        &oauth2.Config{},
			authenticated: grantableFixtureWithResource("", oauth2.Arguments{"https://api.example.com/"}),
			metadata:      &oauth2.ClientRegistrationMetadata{Resource: []string{"https://api.example.com/*"}},
			err:           "invalid_client_metadata",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckGrantableResource(context.Background(), tc.config, tc.authenticated, tc.metadata)

			if tc.err == "" {
				assert.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.Equal(t, tc.err, oauth2.ErrorToRFC6749Error(err).ErrorField)
		})
	}
}

func TestClientRegistrationHandlerRegistersResource(t *testing.T) {
	ctx := context.Background()

	newMetadata := func(resource ...string) *oauth2.ClientRegistrationMetadata {
		return &oauth2.ClientRegistrationMetadata{
			RedirectURIs:  []string{"https://example.com/cb"},
			GrantTypes:    []string{"authorization_code"},
			ResponseTypes: []string{"code"},
			Resource:      resource,
		}
	}

	t.Run("ShouldPersistAndRespondWithTheResource", func(t *testing.T) {
		handler, _, store := newRegistrationHandler(t)

		requester := oauth2.NewClientRegistrationRequest()
		requester.Metadata = newMetadata("https://requested.example.com/")

		responder := oauth2.NewClientRegistrationResponse()
		require.NoError(t, handler.HandleRFC7591ClientRegistrationEndpointRequest(ctx, requester, responder))

		values := responder.ToMap()
		id := values["client_id"].(string)

		assert.Equal(t, []any{"https://requested.example.com/"}, values["resource"])

		client, err := store.GetClient(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, oauth2.Arguments{"https://requested.example.com/"}, client.GetResource())

		token := values["registration_access_token"].(string)

		tokenRequester, err := store.GetClientRegistrationTokenSession(ctx, handler.Strategy.ClientRegistrationTokenSignature(ctx, token), &oauth2.DefaultSession{})
		require.NoError(t, err)
		assert.Equal(t, oauth2.Arguments{"https://requested.example.com/"}, tokenRequester.GetGrantedResource())
	})

	t.Run("ShouldMintTheSessionCeilingWhenAuthenticated", func(t *testing.T) {
		handler, _, store := newRegistrationHandler(t)

		requester := oauth2.NewClientRegistrationRequest()
		requester.Metadata = newMetadata("https://requested.example.com/")
		requester.Authenticated = grantableFixtureWithResource("", oauth2.Arguments{"https://ceiling.example.com/", "https://requested.example.com/"})

		responder := oauth2.NewClientRegistrationResponse()
		require.NoError(t, handler.HandleRFC7591ClientRegistrationEndpointRequest(ctx, requester, responder))

		token := responder.ToMap()["registration_access_token"].(string)

		tokenRequester, err := store.GetClientRegistrationTokenSession(ctx, handler.Strategy.ClientRegistrationTokenSignature(ctx, token), &oauth2.DefaultSession{})
		require.NoError(t, err)
		assert.Equal(t, oauth2.Arguments{"https://ceiling.example.com/", "https://requested.example.com/"}, tokenRequester.GetGrantedResource())
	})

	t.Run("ShouldRejectAResourceOutsideTheCeiling", func(t *testing.T) {
		handler, _, _ := newRegistrationHandler(t)

		requester := oauth2.NewClientRegistrationRequest()
		requester.Metadata = newMetadata("https://ceiling.example.com/", "https://outside.example.com/")
		requester.Authenticated = grantableFixtureWithResource("", oauth2.Arguments{"https://ceiling.example.com/"})

		err := handler.HandleRFC7591ClientRegistrationEndpointRequest(ctx, requester, oauth2.NewClientRegistrationResponse())

		assert.ErrorIs(t, err, oauth2.ErrInvalidClientMetadata)
	})
}

func TestClientConfigurationHandlerEnforcesResourceCeiling(t *testing.T) {
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
		Resource:      []string{"https://ceiling.example.com/", "https://outside.example.com/"},
	}
	requester.Authenticated = grantableFixtureWithResource(id, oauth2.Arguments{"https://ceiling.example.com/"})

	err := handler.HandleRFC7592ClientConfigurationEndpointRequest(ctx, requester, oauth2.NewClientRegistrationResponse())

	assert.ErrorIs(t, err, oauth2.ErrInvalidClientMetadata)
}
