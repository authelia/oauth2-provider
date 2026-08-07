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
)

func TestCheckGrantableScopes(t *testing.T) {
	ctx := context.Background()
	config := &oauth2.Config{ScopeStrategy: oauth2.ExactScopeStrategy}

	testCases := []struct {
		name          string
		authenticated oauth2.Requester
		scope         string
		err           string
	}{
		{
			"ShouldAllowExactMatch",
			grantableFixture("", oauth2.Arguments{"openid", "profile"}),
			"openid profile",
			"",
		},
		{
			"ShouldAllowStrictSubset",
			grantableFixture("", oauth2.Arguments{"openid", "profile"}),
			"openid",
			"",
		},
		{
			"ShouldAllowOmittedScope",
			grantableFixture("", oauth2.Arguments{"openid"}),
			"",
			"",
		},
		{
			"ShouldRejectExcess",
			grantableFixture("", oauth2.Arguments{"openid"}),
			"openid profile",
			"The request requested the scopes 'profile' which the presented Client Registration Token is not permitted to grant.",
		},
		{
			"ShouldRejectAllWhenCeilingEmpty",
			grantableFixture("", nil),
			"openid",
			"The request requested the scopes 'openid' which the presented Client Registration Token is not permitted to grant.",
		},
		{
			"ShouldSkipWhenUnauthenticated",
			nil,
			"openid profile",
			"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metadata := &oauth2.ClientRegistrationMetadata{Scope: tc.scope}

			err := CheckGrantableScopes(ctx, config, tc.authenticated, metadata)

			if tc.err == "" {
				require.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The value of one of the client metadata fields is invalid and the server has rejected this request. "+tc.err)
		})
	}
}

func TestCheckGrantableAudience(t *testing.T) {
	config := &oauth2.Config{AudienceStrategy: oauth2.DefaultAudienceStrategy}

	newAuthenticated := func(grantable oauth2.Arguments) oauth2.Requester {
		request := oauth2.NewRequest()
		request.Session = &oauth2.DefaultSession{}

		for _, audience := range grantable {
			request.GrantAudience(audience)
		}

		return request
	}

	testCases := []struct {
		name          string
		authenticated oauth2.Requester
		metadata      *oauth2.ClientRegistrationMetadata
		err           string
	}{
		{
			name:     "ShouldSkipWithoutAnAuthenticatedRequester",
			metadata: &oauth2.ClientRegistrationMetadata{Audience: []string{"https://api.example.com"}},
		},
		{
			name:          "ShouldAcceptAnAudienceInsideTheCeiling",
			authenticated: newAuthenticated(oauth2.Arguments{"https://api.example.com"}),
			metadata:      &oauth2.ClientRegistrationMetadata{Audience: []string{"https://api.example.com"}},
		},
		{
			name:          "ShouldRejectAnAudienceOutsideTheCeiling",
			authenticated: newAuthenticated(oauth2.Arguments{"https://api.example.com"}),
			metadata:      &oauth2.ClientRegistrationMetadata{Audience: []string{"https://other.example.com"}},
			err:           "invalid_client_metadata",
		},
		{
			name:          "ShouldRejectEveryAudienceWhenTheCeilingIsEmpty",
			authenticated: newAuthenticated(nil),
			metadata:      &oauth2.ClientRegistrationMetadata{Audience: []string{"https://api.example.com"}},
			err:           "invalid_client_metadata",
		},
		{
			name:          "ShouldAcceptWhenNoAudienceIsRequested",
			authenticated: newAuthenticated(nil),
			metadata:      &oauth2.ClientRegistrationMetadata{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckGrantableAudience(context.Background(), config, tc.authenticated, tc.metadata)

			if tc.err == "" {
				assert.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.Equal(t, tc.err, oauth2.ErrorToRFC6749Error(err).ErrorField)
		})
	}
}

func TestCheckGrantableScopesFromTheTokenGrant(t *testing.T) {
	config := &oauth2.Config{ScopeStrategy: oauth2.ExactScopeStrategy}

	newAuthenticated := func(granted ...string) oauth2.Requester {
		request := oauth2.NewRequest()
		request.Session = &oauth2.DefaultSession{}

		for _, scope := range granted {
			request.GrantScope(scope)
		}

		return request
	}

	testCases := []struct {
		name          string
		authenticated oauth2.Requester
		requested     string
		err           string
	}{
		{
			name:          "ShouldAcceptAScopeInsideTheGrant",
			authenticated: newAuthenticated("authelia:oauth2:client_registration", "openid", "profile"),
			requested:     "openid profile",
		},
		{
			name:          "ShouldRejectAScopeOutsideTheGrant",
			authenticated: newAuthenticated("authelia:oauth2:client_registration", "openid"),
			requested:     "openid profile",
			err:           "invalid_client_metadata",
		},
		{
			name:          "ShouldRejectTheRegistrationScopeEvenThoughTheTokenHoldsIt",
			authenticated: newAuthenticated("authelia:oauth2:client_registration", "openid"),
			requested:     "authelia:oauth2:client_registration",
			err:           "invalid_client_metadata",
		},
		{
			name:          "ShouldRejectEveryScopeWhenTheGrantIsEmpty",
			authenticated: newAuthenticated(),
			requested:     "openid",
			err:           "invalid_client_metadata",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckGrantableScopes(context.Background(), config, tc.authenticated, &oauth2.ClientRegistrationMetadata{Scope: tc.requested})

			if tc.err == "" {
				assert.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.Equal(t, tc.err, oauth2.ErrorToRFC6749Error(err).ErrorField)
		})
	}
}

func TestCheckGrantableScopesRejectsEveryRegistrationScope(t *testing.T) {
	ctx := context.Background()
	config := &oauth2.Config{
		ScopeStrategy:                   oauth2.ExactScopeStrategy,
		RFC7591ClientRegistrationScopes: []string{"authelia:oauth2:client_registration", "urn:example:register"},
	}

	authenticated := oauth2.NewRequest()
	authenticated.GrantScope("authelia:oauth2:client_registration")
	authenticated.GrantScope("urn:example:register")
	authenticated.GrantScope("read")

	testCases := []struct {
		name  string
		scope string
	}{
		{"ShouldRejectPrimaryRegistrationScope", "authelia:oauth2:client_registration"},
		{"ShouldRejectSecondaryRegistrationScope", "urn:example:register"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckGrantableScopes(ctx, config, authenticated, &oauth2.ClientRegistrationMetadata{Scope: tc.scope})

			require.Error(t, err)
			assert.Contains(t, oauth2.ErrorToRFC6749Error(err).HintField, tc.scope)
		})
	}

	t.Run("ShouldPermitANonRegistrationScope", func(t *testing.T) {
		assert.NoError(t, CheckGrantableScopes(ctx, config, authenticated, &oauth2.ClientRegistrationMetadata{Scope: "read"}))
	})
}

func TestExcludeRegistrationScopeStripsEveryConfiguredScope(t *testing.T) {
	ctx := context.Background()
	config := &oauth2.Config{
		RFC7591ClientRegistrationScopes: []string{"authelia:oauth2:client_registration", "urn:example:register"},
	}

	filtered := ExcludeRegistrationScope(ctx, config, oauth2.Arguments{
		"authelia:oauth2:client_registration", "read", "urn:example:register", "write",
	})

	assert.Equal(t, oauth2.Arguments{"read", "write"}, filtered)
}

func TestExcludeRegistrationScopeFromMetadataStripsEveryConfiguredScope(t *testing.T) {
	ctx := context.Background()
	config := &oauth2.Config{
		RFC7591ClientRegistrationScopes: []string{"authelia:oauth2:client_registration", "urn:example:register"},
	}

	metadata := &oauth2.ClientRegistrationMetadata{Scope: "authelia:oauth2:client_registration read urn:example:register write"}

	ExcludeRegistrationScopeFromMetadata(ctx, config, metadata)

	assert.Equal(t, "read write", metadata.Scope)
}

func grantableFixture(clientID string, scopes oauth2.Arguments) oauth2.Requester {
	return grantableFixtureWithAudience(clientID, scopes, nil)
}

func grantableFixtureWithAudience(clientID string, scopes, audience oauth2.Arguments) oauth2.Requester {
	requester := oauth2.NewRequest()
	requester.Session = &oauth2.DefaultSession{}

	if clientID != "" {
		requester.Client = &oauth2.DefaultClient{ID: clientID}
	}

	for _, scope := range scopes {
		requester.GrantScope(scope)
	}

	for _, aud := range audience {
		requester.GrantAudience(aud)
	}

	return requester
}

func grantableFixtureWithClient(client oauth2.Client, scopes, audience oauth2.Arguments) oauth2.Requester {
	requester := oauth2.NewRequest()
	requester.Session = &oauth2.DefaultSession{}
	requester.Client = client

	for _, scope := range scopes {
		requester.GrantScope(scope)
	}

	for _, aud := range audience {
		requester.GrantAudience(aud)
	}

	return requester
}
