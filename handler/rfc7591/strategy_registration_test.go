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

func TestDefaultClientRegistrationStrategyNewClient(t *testing.T) {
	ctx := context.Background()
	strategy := NewDefaultClientRegistrationStrategy()

	secret := oauth2.NewPlainTextClientSecret("the-secret")

	metadata := &oauth2.ClientRegistrationMetadata{
		RedirectURIs:             []string{"https://example.com/cb"},
		GrantTypes:               []string{"authorization_code"},
		ResponseTypes:            []string{"code"},
		Scope:                    "openid profile",
		ClientName:               "Example",
		TokenEndpointAuthMethod:  "client_secret_basic",
		IDTokenSignedResponseAlg: "RS256",
	}

	client, err := strategy.NewClient(ctx, "abc", secret, metadata)
	require.NoError(t, err)

	registered, ok := client.(*oauth2.DefaultRegisteredClient)
	require.True(t, ok)

	assert.Equal(t, "abc", registered.GetID())
	assert.Equal(t, []string{"https://example.com/cb"}, registered.GetRedirectURIs())
	assert.Equal(t, oauth2.Arguments{"openid", "profile"}, registered.GetScopes())
	assert.Equal(t, "Example", registered.ClientName)
	assert.Equal(t, secret, registered.GetClientSecret())
	assert.False(t, registered.ClientIDIssuedAt.IsZero())
}

func TestDefaultClientRegistrationStrategyPatchClientReplaces(t *testing.T) {
	ctx := context.Background()
	strategy := NewDefaultClientRegistrationStrategy()

	secret := oauth2.NewPlainTextClientSecret("the-secret")

	client, err := strategy.NewClient(ctx, "abc", secret, &oauth2.ClientRegistrationMetadata{
		RedirectURIs: []string{"https://example.com/cb"},
		Scope:        "openid profile",
		ClientName:   "Example",
		Contacts:     []string{"ops@example.com"},
	})
	require.NoError(t, err)

	patched, err := strategy.PatchClient(ctx, client, nil, &oauth2.ClientRegistrationMetadata{
		RedirectURIs: []string{"https://example.com/other"},
		Scope:        "openid",
	})
	require.NoError(t, err)

	registered, ok := patched.(*oauth2.DefaultRegisteredClient)
	require.True(t, ok)

	assert.Equal(t, "abc", registered.GetID())
	assert.Equal(t, []string{"https://example.com/other"}, registered.GetRedirectURIs())
	assert.Equal(t, oauth2.Arguments{"openid"}, registered.GetScopes())
	assert.Empty(t, registered.ClientName)
	assert.Empty(t, registered.Contacts)
	assert.Equal(t, secret, registered.GetClientSecret())
	assert.False(t, registered.ClientIDIssuedAt.IsZero())
}

func TestDefaultClientRegistrationStrategyPatchClientPreservesServerPolicy(t *testing.T) {
	ctx := context.Background()
	strategy := NewDefaultClientRegistrationStrategy()

	client, err := strategy.NewClient(ctx, "abc", oauth2.NewPlainTextClientSecret("the-secret"), &oauth2.ClientRegistrationMetadata{
		RedirectURIs: []string{"https://example.com/cb"},
		ClientName:   "Example",
	})
	require.NoError(t, err)

	registered, ok := client.(*oauth2.DefaultRegisteredClient)
	require.True(t, ok)

	registered.EnforcePKCE = true
	registered.EnforcePKCEChallengeMethod = true
	registered.PKCEChallengeMethod = "S256"
	registered.EnableJWTProfileOAuthAccessTokens = true
	registered.PushedAuthorizeContextLifespan = 5 * 60 * 1e9 // 5m in time.Duration nanoseconds
	registered.ClientSecretExpiresAt = registered.ClientIDIssuedAt.Add(24 * 60 * 60 * 1e9)
	rotatedSecret := oauth2.NewPlainTextClientSecret("rotated-out")
	registered.RotatedClientSecrets = []oauth2.ClientSecret{rotatedSecret}

	expiresAt := registered.ClientSecretExpiresAt

	patched, err := strategy.PatchClient(ctx, registered, nil, &oauth2.ClientRegistrationMetadata{
		RedirectURIs: []string{"https://example.com/other"},
	})

	require.NoError(t, err)

	result, ok := patched.(*oauth2.DefaultRegisteredClient)
	require.True(t, ok)
	assert.True(t, result.EnforcePKCE)
	assert.True(t, result.EnforcePKCEChallengeMethod)
	assert.Equal(t, "S256", result.PKCEChallengeMethod)
	assert.True(t, result.EnableJWTProfileOAuthAccessTokens)
	assert.Equal(t, 5*60*int64(1e9), int64(result.PushedAuthorizeContextLifespan))
	assert.Equal(t, expiresAt, result.ClientSecretExpiresAt)
	assert.Equal(t, []oauth2.ClientSecret{rotatedSecret}, result.RotatedClientSecrets)
	assert.Empty(t, result.ClientName)
	assert.Equal(t, []string{"https://example.com/other"}, result.GetRedirectURIs())
}

func TestDefaultClientRegistrationStrategyNewClientDerivesPublic(t *testing.T) {
	ctx := context.Background()
	strategy := NewDefaultClientRegistrationStrategy()

	publicClient, err := strategy.NewClient(ctx, "public", nil, &oauth2.ClientRegistrationMetadata{
		TokenEndpointAuthMethod: "none",
	})

	require.NoError(t, err)
	assert.True(t, publicClient.IsPublic())

	confidentialClient, err := strategy.NewClient(ctx, "confidential", oauth2.NewPlainTextClientSecret("s"), &oauth2.ClientRegistrationMetadata{
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	require.NoError(t, err)
	assert.False(t, confidentialClient.IsPublic())

	unsetClient, err := strategy.NewClient(ctx, "unset", oauth2.NewPlainTextClientSecret("s"), &oauth2.ClientRegistrationMetadata{})
	require.NoError(t, err)
	assert.False(t, unsetClient.IsPublic())
}

func TestDefaultClientRegistrationStrategyPatchClientDoesNotMutateInput(t *testing.T) {
	ctx := context.Background()
	strategy := NewDefaultClientRegistrationStrategy()

	client, err := strategy.NewClient(ctx, "abc", oauth2.NewPlainTextClientSecret("the-secret"), &oauth2.ClientRegistrationMetadata{
		RedirectURIs: []string{"https://example.com/cb"},
		Scope:        "openid profile",
		ClientName:   "Example",
	})
	require.NoError(t, err)

	patched, err := strategy.PatchClient(ctx, client, nil, &oauth2.ClientRegistrationMetadata{
		RedirectURIs: []string{"https://example.com/other"},
	})
	require.NoError(t, err)

	assert.NotSame(t, client, patched)

	original, ok := client.(*oauth2.DefaultRegisteredClient)
	require.True(t, ok)

	assert.Equal(t, []string{"https://example.com/cb"}, original.GetRedirectURIs())
	assert.Equal(t, oauth2.Arguments{"openid", "profile"}, original.GetScopes())
	assert.Equal(t, "Example", original.ClientName)

	assert.Equal(t, []string{"https://example.com/other"}, patched.GetRedirectURIs())
}

func TestDefaultClientRegistrationStrategyPatchClientDerivesPublic(t *testing.T) {
	ctx := context.Background()
	strategy := NewDefaultClientRegistrationStrategy()

	client, err := strategy.NewClient(ctx, "abc", oauth2.NewPlainTextClientSecret("s"), &oauth2.ClientRegistrationMetadata{
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	require.NoError(t, err)
	require.False(t, client.IsPublic())

	patched, err := strategy.PatchClient(ctx, client, nil, &oauth2.ClientRegistrationMetadata{
		TokenEndpointAuthMethod: "none",
	})

	require.NoError(t, err)
	assert.True(t, patched.IsPublic())

	repatched, err := strategy.PatchClient(ctx, patched, nil, &oauth2.ClientRegistrationMetadata{
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	require.NoError(t, err)
	assert.False(t, repatched.IsPublic())
}

func TestDefaultClientRegistrationStrategyMetadataFromClient(t *testing.T) {
	ctx := context.Background()
	strategy := NewDefaultClientRegistrationStrategy()

	in := &oauth2.ClientRegistrationMetadata{
		RedirectURIs:  []string{"https://example.com/cb"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scope:         "openid profile",
		ClientName:    "Example",
		Extra:         map[string]any{"vendor": "x"},
	}

	client, err := strategy.NewClient(ctx, "abc", nil, in)
	require.NoError(t, err)

	out, err := strategy.MetadataFromClient(ctx, client)
	require.NoError(t, err)

	assert.Equal(t, in.RedirectURIs, out.RedirectURIs)
	assert.Equal(t, in.Scope, out.Scope)
	assert.Equal(t, in.ClientName, out.ClientName)
	assert.Equal(t, in.Extra, out.Extra)
}

func TestDefaultClientRegistrationStrategyRoundTripsRFC8705AndLogoutMetadata(t *testing.T) {
	ctx := context.Background()
	strategy := NewDefaultClientRegistrationStrategy()

	in := &oauth2.ClientRegistrationMetadata{
		RedirectURIs:            []string{"https://example.com/cb"},
		TokenEndpointAuthMethod: "tls_client_auth",

		RequireSignedRequestObject: true,

		PostLogoutRedirectURIs:           []string{"https://example.com/logout"},
		BackChannelLogoutURI:             "https://example.com/backchannel",
		BackChannelLogoutSessionRequired: true,

		TLSClientAuthSubjectDN:                "CN=client,O=Example",
		TLSClientCertificateBoundAccessTokens: true,
	}

	client, err := strategy.NewClient(ctx, "abc", nil, in)
	require.NoError(t, err)

	registered, ok := client.(*oauth2.DefaultRegisteredClient)
	require.True(t, ok)

	assert.True(t, registered.GetRequireSignedRequestObject())
	assert.Equal(t, []string{"https://example.com/logout"}, registered.GetPostLogoutRedirectURIs())
	assert.Equal(t, "https://example.com/backchannel", registered.GetBackChannelLogoutURI())
	assert.True(t, registered.GetBackChannelLogoutSessionRequired())
	assert.Equal(t, "CN=client,O=Example", registered.GetTLSClientAuthSubjectDN())
	assert.True(t, registered.GetEnableTLSClientAuthBoundAccessTokens())

	out, err := strategy.MetadataFromClient(ctx, client)
	require.NoError(t, err)

	assert.Equal(t, in.RequireSignedRequestObject, out.RequireSignedRequestObject)
	assert.Equal(t, in.PostLogoutRedirectURIs, out.PostLogoutRedirectURIs)
	assert.Equal(t, in.BackChannelLogoutURI, out.BackChannelLogoutURI)
	assert.Equal(t, in.BackChannelLogoutSessionRequired, out.BackChannelLogoutSessionRequired)
	assert.Equal(t, in.TLSClientAuthSubjectDN, out.TLSClientAuthSubjectDN)
	assert.Equal(t, in.TLSClientCertificateBoundAccessTokens, out.TLSClientCertificateBoundAccessTokens)

	patched, err := strategy.PatchClient(ctx, client, nil, &oauth2.ClientRegistrationMetadata{})
	require.NoError(t, err)

	registered, ok = patched.(*oauth2.DefaultRegisteredClient)
	require.True(t, ok)

	assert.False(t, registered.GetRequireSignedRequestObject())
	assert.Empty(t, registered.GetPostLogoutRedirectURIs())
	assert.Empty(t, registered.GetBackChannelLogoutURI())
	assert.False(t, registered.GetBackChannelLogoutSessionRequired())
	assert.Empty(t, registered.GetTLSClientAuthSubjectDN())
	assert.False(t, registered.GetEnableTLSClientAuthBoundAccessTokens())
}

func TestDefaultClientRegistrationStrategyRejectsForeignClient(t *testing.T) {
	ctx := context.Background()
	strategy := NewDefaultClientRegistrationStrategy()

	_, err := strategy.PatchClient(ctx, &oauth2.DefaultClient{ID: "abc"}, nil, &oauth2.ClientRegistrationMetadata{})
	require.Error(t, err)

	_, err = strategy.MetadataFromClient(ctx, &oauth2.DefaultClient{ID: "abc"})
	require.Error(t, err)
}

func TestDefaultClientRegistrationStrategyPreservesDefaultMaxAgePresence(t *testing.T) {
	ctx := context.Background()
	strategy := NewDefaultClientRegistrationStrategy()

	zero := int64(0)

	testCases := []struct {
		name     string
		value    *int64
		expected *int64
	}{
		{name: "ShouldPreserveAnAbsentValue", value: nil, expected: nil},
		{name: "ShouldPreserveAnExplicitZero", value: &zero, expected: &zero},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client, err := strategy.NewClient(ctx, "abc", nil, &oauth2.ClientRegistrationMetadata{
				RedirectURIs:  []string{"https://example.com/cb"},
				DefaultMaxAge: tc.value,
			})
			require.NoError(t, err)

			metadata, err := strategy.MetadataFromClient(ctx, client)
			require.NoError(t, err)

			require.Equal(t, tc.expected, metadata.DefaultMaxAge)

			if metadata.DefaultMaxAge != nil {
				registered, ok := client.(*oauth2.DefaultRegisteredClient)
				require.True(t, ok)
				assert.NotSame(t, registered.DefaultMaxAge, metadata.DefaultMaxAge)
			}
		})
	}
}
