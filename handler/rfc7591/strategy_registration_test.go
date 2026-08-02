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

	// A nil secret must leave the existing secret in place, and values absent from the metadata must be removed
	// rather than preserved.
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

// TestDefaultClientRegistrationStrategyPatchClientPreservesServerPolicy proves that PatchClient's RFC 7592
// Section 2.2 full-replacement semantics apply only to client metadata. Fields with no ClientRegistrationMetadata
// source are locally administered server policy or registration bookkeeping, not metadata the client can reset via
// PUT, and must survive a patch that does not mention them. Metadata fields genuinely absent from the update must
// still be cleared, so both halves are asserted here.
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

	// Simulate locally administered server policy set out-of-band by the deployment, not by the registering client.
	registered.EnforcePKCE = true
	registered.EnforcePKCEChallengeMethod = true
	registered.PKCEChallengeMethod = "S256"
	registered.EnableJWTProfileOAuthAccessTokens = true
	registered.PushedAuthorizeContextLifespan = 5 * 60 * 1e9 // 5m in time.Duration nanoseconds
	registered.ClientSecretExpiresAt = registered.ClientIDIssuedAt.Add(24 * 60 * 60 * 1e9)

	// Simulate rotated secret bookkeeping accumulated out-of-band, e.g. by a secret rotation operation. It has no
	// ClientRegistrationMetadata source and must survive a patch the same way the fields above do.
	rotatedSecret := oauth2.NewPlainTextClientSecret("rotated-out")
	registered.RotatedClientSecrets = []oauth2.ClientSecret{rotatedSecret}

	// A patch whose metadata does not mention any of the above, and which drops ClientName.
	patched, err := strategy.PatchClient(ctx, registered, nil, &oauth2.ClientRegistrationMetadata{
		RedirectURIs: []string{"https://example.com/other"},
	})
	require.NoError(t, err)

	result, ok := patched.(*oauth2.DefaultRegisteredClient)
	require.True(t, ok)

	// Server policy and registration bookkeeping survive the replacement untouched.
	assert.True(t, result.EnforcePKCE)
	assert.True(t, result.EnforcePKCEChallengeMethod)
	assert.Equal(t, "S256", result.PKCEChallengeMethod)
	assert.True(t, result.EnableJWTProfileOAuthAccessTokens)
	assert.Equal(t, 5*60*int64(1e9), int64(result.PushedAuthorizeContextLifespan))
	assert.Equal(t, registered.ClientSecretExpiresAt, result.ClientSecretExpiresAt)
	assert.Equal(t, []oauth2.ClientSecret{rotatedSecret}, result.RotatedClientSecrets)

	// Metadata fields absent from the update are cleared, not merged.
	assert.Empty(t, result.ClientName)
	assert.Equal(t, []string{"https://example.com/other"}, result.GetRedirectURIs())
}

// TestDefaultClientRegistrationStrategyNewClientDerivesPublic proves that Public is derived from
// TokenEndpointAuthMethod rather than left at its zero value. A client registering with
// 'token_endpoint_auth_method: none' must be recognized as public, since GetTokenEndpointAuthMethod()'s "none"
// contract (see client_authentication_strategy.go) requires IsPublic() to also be true, or the client becomes
// permanently unable to authenticate at the token endpoint despite intentionally being issued no secret. Any other
// method, including the field being left unset, is confidential.
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

// TestDefaultClientRegistrationStrategyPatchClientDerivesPublic proves that PatchClient recomputes Public from the
// patched TokenEndpointAuthMethod on every call rather than preserving whatever value the client previously had, in
// both directions: a client switching to 'none' becomes public, and a public client switching away from 'none'
// becomes confidential again.
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

func TestDefaultClientRegistrationStrategyRejectsForeignClient(t *testing.T) {
	ctx := context.Background()
	strategy := NewDefaultClientRegistrationStrategy()

	_, err := strategy.PatchClient(ctx, &oauth2.DefaultClient{ID: "abc"}, nil, &oauth2.ClientRegistrationMetadata{})
	require.Error(t, err)

	_, err = strategy.MetadataFromClient(ctx, &oauth2.DefaultClient{ID: "abc"})
	require.Error(t, err)
}
