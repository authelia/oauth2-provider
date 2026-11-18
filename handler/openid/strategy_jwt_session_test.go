// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestDefaultSessionGrantManagementJSON(t *testing.T) {
	var session *DefaultSession

	assert.Empty(t, session.GetGrantID())
	assert.Empty(t, session.GetGrantManagementAction())
	assert.Nil(t, session.GetGrantPermissions())

	data, err := json.Marshal(NewDefaultSession())
	require.NoError(t, err)
	assert.NotContains(t, string(data), "grant_id")
	assert.NotContains(t, string(data), "grant_management_action")
	assert.NotContains(t, string(data), "grant_permissions")

	permissions := &oauth2.GrantPermissions{
		Scopes:               []oauth2.GrantScope{{Scope: "read", Resource: []string{"https://rs1"}}},
		Audience:             []string{"https://rs1"},
		Claims:               []string{"email"},
		AuthorizationDetails: oauth2.AuthorizationDetails{{Type: "account_information", Actions: []string{"read"}}},
	}

	have := NewDefaultSession()
	have.SetGrantID("grant-1")
	have.SetGrantManagementAction(oauth2.GrantManagementActionMerge)
	have.SetGrantPermissions(permissions)

	data, err = json.Marshal(have)
	require.NoError(t, err)

	session = NewDefaultSession()
	require.NoError(t, json.Unmarshal(data, session))

	assert.Equal(t, "grant-1", session.GetGrantID())
	assert.Equal(t, oauth2.GrantManagementActionMerge, session.GetGrantManagementAction())
	assert.Equal(t, permissions, session.GetGrantPermissions())
}

func TestDefaultSessionMTLSBinding(t *testing.T) {
	var session *DefaultSession

	assert.Empty(t, session.GetClientCertificateSHA256Thumbprint())

	session = NewDefaultSession()

	session.SetClientCertificateSHA256Thumbprint("test-x5t")

	assert.Equal(t, "test-x5t", session.GetClientCertificateSHA256Thumbprint())
}

func TestDefaultSession_DPoPPublicKeyJWK(t *testing.T) {
	var session *DefaultSession

	assert.Nil(t, session.GetDPoPPublicKeyJWK())

	session = NewDefaultSession()

	session.SetDPoPPublicKeyJWK([]byte(`{"kty":"EC"}`))

	assert.Equal(t, []byte(`{"kty":"EC"}`), session.GetDPoPPublicKeyJWK())

	var _ oauth2.DPoPBoundSession = session
}

func TestDefaultSession_RequestedDPoPJWKThumbprint(t *testing.T) {
	var session *DefaultSession

	assert.Empty(t, session.GetRequestedDPoPJWKThumbprint())

	session = NewDefaultSession()

	session.SetRequestedDPoPJWKThumbprint("requested-jkt")
	session.SetDPoPJWKThumbprint("bound-jkt")

	assert.Equal(t, "requested-jkt", session.GetRequestedDPoPJWKThumbprint())
	assert.Equal(t, "bound-jkt", session.GetDPoPJWKThumbprint())

	var _ oauth2.DPoPBoundSession = session
}

func TestDefaultSessionConfirmationRoundTrip(t *testing.T) {
	var source oauth2.MTLSBoundSession = NewDefaultSession()

	source.SetClientCertificateSHA256Thumbprint("round-trip-value")

	claims := map[string]any{}

	oauth2.ApplyConfirmation(context.Background(), &oauth2.Config{DPoPEnabled: true, MTLSEnabled: true}, claims, source.(oauth2.Session))

	cnf, ok := claims[jwt.ClaimConfirmation].(map[string]any)
	require.Truef(t, ok, "cnf is absent or not a map, got %#v", claims[jwt.ClaimConfirmation])
	assert.Equal(t, "round-trip-value", cnf[jwt.ClaimConfirmationX509SHA256Thumbprint])

	restored := NewDefaultSession()

	oauth2.RestoreConfirmation(claims, restored)

	assert.Equal(t, "round-trip-value", restored.GetClientCertificateSHA256Thumbprint())
}
