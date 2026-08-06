// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDefaultRegisteredClientImplementsInterfaces(t *testing.T) {
	client := &DefaultRegisteredClient{
		DefaultClient:            &DefaultClient{ID: "abc", Scopes: []string{"openid"}},
		TokenEndpointAuthMethod:  "client_secret_basic",
		IDTokenSignedResponseAlg: "RS256",
		ResponseModes:            []ResponseModeType{ResponseModeQuery},
		ClientIDIssuedAt:         time.Unix(1, 0).UTC(),
	}

	assert.Equal(t, "abc", client.GetID())
	assert.Equal(t, "client_secret_basic", client.GetTokenEndpointAuthMethod())
	assert.Equal(t, "RS256", client.GetIDTokenSignedResponseAlg())
	assert.Equal(t, []ResponseModeType{ResponseModeQuery}, client.GetResponseModes())

	var (
		_ Client                           = client
		_ RotatedClientSecretsClient       = client
		_ JSONWebKeysClient                = client
		_ JARClient                        = client
		_ IDTokenClient                    = client
		_ UserInfoClient                   = client
		_ JARMClient                       = client
		_ AuthenticationMethodClient       = client
		_ ResponseModeClient               = client
		_ DPoPClient                       = client
		_ JWTProfileClient                 = client
		_ IntrospectionJWTResponseClient   = client
		_ ProofKeyCodeExchangeClient       = client
		_ PushedAuthorizationRequestClient = client
	)
}

func TestDefaultRegisteredClientDefaults(t *testing.T) {
	unset := &DefaultRegisteredClient{
		DefaultClient: &DefaultClient{ID: "abc"},
	}

	assert.Equal(t, "client_secret_basic", unset.GetTokenEndpointAuthMethod())
	assert.Equal(t, "RS256", unset.GetIDTokenSignedResponseAlg())

	set := &DefaultRegisteredClient{
		DefaultClient:            &DefaultClient{ID: "abc"},
		TokenEndpointAuthMethod:  "private_key_jwt",
		IDTokenSignedResponseAlg: "ES256",
	}

	assert.Equal(t, "private_key_jwt", set.GetTokenEndpointAuthMethod())
	assert.Equal(t, "ES256", set.GetIDTokenSignedResponseAlg())
}

// TestDefaultRegisteredClientEndpointAuthMethodInheritance pins that an unregistered introspection or revocation
// endpoint authentication method inherits the token endpoint's method rather than staying empty. An empty value
// would mean no method is registered, which those endpoints read as "accept any authenticated method"; inheriting
// keeps one registered method meaningful everywhere.
func TestDefaultRegisteredClientEndpointAuthMethodInheritance(t *testing.T) {
	testCases := []struct {
		name          string
		client        *DefaultRegisteredClient
		introspection string
		revocation    string
	}{
		{
			name:          "ShouldInheritTheTokenEndpointDefaultWhenNothingIsRegistered",
			client:        &DefaultRegisteredClient{DefaultClient: &DefaultClient{ID: "abc"}},
			introspection: "client_secret_basic",
			revocation:    "client_secret_basic",
		},
		{
			name: "ShouldInheritAnExplicitTokenEndpointMethod",
			client: &DefaultRegisteredClient{
				DefaultClient:           &DefaultClient{ID: "abc"},
				TokenEndpointAuthMethod: "private_key_jwt",
			},
			introspection: "private_key_jwt",
			revocation:    "private_key_jwt",
		},
		{
			name: "ShouldPreferItsOwnRegisteredMethodOverTheTokenEndpointMethod",
			client: &DefaultRegisteredClient{
				DefaultClient:                   &DefaultClient{ID: "abc"},
				TokenEndpointAuthMethod:         "private_key_jwt",
				IntrospectionEndpointAuthMethod: "client_secret_post",
				RevocationEndpointAuthMethod:    "client_secret_jwt",
			},
			introspection: "client_secret_post",
			revocation:    "client_secret_jwt",
		},
		{
			name: "ShouldInheritNoneForAPublicClient",
			client: &DefaultRegisteredClient{
				DefaultClient:           &DefaultClient{ID: "abc", Public: true},
				TokenEndpointAuthMethod: "none",
			},
			introspection: "none",
			revocation:    "none",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.introspection, tc.client.GetIntrospectionEndpointAuthMethod())
			assert.Equal(t, tc.revocation, tc.client.GetRevocationEndpointAuthMethod())
		})
	}
}

// TestDefaultRegisteredClientPublicClientEndpointAuthentication records the consequence of that inheritance for a
// public client. Before it inherited, such a client reported an empty revocation method, which is not the literal
// 'none' this endpoint requires, so it could never revoke its own tokens. Introspection stays closed to it either
// way, because that endpoint does not permit the 'none' method at all.
func TestDefaultRegisteredClientPublicClientEndpointAuthentication(t *testing.T) {
	client := &DefaultRegisteredClient{
		DefaultClient:           &DefaultClient{ID: "abc", Public: true},
		TokenEndpointAuthMethod: "none",
	}

	strategy := &DefaultClientAuthenticationStrategy{}

	method, err := strategy.doAuthenticateNone(t.Context(), client, &RevocationEndpointClientAuthStrategy{})
	assert.NoError(t, err)
	assert.Equal(t, "none", method)

	_, err = strategy.doAuthenticateNone(t.Context(), client, &IntrospectionEndpointClientAuthStrategy{})
	assert.ErrorIs(t, err, ErrInvalidClient)
}
