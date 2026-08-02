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
