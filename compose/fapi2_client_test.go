// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestValidateFAPI2SecurityProfileClientSupport(t *testing.T) {
	testCases := []struct {
		name      string
		modify    func(config *oauth2.Config)
		factories []Factory
		expected  []string
	}{
		{
			name: "ShouldPass",
		},
		{
			name:     "ShouldRejectWithoutAnIssuer",
			modify:   func(config *oauth2.Config) { config.Issuer = "" },
			expected: []string{"Section 5.3.2.2: the 'iss' authorization response parameter must be returned, but Issuer is not set"},
		},
		{
			name:      "ShouldRejectWithoutTheAuthorizationCodeGrantHandler",
			factories: []Factory{OAuth2PKCEFactory, PushedAuthorizeHandlerFactory, DPoPAuthorizeFactory, DPoPTokenFactory},
			expected:  []string{"Section 5.3.2.2: the response type must be 'code', but the authorization code grant handler is not registered"},
		},
		{
			name: "ShouldNotCheckAStrategyReportingNoSigningAlgorithms",
			modify: func(config *oauth2.Config) {
				config.JWTStrategy = &jwt.DefaultStrategy{Config: config}
			},
		},
		{
			name:      "ShouldRejectWithoutThePKCEHandler",
			factories: []Factory{OAuth2AuthorizeExplicitFactory, PushedAuthorizeHandlerFactory, DPoPAuthorizeFactory, DPoPTokenFactory},
			expected:  []string{"Section 5.3.2.2: PKCE is required, but the PKCE handler is not registered"},
		},
		{
			name:      "ShouldRejectWithoutThePushedAuthorizationRequestHandler",
			factories: []Factory{OAuth2AuthorizeExplicitFactory, OAuth2PKCEFactory, DPoPAuthorizeFactory, DPoPTokenFactory},
			expected:  []string{"Section 5.3.2.2: authorization requests must be pushed, but the pushed authorization request handler is not registered"},
		},
		{
			name:     "ShouldRejectWithoutSenderConstraining",
			modify:   func(config *oauth2.Config) { config.DPoPEnabled = false },
			expected: []string{"Section 5.3.2.1: access tokens must be sender-constrained by DPoP or mTLS, but neither is enabled"},
		},
		{
			name: "ShouldRejectWithoutAPermittedClientAuthenticationMethod",
			modify: func(config *oauth2.Config) {
				config.TokenEndpointAuthMethods = []string{consts.ClientAuthMethodClientSecretBasic}
			},
			expected: []string{"Section 5.3.2.1: the token endpoint accepts the client authentication methods 'client_secret_basic', none of which is permitted"},
		},
		{
			name: "ShouldRejectWithoutAPermittedIssuerSigningKey",
			modify: func(config *oauth2.Config) {
				config.JWTStrategy = &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
					{Key: gen.MustRSAKey(), KeyID: "rs256", Algorithm: string(jose.RS256), Use: consts.JSONWebTokenUseSignature},
				}})}
			},
			expected: []string{"Section 5.4.1: the issuer signing algorithms 'RS256' include none permitted"},
		},
		{
			name: "ShouldPassWithAPermittedIssuerSigningKey",
			modify: func(config *oauth2.Config) {
				config.JWTStrategy = &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
					{Key: gen.MustRSAKey(), KeyID: "rs256", Algorithm: string(jose.RS256), Use: consts.JSONWebTokenUseSignature},
					{Key: gen.MustES256Key(), KeyID: "es256", Algorithm: string(jose.ES256), Use: consts.JSONWebTokenUseSignature},
				}})}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := newFAPI2Config()

			if tc.modify != nil {
				tc.modify(config)
			}

			factories := tc.factories
			if factories == nil {
				factories = []Factory{OAuth2AuthorizeExplicitFactory, OAuth2PKCEFactory, PushedAuthorizeHandlerFactory, DPoPAuthorizeFactory, DPoPTokenFactory}
			}

			Compose(config, storage.NewMemoryStore(), &CommonStrategy{CoreStrategy: NewOAuth2HMACStrategy(config)}, factories...)

			err := ValidateFAPI2SecurityProfileClientSupport(context.Background(), config)

			if len(tc.expected) == 0 {
				assert.NoError(t, err)

				return
			}

			require.Error(t, err)

			for _, expected := range tc.expected {
				assert.Contains(t, err.Error(), expected)
			}
		})
	}
}
