// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
)

func TestLocalValidator(t *testing.T) {
	config := &oauth2.Config{
		ScopeStrategy:    oauth2.ExactScopeStrategy,
		AudienceStrategy: oauth2.DefaultAudienceStrategy,
	}

	validator := NewLocalValidator(config)

	testCases := []struct {
		name     string
		metadata *oauth2.ClientRegistrationMetadata
		err      string
	}{
		{
			name: "ShouldAcceptMinimalWebClient",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs:  []string{"https://example.com/cb"},
				GrantTypes:    []string{"authorization_code"},
				ResponseTypes: []string{"code"},
			},
		},
		{
			name: "ShouldRejectRedirectURIWithFragment",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs: []string{"https://example.com/cb#frag"},
			},
			err: "invalid_redirect_uri",
		},
		{
			name: "ShouldRejectRelativeRedirectURI",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs: []string{"/cb"},
			},
			err: "invalid_redirect_uri",
		},
		{
			name: "ShouldRejectInsecureRedirectURIForWebApplicationType",
			metadata: &oauth2.ClientRegistrationMetadata{
				ApplicationType: "web",
				RedirectURIs:    []string{"http://example.com/cb"},
			},
			err: "invalid_redirect_uri",
		},
		{
			name: "ShouldAcceptLoopbackRedirectURIForNativeApplicationType",
			metadata: &oauth2.ClientRegistrationMetadata{
				ApplicationType: "native",
				RedirectURIs:    []string{"http://127.0.0.1:8080/cb"},
				GrantTypes:      []string{"authorization_code"},
				ResponseTypes:   []string{"code"},
			},
		},
		{
			name: "ShouldRejectBothJWKSAndJWKSURI",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs:   []string{"https://example.com/cb"},
				JSONWebKeysURI: "https://example.com/jwks",
				JSONWebKeys:    &jose.JSONWebKeySet{},
			},
			err: "invalid_client_metadata",
		},
		{
			name: "ShouldRejectCodeResponseTypeWithoutAuthorizationCodeGrant",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs:  []string{"https://example.com/cb"},
				GrantTypes:    []string{"client_credentials"},
				ResponseTypes: []string{"code"},
			},
			err: "invalid_client_metadata",
		},
		{
			name: "ShouldRejectUnknownApplicationType",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs:    []string{"https://example.com/cb"},
				ApplicationType: "desktop",
			},
			err: "invalid_client_metadata",
		},
		{
			name: "ShouldRejectUnknownSubjectType",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs: []string{"https://example.com/cb"},
				SubjectType:  "sectoral",
			},
			err: "invalid_client_metadata",
		},
		{
			name: "ShouldRejectNoneIDTokenSignedResponseAlg",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs:             []string{"https://example.com/cb"},
				IDTokenSignedResponseAlg: "none",
			},
			err: "invalid_client_metadata",
		},
		{
			name: "ShouldRejectImplicitResponseTypeWithoutImplicitGrant",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs:  []string{"https://example.com/cb"},
				GrantTypes:    []string{"authorization_code"},
				ResponseTypes: []string{"token"},
			},
			err: "invalid_client_metadata",
		},
		{
			name: "ShouldRejectAuthorizationCodeGrantWithoutRedirectURI",
			metadata: &oauth2.ClientRegistrationMetadata{
				GrantTypes:    []string{"authorization_code"},
				ResponseTypes: []string{"code"},
			},
			err: "invalid_client_metadata",
		},
		{
			name: "ShouldRejectWhitespaceInAlgorithmValue",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs:                []string{"https://example.com/cb"},
				IDTokenEncryptedResponseAlg: "RSA OAEP",
			},
			err: "invalid_client_metadata",
		},
		{
			name: "ShouldAcceptValidScope",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs: []string{"https://example.com/cb"},
				Scope:        "profile openid read:things",
			},
		},
		{
			name: "ShouldRejectScopeWithIllegalCharacter",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs: []string{"https://example.com/cb"},
				Scope:        "profile \"quoted\"",
			},
			err: "invalid_client_metadata",
		},
		{
			name: "ShouldAcceptTLSClientAuthWithExactlyOneSubject",
			metadata: &oauth2.ClientRegistrationMetadata{
				TokenEndpointAuthMethod: "tls_client_auth",
				TLSClientAuthSubjectDN:  "CN=client,O=Example",
			},
		},
		{
			name: "ShouldAcceptTLSClientAuthOnANonTokenEndpoint",
			metadata: &oauth2.ClientRegistrationMetadata{
				IntrospectionEndpointAuthMethod: "tls_client_auth",
				TLSClientAuthSANDNS:             "client.example.com",
			},
		},
		{
			name: "ShouldRejectTLSClientAuthWithNoSubject",
			metadata: &oauth2.ClientRegistrationMetadata{
				TokenEndpointAuthMethod: "tls_client_auth",
			},
			err: "invalid_client_metadata",
		},
		{
			name: "ShouldRejectTLSClientAuthWithMultipleSubjects",
			metadata: &oauth2.ClientRegistrationMetadata{
				TokenEndpointAuthMethod: "tls_client_auth",
				TLSClientAuthSubjectDN:  "CN=client,O=Example",
				TLSClientAuthSANEmail:   "client@example.com",
			},
			err: "invalid_client_metadata",
		},
		{
			name: "ShouldRejectSubjectWithoutTLSClientAuth",
			metadata: &oauth2.ClientRegistrationMetadata{
				TokenEndpointAuthMethod: "client_secret_basic",
				TLSClientAuthSANDNS:     "client.example.com",
			},
			err: "invalid_client_metadata",
		},
		{
			name: "ShouldRejectTLSClientAuthWithMalformedSANIP",
			metadata: &oauth2.ClientRegistrationMetadata{
				TokenEndpointAuthMethod: "tls_client_auth",
				TLSClientAuthSANIP:      "not-an-ip",
			},
			err: "invalid_client_metadata",
		},
		{
			name: "ShouldAcceptSelfSignedTLSClientAuthWithJSONWebKeysURI",
			metadata: &oauth2.ClientRegistrationMetadata{
				TokenEndpointAuthMethod: "self_signed_tls_client_auth",
				JSONWebKeysURI:          "https://example.com/jwks.json",
			},
		},
		{
			name: "ShouldRejectSelfSignedTLSClientAuthWithoutJSONWebKeys",
			metadata: &oauth2.ClientRegistrationMetadata{
				TokenEndpointAuthMethod: "self_signed_tls_client_auth",
			},
			err: "invalid_client_metadata",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validator.ValidateClientRegistrationMetadata(context.Background(), nil, tc.metadata)

			if tc.err == "" {
				require.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.Equal(t, tc.err, oauth2.ErrorToRFC6749Error(err).ErrorField)
		})
	}
}
