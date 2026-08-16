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
			name: "ShouldRejectLocalhostRedirectURIForWebApplicationType",
			metadata: &oauth2.ClientRegistrationMetadata{
				ApplicationType: "web",
				RedirectURIs:    []string{"https://localhost:8080/cb"},
			},
			err: "invalid_redirect_uri",
		},
		{
			// The 'localhost' name and the loopback IP literals are the same host: rejecting only the name leaves
			// the rule bypassable by spelling it as an address.
			name: "ShouldRejectLoopbackIPv4RedirectURIForWebApplicationType",
			metadata: &oauth2.ClientRegistrationMetadata{
				ApplicationType: "web",
				RedirectURIs:    []string{"https://127.0.0.1:8080/cb"},
			},
			err: "invalid_redirect_uri",
		},
		{
			name: "ShouldRejectLoopbackIPv6RedirectURIForWebApplicationType",
			metadata: &oauth2.ClientRegistrationMetadata{
				ApplicationType: "web",
				RedirectURIs:    []string{"https://[::1]:8080/cb"},
			},
			err: "invalid_redirect_uri",
		},
		{
			// 127.0.0.0/8 is loopback in its entirety, not just 127.0.0.1.
			name: "ShouldRejectNonCanonicalLoopbackIPv4RedirectURIForWebApplicationType",
			metadata: &oauth2.ClientRegistrationMetadata{
				ApplicationType: "web",
				RedirectURIs:    []string{"https://127.0.0.2:8080/cb"},
			},
			err: "invalid_redirect_uri",
		},
		{
			// RFC 6761 §6.3 reserves names under '.localhost' as loopback, and 'localhost.' is the same name fully
			// qualified.
			name: "ShouldRejectLocalhostNamesForWebApplicationType",
			metadata: &oauth2.ClientRegistrationMetadata{
				ApplicationType: "web",
				RedirectURIs:    []string{"https://app.LOCALHOST./cb"},
			},
			err: "invalid_redirect_uri",
		},
		{
			// The loopback prohibition is scoped to web clients: it must not follow a native client to the loopback
			// redirect RFC 8252 §7.3 requires of it.
			name: "ShouldAcceptLoopbackRedirectURIForNativeApplicationType",
			metadata: &oauth2.ClientRegistrationMetadata{
				ApplicationType: "native",
				RedirectURIs:    []string{"http://127.0.0.1:8080/cb"},
				GrantTypes:      []string{"authorization_code"},
				ResponseTypes:   []string{"code"},
			},
		},
		{
			// RFC 8252 §7.1 requires a private-use scheme be based on a domain the app controls, expressed in
			// reverse order.
			name: "ShouldAcceptReverseDNSPrivateUseSchemeForNativeApplicationType",
			metadata: &oauth2.ClientRegistrationMetadata{
				ApplicationType: "native",
				RedirectURIs:    []string{"com.example.app:/oauth2redirect/example-provider"},
				GrantTypes:      []string{"authorization_code"},
				ResponseTypes:   []string{"code"},
			},
		},
		{
			// A single-label scheme is claimable by any other application on the device, so it is not a scheme the
			// registrant can be said to control.
			name: "ShouldRejectSingleLabelPrivateUseSchemeForNativeApplicationType",
			metadata: &oauth2.ClientRegistrationMetadata{
				ApplicationType: "native",
				RedirectURIs:    []string{"myapp://cb"},
				GrantTypes:      []string{"authorization_code"},
				ResponseTypes:   []string{"code"},
			},
			err: "invalid_redirect_uri",
		},
		{
			name: "ShouldRejectJavascriptSchemeForNativeApplicationType",
			metadata: &oauth2.ClientRegistrationMetadata{
				ApplicationType: "native",
				RedirectURIs:    []string{"javascript:alert(1)"},
				GrantTypes:      []string{"authorization_code"},
				ResponseTypes:   []string{"code"},
			},
			err: "invalid_redirect_uri",
		},
		{
			name: "ShouldRejectDataSchemeForNativeApplicationType",
			metadata: &oauth2.ClientRegistrationMetadata{
				ApplicationType: "native",
				RedirectURIs:    []string{"data:text/html,<script>alert(1)</script>"},
				GrantTypes:      []string{"authorization_code"},
				ResponseTypes:   []string{"code"},
			},
			err: "invalid_redirect_uri",
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
			name: "ShouldRejectNoneTokenEndpointAuthSigningAlg",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs:                []string{"https://example.com/cb"},
				TokenEndpointAuthSigningAlg: "none",
			},
			err: "invalid_client_metadata",
		},
		{
			name: "ShouldRejectNoneIntrospectionEndpointAuthSigningAlg",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs:                        []string{"https://example.com/cb"},
				IntrospectionEndpointAuthSigningAlg: "none",
			},
			err: "invalid_client_metadata",
		},
		{
			name: "ShouldRejectNoneRevocationEndpointAuthSigningAlg",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs:                     []string{"https://example.com/cb"},
				RevocationEndpointAuthSigningAlg: "none",
			},
			err: "invalid_client_metadata",
		},
		{
			name: "ShouldAcceptNoneRequestObjectSigningAlg",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs:            []string{"https://example.com/cb"},
				RequestObjectSigningAlg: "none",
			},
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
				GrantTypes:              []string{"client_credentials"},
				TokenEndpointAuthMethod: "tls_client_auth",
				TLSClientAuthSubjectDN:  "CN=client,O=Example",
			},
		},
		{
			name: "ShouldAcceptTLSClientAuthOnANonTokenEndpoint",
			metadata: &oauth2.ClientRegistrationMetadata{
				GrantTypes:                      []string{"client_credentials"},
				IntrospectionEndpointAuthMethod: "tls_client_auth",
				TLSClientAuthSANDNS:             "client.example.com",
			},
		},
		{
			name: "ShouldRejectTLSClientAuthWithNoSubject",
			metadata: &oauth2.ClientRegistrationMetadata{
				GrantTypes:              []string{"client_credentials"},
				TokenEndpointAuthMethod: "tls_client_auth",
			},
			err: "invalid_client_metadata",
		},
		{
			name: "ShouldRejectTLSClientAuthWithMultipleSubjects",
			metadata: &oauth2.ClientRegistrationMetadata{
				GrantTypes:              []string{"client_credentials"},
				TokenEndpointAuthMethod: "tls_client_auth",
				TLSClientAuthSubjectDN:  "CN=client,O=Example",
				TLSClientAuthSANEmail:   "client@example.com",
			},
			err: "invalid_client_metadata",
		},
		{
			name: "ShouldRejectSubjectWithoutTLSClientAuth",
			metadata: &oauth2.ClientRegistrationMetadata{
				GrantTypes:              []string{"client_credentials"},
				TokenEndpointAuthMethod: "client_secret_basic",
				TLSClientAuthSANDNS:     "client.example.com",
			},
			err: "invalid_client_metadata",
		},
		{
			name: "ShouldRejectTLSClientAuthWithMalformedSANIP",
			metadata: &oauth2.ClientRegistrationMetadata{
				GrantTypes:              []string{"client_credentials"},
				TokenEndpointAuthMethod: "tls_client_auth",
				TLSClientAuthSANIP:      "not-an-ip",
			},
			err: "invalid_client_metadata",
		},
		{
			name: "ShouldAcceptSelfSignedTLSClientAuthWithJSONWebKeysURI",
			metadata: &oauth2.ClientRegistrationMetadata{
				GrantTypes:              []string{"client_credentials"},
				TokenEndpointAuthMethod: "self_signed_tls_client_auth",
				JSONWebKeysURI:          "https://example.com/jwks.json",
			},
		},
		{
			name: "ShouldRejectSelfSignedTLSClientAuthWithoutJSONWebKeys",
			metadata: &oauth2.ClientRegistrationMetadata{
				GrantTypes:              []string{"client_credentials"},
				TokenEndpointAuthMethod: "self_signed_tls_client_auth",
			},
			err: "invalid_client_metadata",
		},
		{
			name:     "ShouldRejectOmittedGrantTypesWithoutRedirectURI",
			metadata: &oauth2.ClientRegistrationMetadata{},
			err:      "invalid_client_metadata",
		},
		{
			name: "ShouldAcceptOmittedGrantTypesWithRedirectURI",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs: []string{"https://example.com/cb"},
			},
		},
		{
			name: "ShouldAcceptExplicitNonRedirectingGrantWithoutRedirectURI",
			metadata: &oauth2.ClientRegistrationMetadata{
				GrantTypes: []string{"client_credentials"},
			},
		},
		{
			name: "ShouldRejectImplicitResponseTypeWithOmittedGrantTypes",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs:  []string{"https://example.com/cb"},
				ResponseTypes: []string{"id_token"},
			},
			err: "invalid_client_metadata",
		},
		{
			name: "ShouldRejectPlaintextJWKSURI",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs:   []string{"https://example.com/cb"},
				JSONWebKeysURI: "http://169.254.169.254/latest/meta-data/",
			},
			err: "invalid_client_metadata",
		},
		{
			name: "ShouldRejectPlaintextRequestURI",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs: []string{"https://example.com/cb"},
				RequestURIs:  []string{"http://127.0.0.1:9200/_cluster/health"},
			},
			err: "invalid_client_metadata",
		},
		{
			name: "ShouldRejectPlaintextInitiateLoginURI",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs:     []string{"https://example.com/cb"},
				InitiateLoginURI: "http://example.com/login",
			},
			err: "invalid_client_metadata",
		},
		{
			name: "ShouldRejectPlaintextBackChannelLogoutURI",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs:         []string{"https://example.com/cb"},
				BackChannelLogoutURI: "http://169.254.169.254/",
			},
			err: "invalid_client_metadata",
		},
		{
			name: "ShouldRejectOpaqueJWKSURI",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs:   []string{"https://example.com/cb"},
				JSONWebKeysURI: "javascript:alert(1)",
			},
			err: "invalid_client_metadata",
		},
		{
			name: "ShouldAcceptSecureFetchedURIs",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs:         []string{"https://example.com/cb"},
				GrantTypes:           []string{"authorization_code"},
				ResponseTypes:        []string{"code"},
				JSONWebKeysURI:       "https://example.com/jwks",
				RequestURIs:          []string{"https://example.com/ro"},
				InitiateLoginURI:     "https://example.com/login",
				BackChannelLogoutURI: "https://example.com/logout",
			},
		},
		{
			name: "ShouldAcceptPlaintextPostLogoutRedirectURIForConfidentialClient",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs:            []string{"https://example.com/cb"},
				GrantTypes:              []string{"authorization_code"},
				ResponseTypes:           []string{"code"},
				TokenEndpointAuthMethod: "client_secret_basic",
				PostLogoutRedirectURIs:  []string{"http://example.com/post-logout"},
			},
		},
		{
			name: "ShouldRejectPlaintextPostLogoutRedirectURIForPublicClient",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs:            []string{"https://example.com/cb"},
				TokenEndpointAuthMethod: "none",
				PostLogoutRedirectURIs:  []string{"http://example.com/post-logout"},
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
