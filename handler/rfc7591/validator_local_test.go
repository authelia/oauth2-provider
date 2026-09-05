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
	"authelia.com/provider/oauth2/token/jose"
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
		expected string
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
			expected: "The value of one or more redirection URIs is invalid. The 'redirect_uris' value 'https://example.com/cb#frag' must not contain a fragment component.",
		},
		{
			name: "ShouldRejectRelativeRedirectURI",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs: []string{"/cb"},
			},
			expected: "The value of one or more redirection URIs is invalid. The 'redirect_uris' value '/cb' must be an absolute URI.",
		},
		{
			name: "ShouldRejectInsecureRedirectURIForWebApplicationType",
			metadata: &oauth2.ClientRegistrationMetadata{
				ApplicationType: "web",
				RedirectURIs:    []string{"http://example.com/cb"},
			},
			expected: "The value of one or more redirection URIs is invalid. The 'redirect_uris' value 'http://example.com/cb' must use the 'https' scheme.",
		},
		{
			name: "ShouldRejectLocalhostRedirectURIForWebApplicationType",
			metadata: &oauth2.ClientRegistrationMetadata{
				ApplicationType: "web",
				RedirectURIs:    []string{"https://localhost:8080/cb"},
			},
			expected: "The value of one or more redirection URIs is invalid. The 'redirect_uris' value 'https://localhost:8080/cb' must not target the loopback interface for the 'web' 'application_type'.",
		},
		{
			name: "ShouldRejectLoopbackIPv4RedirectURIForWebApplicationType",
			metadata: &oauth2.ClientRegistrationMetadata{
				ApplicationType: "web",
				RedirectURIs:    []string{"https://127.0.0.1:8080/cb"},
			},
			expected: "The value of one or more redirection URIs is invalid. The 'redirect_uris' value 'https://127.0.0.1:8080/cb' must not target the loopback interface for the 'web' 'application_type'.",
		},
		{
			name: "ShouldRejectLoopbackIPv6RedirectURIForWebApplicationType",
			metadata: &oauth2.ClientRegistrationMetadata{
				ApplicationType: "web",
				RedirectURIs:    []string{"https://[::1]:8080/cb"},
			},
			expected: "The value of one or more redirection URIs is invalid. The 'redirect_uris' value 'https://[::1]:8080/cb' must not target the loopback interface for the 'web' 'application_type'.",
		},
		{
			name: "ShouldRejectNonCanonicalLoopbackIPv4RedirectURIForWebApplicationType",
			metadata: &oauth2.ClientRegistrationMetadata{
				ApplicationType: "web",
				RedirectURIs:    []string{"https://127.0.0.2:8080/cb"},
			},
			expected: "The value of one or more redirection URIs is invalid. The 'redirect_uris' value 'https://127.0.0.2:8080/cb' must not target the loopback interface for the 'web' 'application_type'.",
		},
		{
			// RFC 6761 §6.3: names under '.localhost' are reserved as loopback.
			name: "ShouldRejectLocalhostNamesForWebApplicationType",
			metadata: &oauth2.ClientRegistrationMetadata{
				ApplicationType: "web",
				RedirectURIs:    []string{"https://app.LOCALHOST./cb"},
			},
			expected: "The value of one or more redirection URIs is invalid. The 'redirect_uris' value 'https://app.LOCALHOST./cb' must not target the loopback interface for the 'web' 'application_type'.",
		},
		{
			// RFC 8252 §7.3: a native client requires the loopback redirect.
			name: "ShouldAcceptLoopbackRedirectURIForNativeApplicationType",
			metadata: &oauth2.ClientRegistrationMetadata{
				ApplicationType: "native",
				RedirectURIs:    []string{"http://127.0.0.1:8080/cb"},
				GrantTypes:      []string{"authorization_code"},
				ResponseTypes:   []string{"code"},
			},
		},
		{
			// RFC 8252 §7.1: a private-use scheme must be a domain the app controls, in reverse order.
			name: "ShouldAcceptReverseDNSPrivateUseSchemeForNativeApplicationType",
			metadata: &oauth2.ClientRegistrationMetadata{
				ApplicationType: "native",
				RedirectURIs:    []string{"com.example.app:/oauth2redirect/example-provider"},
				GrantTypes:      []string{"authorization_code"},
				ResponseTypes:   []string{"code"},
			},
		},
		{
			name: "ShouldRejectSingleLabelPrivateUseSchemeForNativeApplicationType",
			metadata: &oauth2.ClientRegistrationMetadata{
				ApplicationType: "native",
				RedirectURIs:    []string{"myapp://cb"},
				GrantTypes:      []string{"authorization_code"},
				ResponseTypes:   []string{"code"},
			},
			expected: "The value of one or more redirection URIs is invalid. The 'redirect_uris' value 'myapp://cb' must use a private-use URI scheme based on a domain name under the client's control, expressed in reverse order.",
		},
		{
			name: "ShouldRejectJavascriptSchemeForNativeApplicationType",
			metadata: &oauth2.ClientRegistrationMetadata{
				ApplicationType: "native",
				RedirectURIs:    []string{"javascript:alert(1)"},
				GrantTypes:      []string{"authorization_code"},
				ResponseTypes:   []string{"code"},
			},
			expected: "The value of one or more redirection URIs is invalid. The 'redirect_uris' value 'javascript:alert(1)' must use a private-use URI scheme based on a domain name under the client's control, expressed in reverse order.",
		},
		{
			name: "ShouldRejectDataSchemeForNativeApplicationType",
			metadata: &oauth2.ClientRegistrationMetadata{
				ApplicationType: "native",
				RedirectURIs:    []string{"data:text/html,<script>alert(1)</script>"},
				GrantTypes:      []string{"authorization_code"},
				ResponseTypes:   []string{"code"},
			},
			expected: "The value of one or more redirection URIs is invalid. The 'redirect_uris' value 'data:text/html,<script>alert(1)</script>' must use a private-use URI scheme based on a domain name under the client's control, expressed in reverse order.",
		},
		{
			name: "ShouldRejectBothJWKSAndJWKSURI",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs:   []string{"https://example.com/cb"},
				JSONWebKeysURI: "https://example.com/jwks",
				JSONWebKeys:    &jose.JSONWebKeySet{},
			},
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'jwks' and 'jwks_uri' parameters are mutually exclusive.",
		},
		{
			name: "ShouldRejectCodeResponseTypeWithoutAuthorizationCodeGrant",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs:  []string{"https://example.com/cb"},
				GrantTypes:    []string{"client_credentials"},
				ResponseTypes: []string{"code"},
			},
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'code' response type requires the 'authorization_code' grant type to be present in 'grant_types'.",
		},
		{
			name: "ShouldRejectUnknownApplicationType",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs:    []string{"https://example.com/cb"},
				ApplicationType: "desktop",
			},
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'application_type' value 'desktop' is not a recognized application type.",
		},
		{
			name: "ShouldRejectUnknownSubjectType",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs: []string{"https://example.com/cb"},
				SubjectType:  "sectoral",
			},
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'subject_type' value 'sectoral' is not a recognized subject type.",
		},
		{
			name: "ShouldRejectNoneIDTokenSignedResponseAlg",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs:             []string{"https://example.com/cb"},
				IDTokenSignedResponseAlg: "none",
			},
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'id_token_signed_response_alg' value must not be 'none'.",
		},
		{
			name: "ShouldRejectNoneTokenEndpointAuthSigningAlg",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs:                []string{"https://example.com/cb"},
				TokenEndpointAuthSigningAlg: "none",
			},
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'token_endpoint_auth_signing_alg' value must not be 'none'.",
		},
		{
			name: "ShouldRejectNoneIntrospectionEndpointAuthSigningAlg",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs:                        []string{"https://example.com/cb"},
				IntrospectionEndpointAuthSigningAlg: "none",
			},
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'introspection_endpoint_auth_signing_alg' value must not be 'none'.",
		},
		{
			name: "ShouldRejectNoneRevocationEndpointAuthSigningAlg",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs:                     []string{"https://example.com/cb"},
				RevocationEndpointAuthSigningAlg: "none",
			},
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'revocation_endpoint_auth_signing_alg' value must not be 'none'.",
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
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. A 'token' or 'id_token' response type requires the 'implicit' grant type to be present in 'grant_types'.",
		},
		{
			name: "ShouldRejectAuthorizationCodeGrantWithoutRedirectURI",
			metadata: &oauth2.ClientRegistrationMetadata{
				GrantTypes:    []string{"authorization_code"},
				ResponseTypes: []string{"code"},
			},
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'authorization_code' grant type requires at least one 'redirect_uris' value.",
		},
		{
			name: "ShouldRejectWhitespaceInAlgorithmValue",
			metadata: &oauth2.ClientRegistrationMetadata{
				RedirectURIs:                []string{"https://example.com/cb"},
				IDTokenEncryptedResponseAlg: "RSA OAEP",
			},
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'id_token_encrypted_response_alg' value 'RSA OAEP' must be a non-empty token.",
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
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'scope' value ''quoted'' contains characters that are not permitted in a scope token.",
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
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'tls_client_auth' authentication method requires exactly one of the 'tls_client_auth_subject_dn', 'tls_client_auth_san_dns', 'tls_client_auth_san_uri', 'tls_client_auth_san_ip', or 'tls_client_auth_san_email' values but 0 were registered.",
		},
		{
			name: "ShouldRejectTLSClientAuthWithMultipleSubjects",
			metadata: &oauth2.ClientRegistrationMetadata{
				GrantTypes:              []string{"client_credentials"},
				TokenEndpointAuthMethod: "tls_client_auth",
				TLSClientAuthSubjectDN:  "CN=client,O=Example",
				TLSClientAuthSANEmail:   "client@example.com",
			},
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'tls_client_auth' authentication method requires exactly one of the 'tls_client_auth_subject_dn', 'tls_client_auth_san_dns', 'tls_client_auth_san_uri', 'tls_client_auth_san_ip', or 'tls_client_auth_san_email' values but 2 were registered.",
		},
		{
			name: "ShouldRejectSubjectWithoutTLSClientAuth",
			metadata: &oauth2.ClientRegistrationMetadata{
				GrantTypes:              []string{"client_credentials"},
				TokenEndpointAuthMethod: "client_secret_basic",
				TLSClientAuthSANDNS:     "client.example.com",
			},
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'tls_client_auth_san_dns' value is only permitted when an endpoint authentication method is 'tls_client_auth'.",
		},
		{
			name: "ShouldRejectTLSClientAuthWithMalformedSANIP",
			metadata: &oauth2.ClientRegistrationMetadata{
				GrantTypes:              []string{"client_credentials"},
				TokenEndpointAuthMethod: "tls_client_auth",
				TLSClientAuthSANIP:      "not-an-ip",
			},
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'tls_client_auth_san_ip' value 'not-an-ip' must be a valid IP address.",
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
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'self_signed_tls_client_auth' authentication method requires either the 'jwks' or 'jwks_uri' value to be registered.",
		},
		{
			name:     "ShouldRejectOmittedGrantTypesWithoutRedirectURI",
			metadata: &oauth2.ClientRegistrationMetadata{},
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'authorization_code' grant type, which applies by default when 'grant_types' is omitted, requires at least one 'redirect_uris' value.",
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
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. A 'token' or 'id_token' response type requires the 'implicit' grant type to be present in 'grant_types'.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validator.ValidateClientRegistrationMetadata(context.Background(), nil, tc.metadata)

			if tc.expected == "" {
				require.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.expected)
		})
	}
}

func TestLocalValidatorURIs(t *testing.T) {
	validator := NewLocalValidator(&oauth2.Config{
		ScopeStrategy:    oauth2.ExactScopeStrategy,
		AudienceStrategy: oauth2.DefaultAudienceStrategy,
	})

	base := func() *oauth2.ClientRegistrationMetadata {
		return &oauth2.ClientRegistrationMetadata{
			RedirectURIs:  []string{"https://example.com/cb"},
			GrantTypes:    []string{"authorization_code"},
			ResponseTypes: []string{"code"},
		}
	}

	testCases := []struct {
		name     string
		mutate   func(m *oauth2.ClientRegistrationMetadata)
		expected string
	}{
		{
			name:   "ShouldAcceptSecureJSONWebKeysURI",
			mutate: func(m *oauth2.ClientRegistrationMetadata) { m.JSONWebKeysURI = "https://example.com/jwks.json" },
		},
		{
			name: "ShouldRejectInsecureJSONWebKeysURI",
			mutate: func(m *oauth2.ClientRegistrationMetadata) {
				m.JSONWebKeysURI = "http://169.254.169.254/latest/meta-data/"
			},
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'jwks_uri' value 'http://169.254.169.254/latest/meta-data/' must use the 'https' scheme.",
		},
		{
			name:     "ShouldRejectRelativeJSONWebKeysURI",
			mutate:   func(m *oauth2.ClientRegistrationMetadata) { m.JSONWebKeysURI = "/jwks.json" },
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'jwks_uri' value '/jwks.json' must be an absolute URI.",
		},
		{
			name:     "ShouldRejectJSONWebKeysURIWithFragment",
			mutate:   func(m *oauth2.ClientRegistrationMetadata) { m.JSONWebKeysURI = "https://example.com/jwks.json#k" },
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'jwks_uri' value 'https://example.com/jwks.json#k' must not contain a fragment component.",
		},
		{
			name:   "ShouldAcceptSecureRequestURIs",
			mutate: func(m *oauth2.ClientRegistrationMetadata) { m.RequestURIs = []string{"https://example.com/ro.jwt"} },
		},
		{
			name:     "ShouldRejectInsecureRequestURI",
			mutate:   func(m *oauth2.ClientRegistrationMetadata) { m.RequestURIs = []string{"http://127.0.0.1:6379/"} },
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'request_uris' value 'http://127.0.0.1:6379/' must use the 'https' scheme.",
		},
		{
			name:   "ShouldAcceptSecureBackChannelLogoutURI",
			mutate: func(m *oauth2.ClientRegistrationMetadata) { m.BackChannelLogoutURI = "https://example.com/logout" },
		},
		{
			name:     "ShouldRejectInsecureBackChannelLogoutURI",
			mutate:   func(m *oauth2.ClientRegistrationMetadata) { m.BackChannelLogoutURI = "http://169.254.169.254/" },
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'backchannel_logout_uri' value 'http://169.254.169.254/' must use the 'https' scheme.",
		},
		{
			name:     "ShouldRejectBackChannelLogoutURIWithFragment",
			mutate:   func(m *oauth2.ClientRegistrationMetadata) { m.BackChannelLogoutURI = "https://example.com/logout#f" },
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'backchannel_logout_uri' value 'https://example.com/logout#f' must not contain a fragment component.",
		},
		{
			name:     "ShouldRejectRelativePostLogoutRedirectURI",
			mutate:   func(m *oauth2.ClientRegistrationMetadata) { m.PostLogoutRedirectURIs = []string{"/after-logout"} },
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'post_logout_redirect_uris' value '/after-logout' must be an absolute URI.",
		},
		{
			name: "ShouldRejectPostLogoutRedirectURIWithFragment",
			mutate: func(m *oauth2.ClientRegistrationMetadata) {
				m.PostLogoutRedirectURIs = []string{"https://example.com/o#f"}
			},
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'post_logout_redirect_uris' value 'https://example.com/o#f' must not contain a fragment component.",
		},
		{
			name: "ShouldAcceptPrivateUseSchemePostLogoutRedirectURI",
			mutate: func(m *oauth2.ClientRegistrationMetadata) {
				m.PostLogoutRedirectURIs = []string{"com.example.app:/done"}
			},
		},
		{
			// url.Parse reports a bare scheme as absolute, so only the host check rejects it.
			name:     "ShouldRejectHostlessJSONWebKeysURI",
			mutate:   func(m *oauth2.ClientRegistrationMetadata) { m.JSONWebKeysURI = "https:" },
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'jwks_uri' value 'https:' must include a host component.",
		},
		{
			name:     "ShouldRejectOpaqueJSONWebKeysURI",
			mutate:   func(m *oauth2.ClientRegistrationMetadata) { m.JSONWebKeysURI = "https:example.com/jwks.json" },
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'jwks_uri' value 'https:example.com/jwks.json' must include a host component.",
		},
		{
			name:     "ShouldRejectSingleSlashJSONWebKeysURI",
			mutate:   func(m *oauth2.ClientRegistrationMetadata) { m.JSONWebKeysURI = "https:/jwks.json" },
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'jwks_uri' value 'https:/jwks.json' must include a host component.",
		},
		{
			name:     "ShouldRejectHostlessBackChannelLogoutURI",
			mutate:   func(m *oauth2.ClientRegistrationMetadata) { m.BackChannelLogoutURI = "https:/logout" },
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'backchannel_logout_uri' value 'https:/logout' must include a host component.",
		},
		{
			name:     "ShouldRejectEmptyRequestURIMember",
			mutate:   func(m *oauth2.ClientRegistrationMetadata) { m.RequestURIs = []string{"https://example.com/ro.jwt", ""} },
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'request_uris' values must not contain an empty value.",
		},
		{
			name:     "ShouldRejectEmptyPostLogoutRedirectURIMember",
			mutate:   func(m *oauth2.ClientRegistrationMetadata) { m.PostLogoutRedirectURIs = []string{""} },
			expected: "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'post_logout_redirect_uris' values must not contain an empty value.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metadata := base()
			tc.mutate(metadata)

			err := validator.ValidateClientRegistrationMetadata(t.Context(), nil, metadata)

			if tc.expected == "" {
				assert.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.expected)
		})
	}
}

func TestLocalValidatorGrantTypePolicy(t *testing.T) {
	base := func(grantTypes, responseTypes []string) *oauth2.ClientRegistrationMetadata {
		return &oauth2.ClientRegistrationMetadata{
			RedirectURIs:  []string{"https://example.com/cb"},
			GrantTypes:    grantTypes,
			ResponseTypes: responseTypes,
		}
	}

	testCases := []struct {
		name      string
		permitted []string
		metadata  *oauth2.ClientRegistrationMetadata
		expected  string
	}{
		{
			// Unset permits any grant, so that registering an mTLS client credentials client keeps working.
			name:     "ShouldPermitAnyGrantWhenUnset",
			metadata: base([]string{"client_credentials"}, nil),
		},
		{
			name:     "ShouldPermitResourceOwnerPasswordWhenUnset",
			metadata: base([]string{"password"}, nil),
		},
		{
			name:      "ShouldRejectClientCredentialsWhenNotPermitted",
			permitted: []string{"authorization_code", "refresh_token"},
			metadata:  base([]string{"client_credentials"}, nil),
			expected:  "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'grant_types' value 'client_credentials' is not permitted for registration.",
		},
		{
			name:      "ShouldRejectResourceOwnerPasswordWhenNotPermitted",
			permitted: []string{"authorization_code"},
			metadata:  base([]string{"password"}, nil),
			expected:  "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'grant_types' value 'password' is not permitted for registration.",
		},
		{
			name:      "ShouldRejectTokenExchangeWhenNotPermitted",
			permitted: []string{"authorization_code"},
			metadata:  base([]string{"urn:ietf:params:oauth:grant-type:token-exchange"}, nil),
			expected:  "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'grant_types' value 'urn:ietf:params:oauth:grant-type:token-exchange' is not permitted for registration.",
		},
		{
			name:      "ShouldAcceptWhatTheDeploymentPermits",
			permitted: []string{"authorization_code", "client_credentials"},
			metadata:  base([]string{"client_credentials"}, nil),
		},
		{
			name:      "ShouldRejectWhatTheDeploymentDoesNotPermit",
			permitted: []string{"authorization_code"},
			metadata:  base([]string{"authorization_code", "refresh_token"}, []string{"code"}),
			expected:  "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'grant_types' value 'refresh_token' is not permitted for registration.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validator := NewLocalValidator(&oauth2.Config{
				ScopeStrategy:                       oauth2.ExactScopeStrategy,
				AudienceStrategy:                    oauth2.DefaultAudienceStrategy,
				RFC7591ClientRegistrationGrantTypes: tc.permitted,
			})

			err := validator.ValidateClientRegistrationMetadata(t.Context(), nil, tc.metadata)

			if tc.expected == "" {
				assert.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.expected)
		})
	}
}
