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

// TestLocalValidatorURIs covers the client metadata URIs the authorization server itself dereferences. Nothing
// constrained them, so a registrant could point the server at an internal service: 'jwks_uri' and 'request_uris' are
// fetched, and 'backchannel_logout_uri' is issued a POST whose status code reaches the caller.
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
		name   string
		mutate func(m *oauth2.ClientRegistrationMetadata)
		err    string
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
			err: "must use the 'https' scheme",
		},
		{
			name:   "ShouldRejectRelativeJSONWebKeysURI",
			mutate: func(m *oauth2.ClientRegistrationMetadata) { m.JSONWebKeysURI = "/jwks.json" },
			err:    "must be an absolute URI",
		},
		{
			name:   "ShouldRejectJSONWebKeysURIWithFragment",
			mutate: func(m *oauth2.ClientRegistrationMetadata) { m.JSONWebKeysURI = "https://example.com/jwks.json#k" },
			err:    "must not contain a fragment component",
		},
		{
			name:   "ShouldAcceptSecureRequestURIs",
			mutate: func(m *oauth2.ClientRegistrationMetadata) { m.RequestURIs = []string{"https://example.com/ro.jwt"} },
		},
		{
			name:   "ShouldRejectInsecureRequestURI",
			mutate: func(m *oauth2.ClientRegistrationMetadata) { m.RequestURIs = []string{"http://127.0.0.1:6379/"} },
			err:    "must use the 'https' scheme",
		},
		{
			name:   "ShouldAcceptSecureBackChannelLogoutURI",
			mutate: func(m *oauth2.ClientRegistrationMetadata) { m.BackChannelLogoutURI = "https://example.com/logout" },
		},
		{
			name:   "ShouldRejectInsecureBackChannelLogoutURI",
			mutate: func(m *oauth2.ClientRegistrationMetadata) { m.BackChannelLogoutURI = "http://169.254.169.254/" },
			err:    "must use the 'https' scheme",
		},
		{
			name:   "ShouldRejectBackChannelLogoutURIWithFragment",
			mutate: func(m *oauth2.ClientRegistrationMetadata) { m.BackChannelLogoutURI = "https://example.com/logout#f" },
			err:    "must not contain a fragment component",
		},
		{
			name:   "ShouldRejectRelativePostLogoutRedirectURI",
			mutate: func(m *oauth2.ClientRegistrationMetadata) { m.PostLogoutRedirectURIs = []string{"/after-logout"} },
			err:    "must be an absolute URI",
		},
		{
			name: "ShouldRejectPostLogoutRedirectURIWithFragment",
			mutate: func(m *oauth2.ClientRegistrationMetadata) {
				m.PostLogoutRedirectURIs = []string{"https://example.com/o#f"}
			},
			err: "must not contain a fragment component",
		},
		{
			// Not fetched by the server, so the https requirement that closes the SSRF does not apply and a native
			// client's private-use scheme stays registrable.
			name: "ShouldAcceptPrivateUseSchemePostLogoutRedirectURI",
			mutate: func(m *oauth2.ClientRegistrationMetadata) {
				m.PostLogoutRedirectURIs = []string{"com.example.app:/done"}
			},
		},
		{
			// url.Parse reports a bare scheme as absolute, so the absolute and https checks both pass and only the
			// host check rejects it.
			name:   "ShouldRejectHostlessJSONWebKeysURI",
			mutate: func(m *oauth2.ClientRegistrationMetadata) { m.JSONWebKeysURI = "https:" },
			err:    "must include a host component",
		},
		{
			name:   "ShouldRejectOpaqueJSONWebKeysURI",
			mutate: func(m *oauth2.ClientRegistrationMetadata) { m.JSONWebKeysURI = "https:example.com/jwks.json" },
			err:    "must include a host component",
		},
		{
			name:   "ShouldRejectSingleSlashJSONWebKeysURI",
			mutate: func(m *oauth2.ClientRegistrationMetadata) { m.JSONWebKeysURI = "https:/jwks.json" },
			err:    "must include a host component",
		},
		{
			name:   "ShouldRejectHostlessBackChannelLogoutURI",
			mutate: func(m *oauth2.ClientRegistrationMetadata) { m.BackChannelLogoutURI = "https:/logout" },
			err:    "must include a host component",
		},
		{
			name:   "ShouldRejectEmptyRequestURIMember",
			mutate: func(m *oauth2.ClientRegistrationMetadata) { m.RequestURIs = []string{"https://example.com/ro.jwt", ""} },
			err:    "must not contain an empty value",
		},
		{
			name:   "ShouldRejectEmptyPostLogoutRedirectURIMember",
			mutate: func(m *oauth2.ClientRegistrationMetadata) { m.PostLogoutRedirectURIs = []string{""} },
			err:    "must not contain an empty value",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metadata := base()
			tc.mutate(metadata)

			err := validator.ValidateClientRegistrationMetadata(t.Context(), nil, metadata)

			if tc.err == "" {
				assert.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), tc.err)
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
		err       string
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
			err:       "client_credentials",
		},
		{
			name:      "ShouldRejectResourceOwnerPasswordWhenNotPermitted",
			permitted: []string{"authorization_code"},
			metadata:  base([]string{"password"}, nil),
			err:       "password",
		},
		{
			name:      "ShouldRejectTokenExchangeWhenNotPermitted",
			permitted: []string{"authorization_code"},
			metadata:  base([]string{"urn:ietf:params:oauth:grant-type:token-exchange"}, nil),
			err:       "token-exchange",
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
			err:       "refresh_token",
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

			if tc.err == "" {
				assert.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), tc.err)
		})
	}
}
