// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

// OAuth2AuthorizationServerMetadata is the OAuth 2.0 Authorization Server Metadata document. Each embedded pointer is
// one extension specification and is omitted from the document while nil.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
type OAuth2AuthorizationServerMetadata struct {
	Issuer                                             string   `json:"issuer,omitempty"`
	AuthorizationEndpoint                              string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                                      string   `json:"token_endpoint,omitempty"`
	JWKSURI                                            string   `json:"jwks_uri,omitempty"`
	RegistrationEndpoint                               string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                                    []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported                             []string `json:"response_types_supported,omitempty"`
	ResponseModesSupported                             []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported                                []string `json:"grant_types_supported,omitempty"`
	TokenEndpointAuthMethodsSupported                  []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported         []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	ServiceDocumentation                               string   `json:"service_documentation,omitempty"`
	UILocalesSupported                                 []string `json:"ui_locales_supported,omitempty"`
	OPPolicyURI                                        string   `json:"op_policy_uri,omitempty"`
	OPTOSURI                                           string   `json:"op_tos_uri,omitempty"`
	RevocationEndpoint                                 string   `json:"revocation_endpoint,omitempty"`
	RevocationEndpointAuthMethodsSupported             []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	RevocationEndpointAuthSigningAlgValuesSupported    []string `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty"`
	IntrospectionEndpoint                              string   `json:"introspection_endpoint,omitempty"`
	IntrospectionEndpointAuthMethodsSupported          []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	IntrospectionEndpointAuthSigningAlgValuesSupported []string `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`
	CodeChallengeMethodsSupported                      []string `json:"code_challenge_methods_supported,omitempty"`
	ACRValuesSupported                                 []string `json:"acr_values_supported,omitempty"`
	SignedMetadata                                     string   `json:"signed_metadata,omitempty"`

	*RFC8628DeviceAuthorizationMetadata
	*RFC8705MutualTLSMetadata
	*RFC9101JWTSecuredAuthorizationRequestMetadata
	*RFC9126PushedAuthorizationRequestMetadata
	*RFC9207AuthorizationServerIssuerIdentificationMetadata
	*RFC9396RichAuthorizationRequestsMetadata
	*RFC9449DPoPMetadata
	*RFC9701JWTIntrospectionResponseMetadata
	*RFC9728ProtectedResourceMetadata
	*OpenIDConnectJARMMetadata
	*DraftClientIDMetadataDocumentMetadata
	*DraftIdentityChainingMetadata
	*DraftIDJAGMetadata
	*DraftStatusListMetadata
	*DraftAttestationBasedClientAuthMetadata
	*DraftFirstPartyAppsMetadata
	*DraftRefreshTokenExpirationMetadata
	*DraftDeferredTokenResponseMetadata
	*DraftRARMetadataRemediationMetadata
	*DraftDPoPRequiredMetadata
	*DraftUserAuthorizationManagementMetadata
	*DraftAuthorityMetadata
	*OpenIDFederationMetadata
	*OpenID4VCIMetadata
}

// OpenIDConnectProviderMetadata is the OpenID Connect Discovery 1.0 OpenID Provider Metadata document. Each embedded
// pointer is one extension specification and is omitted from the document while nil.
//
// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
type OpenIDConnectProviderMetadata struct {
	OAuth2AuthorizationServerMetadata

	UserinfoEndpoint                     string   `json:"userinfo_endpoint,omitempty"`
	SubjectTypesSupported                []string `json:"subject_types_supported,omitempty"`
	IDTokenSigningAlgValuesSupported     []string `json:"id_token_signing_alg_values_supported,omitempty"`
	IDTokenEncryptionAlgValuesSupported  []string `json:"id_token_encryption_alg_values_supported,omitempty"`
	IDTokenEncryptionEncValuesSupported  []string `json:"id_token_encryption_enc_values_supported,omitempty"`
	UserinfoSigningAlgValuesSupported    []string `json:"userinfo_signing_alg_values_supported,omitempty"`
	UserinfoEncryptionAlgValuesSupported []string `json:"userinfo_encryption_alg_values_supported,omitempty"`
	UserinfoEncryptionEncValuesSupported []string `json:"userinfo_encryption_enc_values_supported,omitempty"`
	DisplayValuesSupported               []string `json:"display_values_supported,omitempty"`
	ClaimTypesSupported                  []string `json:"claim_types_supported,omitempty"`
	ClaimsSupported                      []string `json:"claims_supported,omitempty"`
	ClaimsLocalesSupported               []string `json:"claims_locales_supported,omitempty"`
	ClaimsParameterSupported             bool     `json:"claims_parameter_supported,omitempty"`
	RequestParameterSupported            bool     `json:"request_parameter_supported,omitempty"`
	RequestURIParameterSupported         *bool    `json:"request_uri_parameter_supported,omitempty"`
	RequireRequestURIRegistration        bool     `json:"require_request_uri_registration,omitempty"`

	*OpenIDConnectRPInitiatedLogoutMetadata
	*OpenIDConnectBackChannelLogoutMetadata
	*OpenIDConnectFrontChannelLogoutMetadata
	*OpenIDConnectSessionManagementMetadata
	*OpenIDConnectPromptCreateMetadata
	*OpenIDConnectNativeSSOMetadata
	*OpenIDConnectCIBAMetadata
	*OpenIDGrantManagementMetadata
	*OpenIDConnectIdentityAssuranceMetadata
	*OpenIDConnectAdvancedSyntaxForClaimsMetadata
	*OpenID4VPMetadata
}
