// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"authelia.com/provider/jose"
)

// OpenIDConnectJARMMetadata is the JWT Secured Authorization Response Mode metadata.
//
// See: https://openid.net/specs/oauth-v2-jarm.html#section-4
type OpenIDConnectJARMMetadata struct {
	AuthorizationSigningAlgValuesSupported    []string `json:"authorization_signing_alg_values_supported,omitempty"`
	AuthorizationEncryptionAlgValuesSupported []string `json:"authorization_encryption_alg_values_supported,omitempty"`
	AuthorizationEncryptionEncValuesSupported []string `json:"authorization_encryption_enc_values_supported,omitempty"`
}

// OpenIDFederationMetadata is the OpenID Federation 1.0 metadata of an OpenID Provider or authorization server.
//
// See: https://openid.net/specs/openid-federation-1_0.html#section-5.1.3
type OpenIDFederationMetadata struct {
	ClientRegistrationTypesSupported []string            `json:"client_registration_types_supported,omitempty"`
	FederationRegistrationEndpoint   string              `json:"federation_registration_endpoint,omitempty"`
	SignedJWKSURI                    string              `json:"signed_jwks_uri,omitempty"`
	JWKS                             *jose.JSONWebKeySet `json:"jwks,omitempty"`
	OrganizationName                 string              `json:"organization_name,omitempty"`
	DisplayName                      string              `json:"display_name,omitempty"`
	Description                      string              `json:"description,omitempty"`
	Keywords                         []string            `json:"keywords,omitempty"`
	Contacts                         []string            `json:"contacts,omitempty"`
	LogoURI                          string              `json:"logo_uri,omitempty"`
	InformationURI                   string              `json:"information_uri,omitempty"`
	OrganizationURI                  string              `json:"organization_uri,omitempty"`
	PolicyURI                        string              `json:"policy_uri,omitempty"`
}

// OpenID4VCIMetadata is the OpenID for Verifiable Credential Issuance 1.0 authorization server metadata.
//
// See: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.3
type OpenID4VCIMetadata struct {
	PreAuthorizedGrantAnonymousAccessSupported bool `json:"pre-authorized_grant_anonymous_access_supported,omitempty"`
}

// OpenIDConnectRPInitiatedLogoutMetadata is the OpenID Connect RP-Initiated Logout 1.0 metadata.
//
// See: https://openid.net/specs/openid-connect-rpinitiated-1_0.html#OPMetadata
type OpenIDConnectRPInitiatedLogoutMetadata struct {
	EndSessionEndpoint string `json:"end_session_endpoint,omitempty"`
}

// OpenIDConnectBackChannelLogoutMetadata is the OpenID Connect Back-Channel Logout 1.0 metadata.
//
// See: https://openid.net/specs/openid-connect-backchannel-1_0.html#BCSupport
type OpenIDConnectBackChannelLogoutMetadata struct {
	BackChannelLogoutSupported        bool `json:"backchannel_logout_supported,omitempty"`
	BackChannelLogoutSessionSupported bool `json:"backchannel_logout_session_supported,omitempty"`
}

// OpenIDConnectFrontChannelLogoutMetadata is the OpenID Connect Front-Channel Logout 1.0 metadata.
//
// See: https://openid.net/specs/openid-connect-frontchannel-1_0.html#OPLogout
type OpenIDConnectFrontChannelLogoutMetadata struct {
	FrontChannelLogoutSupported        bool `json:"frontchannel_logout_supported,omitempty"`
	FrontChannelLogoutSessionSupported bool `json:"frontchannel_logout_session_supported,omitempty"`
}

// OpenIDConnectSessionManagementMetadata is the OpenID Connect Session Management 1.0 metadata.
//
// See: https://openid.net/specs/openid-connect-session-1_0.html#OPMetadata
type OpenIDConnectSessionManagementMetadata struct {
	CheckSessionIFrame string `json:"check_session_iframe,omitempty"`
}

// OpenIDConnectPromptCreateMetadata is the Initiating User Registration via OpenID Connect 1.0 metadata.
//
// See: https://openid.net/specs/openid-connect-prompt-create-1_0.html#section-4.1
type OpenIDConnectPromptCreateMetadata struct {
	PromptValuesSupported []string `json:"prompt_values_supported,omitempty"`
}

// OpenIDConnectNativeSSOMetadata is the OpenID Connect Native SSO for Mobile Apps 1.0 draft 07 metadata.
//
// See: https://openid.net/specs/openid-connect-native-sso-1_0-07.html#section-5
type OpenIDConnectNativeSSOMetadata struct {
	NativeSSOSupported bool `json:"native_sso_supported,omitempty"`
}

// OpenIDConnectCIBAMetadata is the OpenID Connect Client-Initiated Backchannel Authentication Core 1.0 metadata.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4
type OpenIDConnectCIBAMetadata struct {
	BackChannelTokenDeliveryModesSupported                    []string `json:"backchannel_token_delivery_modes_supported,omitempty"`
	BackChannelAuthenticationEndpoint                         string   `json:"backchannel_authentication_endpoint,omitempty"`
	BackChannelAuthenticationRequestSigningAlgValuesSupported []string `json:"backchannel_authentication_request_signing_alg_values_supported,omitempty"`
	BackChannelUserCodeParameterSupported                     bool     `json:"backchannel_user_code_parameter_supported,omitempty"`
}

// OpenIDGrantManagementMetadata is the OpenID Grant Management for OAuth 2.0 ID1 metadata.
//
// See: https://openid.net/specs/oauth-v2-grant-management-ID1.html#section-7.1
type OpenIDGrantManagementMetadata struct {
	GrantManagementActionsSupported []string `json:"grant_management_actions_supported,omitempty"`
	GrantManagementEndpoint         string   `json:"grant_management_endpoint,omitempty"`
	GrantManagementActionRequired   bool     `json:"grant_management_action_required,omitempty"`
}

// OpenIDConnectIdentityAssuranceMetadata is the OpenID Connect for Identity Assurance 1.0 metadata.
//
// See: https://openid.net/specs/openid-connect-4-identity-assurance-1_0-final.html#section-8
type OpenIDConnectIdentityAssuranceMetadata struct {
	TrustFrameworksSupported        []string `json:"trust_frameworks_supported,omitempty"`
	ClaimsInVerifiedClaimsSupported []string `json:"claims_in_verified_claims_supported,omitempty"`
	EvidenceSupported               []string `json:"evidence_supported,omitempty"`
	DocumentsSupported              []string `json:"documents_supported,omitempty"`
	DocumentsMethodsSupported       []string `json:"documents_methods_supported,omitempty"`
	DocumentsCheckMethodsSupported  []string `json:"documents_check_methods_supported,omitempty"`
	ElectronicRecordsSupported      []string `json:"electronic_records_supported,omitempty"`
}

// OpenIDConnectAdvancedSyntaxForClaimsMetadata is the OpenID Connect Advanced Syntax for Claims draft 02 metadata.
//
// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0-02.html#section-7.3
//
// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0-02.html#section-8.6
type OpenIDConnectAdvancedSyntaxForClaimsMetadata struct {
	SelectiveAbortOmitSupported         bool           `json:"selective_abort_omit_supported,omitempty"`
	SelectiveAbortOmitSchemaSupported   *bool          `json:"selective_abort_omit_schema_supported,omitempty"`
	TransformedClaimsFunctionsSupported []string       `json:"transformed_claims_functions_supported,omitempty"`
	TransformedClaimsPredefined         map[string]any `json:"transformed_claims_predefined,omitempty"`
	TransformedClaimsMaxDepth           *int           `json:"transformed_claims_max_depth,omitempty"`
	TransformedClaimsMaxCount           *int           `json:"transformed_claims_max_count,omitempty"`
}

// OpenID4VPMetadata is the OpenID for Verifiable Presentations 1.0 authorization server metadata.
//
// See: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-10
type OpenID4VPMetadata struct {
	VPFormatsSupported        map[string]any `json:"vp_formats_supported,omitempty"`
	ClientIDPrefixesSupported []string       `json:"client_id_prefixes_supported,omitempty"`
}
