// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

// RFC8705MutualTLSEndpointAliases is the RFC 8705 Section 5 'mtls_endpoint_aliases' object, which maps endpoint
// metadata names to the absolute URLs a mutual TLS client uses instead.
//
// See: https://datatracker.ietf.org/doc/html/rfc8705#section-5
type RFC8705MutualTLSEndpointAliases struct {
	Token                      string `json:"token_endpoint,omitempty"`
	Revocation                 string `json:"revocation_endpoint,omitempty"`
	Introspection              string `json:"introspection_endpoint,omitempty"`
	DeviceAuthorization        string `json:"device_authorization_endpoint,omitempty"`
	PushedAuthorizationRequest string `json:"pushed_authorization_request_endpoint,omitempty"`
	UserInfo                   string `json:"userinfo_endpoint,omitempty"`
	Registration               string `json:"registration_endpoint,omitempty"`
	EndSession                 string `json:"end_session_endpoint,omitempty"`
	BackChannelAuthentication  string `json:"backchannel_authentication_endpoint,omitempty"`
}

// RFC8628DeviceAuthorizationMetadata is the OAuth 2.0 Device Authorization Grant metadata.
//
// See: https://datatracker.ietf.org/doc/html/rfc8628#section-4
type RFC8628DeviceAuthorizationMetadata struct {
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint,omitempty"`
}

// RFC8705MutualTLSMetadata is the OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens
// metadata.
//
// See: https://datatracker.ietf.org/doc/html/rfc8705#section-3.3
//
// See: https://datatracker.ietf.org/doc/html/rfc8705#section-5
type RFC8705MutualTLSMetadata struct {
	TLSClientCertificateBoundAccessTokens bool                             `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	MutualTLSEndpointAliases              *RFC8705MutualTLSEndpointAliases `json:"mtls_endpoint_aliases,omitempty"`
}

// RFC9101JWTSecuredAuthorizationRequestMetadata is the JWT-Secured Authorization Request metadata. It appears in both
// the OAuth 2.0 Authorization Server Metadata and the OpenID Provider Metadata.
//
// See: https://datatracker.ietf.org/doc/html/rfc9101#section-10.5
// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
type RFC9101JWTSecuredAuthorizationRequestMetadata struct {
	RequestObjectSigningAlgValuesSupported    []string `json:"request_object_signing_alg_values_supported,omitempty"`
	RequestObjectEncryptionAlgValuesSupported []string `json:"request_object_encryption_alg_values_supported,omitempty"`
	RequestObjectEncryptionEncValuesSupported []string `json:"request_object_encryption_enc_values_supported,omitempty"`
	RequireSignedRequestObject                bool     `json:"require_signed_request_object,omitempty"`
}

// RFC9126PushedAuthorizationRequestMetadata is the OAuth 2.0 Pushed Authorization Requests metadata.
//
// See: https://datatracker.ietf.org/doc/html/rfc9126#section-5
type RFC9126PushedAuthorizationRequestMetadata struct {
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint,omitempty"`
	RequirePushedAuthorizationRequests bool   `json:"require_pushed_authorization_requests,omitempty"`
}

// RFC9207AuthorizationServerIssuerIdentificationMetadata is the OAuth 2.0 Authorization Server Issuer Identification
// metadata.
//
// See: https://datatracker.ietf.org/doc/html/rfc9207#section-3
type RFC9207AuthorizationServerIssuerIdentificationMetadata struct {
	AuthorizationResponseISSParameterSupported bool `json:"authorization_response_iss_parameter_supported,omitempty"`
}

// RFC9396RichAuthorizationRequestsMetadata is the OAuth 2.0 Rich Authorization Requests metadata.
//
// See: https://datatracker.ietf.org/doc/html/rfc9396#section-10
type RFC9396RichAuthorizationRequestsMetadata struct {
	AuthorizationDetailsTypesSupported []string `json:"authorization_details_types_supported,omitempty"`
}

// RFC9449DPoPMetadata is the OAuth 2.0 Demonstrating Proof of Possession metadata.
//
// See: https://datatracker.ietf.org/doc/html/rfc9449#section-5.1
type RFC9449DPoPMetadata struct {
	DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported,omitempty"`
}

// RFC9701JWTIntrospectionResponseMetadata is the JWT Response for OAuth Token Introspection metadata.
//
// See: https://datatracker.ietf.org/doc/html/rfc9701#section-7
type RFC9701JWTIntrospectionResponseMetadata struct {
	IntrospectionSigningAlgValuesSupported    []string `json:"introspection_signing_alg_values_supported,omitempty"`
	IntrospectionEncryptionAlgValuesSupported []string `json:"introspection_encryption_alg_values_supported,omitempty"`
	IntrospectionEncryptionEncValuesSupported []string `json:"introspection_encryption_enc_values_supported,omitempty"`
}

// RFC9728ProtectedResourceMetadata is the OAuth 2.0 Protected Resource Metadata authorization server metadata. It
// holds the authorization server metadata member, not the protected resource metadata document.
//
// See: https://datatracker.ietf.org/doc/html/rfc9728#section-4
type RFC9728ProtectedResourceMetadata struct {
	ProtectedResources []string `json:"protected_resources,omitempty"`
}

// DraftClientIDMetadataDocumentMetadata is the OAuth Client ID Metadata Document metadata.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-8
type DraftClientIDMetadataDocumentMetadata struct {
	ClientIDMetadataDocumentSupported bool `json:"client_id_metadata_document_supported,omitempty"`
}

// DraftIdentityChainingMetadata is the OAuth Identity and Authorization Chaining Across Domains metadata.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-chaining-17#section-3
type DraftIdentityChainingMetadata struct {
	IdentityChainingRequestedTokenTypesSupported []string `json:"identity_chaining_requested_token_types_supported,omitempty"`
}

// DraftIDJAGMetadata is the Identity Assertion Authorization Grant metadata.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-7
type DraftIDJAGMetadata struct {
	AuthorizationGrantProfilesSupported []string `json:"authorization_grant_profiles_supported,omitempty"`
	IDJAGSigningAlgValuesSupported      []string `json:"id_jag_signing_alg_values_supported,omitempty"`
}

// DraftStatusListMetadata is the Token Status List metadata.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-9.1
type DraftStatusListMetadata struct {
	StatusListAggregationEndpoint string `json:"status_list_aggregation_endpoint,omitempty"`
}

// DraftAttestationBasedClientAuthMetadata is the OAuth 2.0 Attestation-Based Client Authentication metadata.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-12#section-8
type DraftAttestationBasedClientAuthMetadata struct {
	ChallengeEndpoint                             string   `json:"challenge_endpoint,omitempty"`
	ClientAttestationSigningAlgValuesSupported    []string `json:"client_attestation_signing_alg_values_supported,omitempty"`
	ClientAttestationPoPSigningAlgValuesSupported []string `json:"client_attestation_pop_signing_alg_values_supported,omitempty"`
	ClientAttestationPoPMethodsSupported          []string `json:"client_attestation_pop_methods_supported,omitempty"`
}

// DraftFirstPartyAppsMetadata is the OAuth 2.0 for First-Party Applications metadata.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-first-party-apps-04#section-8
type DraftFirstPartyAppsMetadata struct {
	AuthorizationChallengeEndpoint string `json:"authorization_challenge_endpoint,omitempty"`
}

// DraftRefreshTokenExpirationMetadata is the OAuth 2.0 Refresh Token Expiration metadata.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-refresh-token-expiration-03#section-8
type DraftRefreshTokenExpirationMetadata struct {
	RefreshTokenExpirationTypesSupported []string `json:"refresh_token_expiration_types_supported,omitempty"`
}

// DraftDeferredTokenResponseMetadata is the OAuth 2.0 Deferred Token Response metadata.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-deferred-token-response-01#section-5.1
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-deferred-token-response-01#section-8.4
type DraftDeferredTokenResponseMetadata struct {
	DeferredTokenResponseSupported             bool     `json:"deferred_token_response_supported,omitempty"`
	RevocationEndpointTokenTypeValuesSupported []string `json:"revocation_endpoint_token_type_values_supported,omitempty"`
}

// DraftRARMetadataRemediationMetadata is the Rich Authorization Requests Metadata and Remediation metadata.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rar-metadata-remediation-00#section-5
type DraftRARMetadataRemediationMetadata struct {
	AuthorizationDetailsTypesMetadataEndpoint string `json:"authorization_details_types_metadata_endpoint,omitempty"`
}

// DraftDPoPRequiredMetadata is the Authorization Server Metadata for DPoP-bound Access Tokens Required metadata.
//
// See: https://datatracker.ietf.org/doc/html/draft-emelia-oauth-as-metadata-dpop-required-00#section-3
type DraftDPoPRequiredMetadata struct {
	DPoPBoundAccessTokensRequired bool `json:"dpop_bound_access_tokens_required,omitempty"`
}

// DraftUserAuthorizationManagementMetadata is the User Authorization Management URI metadata.
//
// See: https://datatracker.ietf.org/doc/html/draft-emelia-oauth-user-authorization-mgmt-uri-00#section-3
type DraftUserAuthorizationManagementMetadata struct {
	UserAuthorizationManagementURI string `json:"user_authorization_management_uri,omitempty"`
}

// DraftAuthorityMetadata is the OAuth 2.0 Authority Metadata.
//
// See: https://datatracker.ietf.org/doc/html/draft-zehavi-oauth-authority-metadata-00#section-2.2
type DraftAuthorityMetadata struct {
	AuthorityMetadata map[string]any `json:"authority_metadata,omitempty"`
}
