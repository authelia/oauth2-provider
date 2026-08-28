// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package consts

// Client registration response parameters.
//
// See https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.1 and
// https://datatracker.ietf.org/doc/html/rfc7592#section-3.
const (
	ClientRegistrationResponseClientID                = "client_id"
	ClientRegistrationResponseClientSecret            = "client_secret" //nolint:gosec // This is a parameter name, not a credential.
	ClientRegistrationResponseClientIDIssuedAt        = "client_id_issued_at"
	ClientRegistrationResponseClientSecretExpiresAt   = "client_secret_expires_at" //nolint:gosec // This is a parameter name, not a credential.
	ClientRegistrationResponseRegistrationAccessToken = "registration_access_token"
	ClientRegistrationResponseRegistrationClientURI   = "registration_client_uri"
)

// Client metadata parameters validated by name.
//
// See https://datatracker.ietf.org/doc/html/rfc7591#section-2 and
// https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata.
const (
	ClientMetadataRedirectURIs                 = "redirect_uris"
	ClientMetadataGrantTypes                   = "grant_types"
	ClientMetadataResponseTypes                = "response_types"
	ClientMetadataScope                        = valueScope
	ClientMetadataJSONWebKeys                  = "jwks"
	ClientMetadataJSONWebKeysURI               = "jwks_uri"
	ClientMetadataApplicationType              = "application_type"
	ClientMetadataSectorIdentifierURI          = "sector_identifier_uri"
	ClientMetadataRequestURIs                  = "request_uris"
	ClientMetadataBackChannelLogoutURI         = "backchannel_logout_uri"
	ClientMetadataPostLogoutRedirectURIs       = "post_logout_redirect_uris"
	ClientMetadataSubjectType                  = "subject_type"
	ClientMetadataInitiateLoginURI             = "initiate_login_uri"
	ClientMetadataSoftwareStatement            = "software_statement"
	ClientMetadataTokenEndpointAuthAlg         = "token_endpoint_auth_signing_alg"
	ClientMetadataIDTokenSignedResponseAlg     = "id_token_signed_response_alg"
	ClientMetadataIDTokenEncryptedResponseAlg  = "id_token_encrypted_response_alg"
	ClientMetadataIDTokenEncryptedResponseEnc  = "id_token_encrypted_response_enc"
	ClientMetadataUserinfoSignedResponseAlg    = "userinfo_signed_response_alg"
	ClientMetadataUserinfoEncryptedResponseAlg = "userinfo_encrypted_response_alg"
	ClientMetadataUserinfoEncryptedResponseEnc = "userinfo_encrypted_response_enc"
	ClientMetadataRequestObjectSigningAlg      = "request_object_signing_alg"
	ClientMetadataRequestObjectEncryptionAlg   = "request_object_encryption_alg"
	ClientMetadataRequestObjectEncryptionEnc   = "request_object_encryption_enc"
	ClientMetadataIntrospectionEndpointAuthAlg = "introspection_endpoint_auth_signing_alg"
	ClientMetadataRevocationEndpointAuthAlg    = "revocation_endpoint_auth_signing_alg"
)

// Client metadata parameters naming a client authentication method, validated by name.
const (
	ClientMetadataTokenEndpointAuthMethod         = "token_endpoint_auth_method"
	ClientMetadataIntrospectionEndpointAuthMethod = "introspection_endpoint_auth_method"
	ClientMetadataRevocationEndpointAuthMethod    = "revocation_endpoint_auth_method"
)

// RFC 8705 client metadata parameters validated by name.
//
// See https://datatracker.ietf.org/doc/html/rfc8705#section-2.1.2.
const (
	ClientMetadataTLSClientAuthSubjectDN = "tls_client_auth_subject_dn"
	ClientMetadataTLSClientAuthSANDNS    = "tls_client_auth_san_dns"
	ClientMetadataTLSClientAuthSANURI    = "tls_client_auth_san_uri"
	ClientMetadataTLSClientAuthSANIP     = "tls_client_auth_san_ip"
	ClientMetadataTLSClientAuthSANEmail  = "tls_client_auth_san_email"
)

// Client metadata 'application_type' values.
//
// See https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata.
const (
	ApplicationTypeWeb    = "web"
	ApplicationTypeNative = "native"
)

// Client metadata 'subject_type' values.
const (
	SubjectTypePublic   = "public"
	SubjectTypePairwise = "pairwise"
)
