// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"time"

	"github.com/go-jose/go-jose/v4"
)

// DefaultRegisteredClient is a Client implementation capable of holding every client metadata value defined by
// OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591), OAuth 2.0 Dynamic Client Registration Management
// Protocol (RFC 7592), and OpenID Connect Dynamic Client Registration 1.0. It is the concrete client type produced
// by dynamic client registration; see ClientRegistrationMetadata for the wire format this type is populated from.
type DefaultRegisteredClient struct {
	*DefaultClient

	// ClientIDIssuedAt is the time at which the client identifier was issued. It is registration bookkeeping, not
	// client metadata.
	ClientIDIssuedAt time.Time

	// ClientSecretExpiresAt is the time at which the client secret will expire, or the zero value if it does not
	// expire. It is registration bookkeeping, not client metadata.
	ClientSecretExpiresAt time.Time

	// RFC 7591 Section 2 (OAuth 2.0 Dynamic Client Registration Protocol) client metadata not already covered by
	// DefaultClient.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc7591#section-2

	TokenEndpointAuthMethod string              `json:"token_endpoint_auth_method"`
	ClientName              string              `json:"client_name"`
	ClientURI               string              `json:"client_uri"`
	LogoURI                 string              `json:"logo_uri"`
	Contacts                []string            `json:"contacts"`
	TOSURI                  string              `json:"tos_uri"`
	PolicyURI               string              `json:"policy_uri"`
	JSONWebKeysURI          string              `json:"jwks_uri"`
	JSONWebKeys             *jose.JSONWebKeySet `json:"jwks"`
	SoftwareID              string              `json:"software_id"`
	SoftwareStatement       string              `json:"software_statement"`
	SoftwareVersion         string              `json:"software_version"`

	// OpenID Connect Dynamic Client Registration 1.0 Section 2 client metadata not already covered by DefaultClient.
	//
	// See: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata

	ApplicationType              string   `json:"application_type"`
	SectorIdentifierURI          string   `json:"sector_identifier_uri"`
	SubjectType                  string   `json:"subject_type"`
	IDTokenSignedResponseAlg     string   `json:"id_token_signed_response_alg"`
	IDTokenEncryptedResponseAlg  string   `json:"id_token_encrypted_response_alg"`
	IDTokenEncryptedResponseEnc  string   `json:"id_token_encrypted_response_enc"`
	UserinfoSignedResponseAlg    string   `json:"userinfo_signed_response_alg"`
	UserinfoEncryptedResponseAlg string   `json:"userinfo_encrypted_response_alg"`
	UserinfoEncryptedResponseEnc string   `json:"userinfo_encrypted_response_enc"`
	RequestObjectSigningAlg      string   `json:"request_object_signing_alg"`
	RequestObjectEncryptionAlg   string   `json:"request_object_encryption_alg"`
	RequestObjectEncryptionEnc   string   `json:"request_object_encryption_enc"`
	TokenEndpointAuthSigningAlg  string   `json:"token_endpoint_auth_signing_alg"`
	DefaultMaxAge                int64    `json:"default_max_age"`
	RequireAuthTime              bool     `json:"require_auth_time"`
	DefaultACRValues             []string `json:"default_acr_values"`
	InitiateLoginURI             string   `json:"initiate_login_uri"`
	RequestURIs                  []string `json:"request_uris"`

	// Values this codebase already models on its own client interfaces (see client.go), not already covered by
	// DefaultClient.

	IDTokenSignedResponseKeyID                       string             `json:"id_token_signed_response_kid"`
	IDTokenEncryptedResponseKeyID                    string             `json:"id_token_encrypted_response_kid"`
	UserinfoSignedResponseKeyID                      string             `json:"userinfo_signed_response_kid"`
	UserinfoEncryptedResponseKeyID                   string             `json:"userinfo_encrypted_response_kid"`
	RequestObjectSigningKeyID                        string             `json:"request_object_signing_kid"`
	RequestObjectEncryptionKeyID                     string             `json:"request_object_encryption_kid"`
	AuthorizationSignedResponseKeyID                 string             `json:"authorization_signed_response_kid"`
	AuthorizationSignedResponseAlg                   string             `json:"authorization_signed_response_alg"`
	AuthorizationEncryptedResponseKeyID              string             `json:"authorization_encrypted_response_kid"`
	AuthorizationEncryptedResponseAlg                string             `json:"authorization_encrypted_response_alg"`
	AuthorizationEncryptedResponseEnc                string             `json:"authorization_encrypted_response_enc"`
	IntrospectionSignedResponseKeyID                 string             `json:"introspection_signed_response_kid"`
	IntrospectionSignedResponseAlg                   string             `json:"introspection_signed_response_alg"`
	IntrospectionEncryptedResponseKeyID              string             `json:"introspection_encrypted_response_kid"`
	IntrospectionEncryptedResponseAlg                string             `json:"introspection_encrypted_response_alg"`
	IntrospectionEncryptedResponseEnc                string             `json:"introspection_encrypted_response_enc"`
	AccessTokenSignedResponseKeyID                   string             `json:"access_token_signed_response_kid"`
	AccessTokenSignedResponseAlg                     string             `json:"access_token_signed_response_alg"`
	AccessTokenEncryptedResponseKeyID                string             `json:"access_token_encrypted_response_kid"`
	AccessTokenEncryptedResponseAlg                  string             `json:"access_token_encrypted_response_alg"`
	AccessTokenEncryptedResponseEnc                  string             `json:"access_token_encrypted_response_enc"`
	IntrospectionEndpointAuthMethod                  string             `json:"introspection_endpoint_auth_method"`
	IntrospectionEndpointAuthSigningAlg              string             `json:"introspection_endpoint_auth_signing_alg"`
	RevocationEndpointAuthMethod                     string             `json:"revocation_endpoint_auth_method"`
	RevocationEndpointAuthSigningAlg                 string             `json:"revocation_endpoint_auth_signing_alg"`
	PushedAuthorizationRequestEndpointAuthMethod     string             `json:"pushed_authorization_request_endpoint_auth_method"`
	PushedAuthorizationRequestEndpointAuthSigningAlg string             `json:"pushed_authorization_request_endpoint_auth_signing_alg"`
	RequirePushedAuthorizationRequests               bool               `json:"require_pushed_authorization_requests"`
	ResponseModes                                    []ResponseModeType `json:"response_modes"`

	// Client policy values which have no corresponding ClientRegistrationMetadata parameter because they are locally
	// administered rather than supplied by the registering client.

	EnableJWTProfileOAuthAccessTokens bool          `json:"-"`
	EnforcePKCE                       bool          `json:"-"`
	EnforcePKCEChallengeMethod        bool          `json:"-"`
	PKCEChallengeMethod               string        `json:"-"`
	PushedAuthorizeContextLifespan    time.Duration `json:"-"`

	// Extra holds every unregistered client metadata parameter carried by ClientRegistrationMetadata.Extra so it can
	// survive a registration round trip. This type only provides the storage location; converting to and from
	// ClientRegistrationMetadata.Extra is not this type's responsibility.
	Extra map[string]any `json:"-"`
}

func (c *DefaultRegisteredClient) GetJSONWebKeysURI() string {
	return c.JSONWebKeysURI
}

func (c *DefaultRegisteredClient) GetJSONWebKeys() *jose.JSONWebKeySet {
	return c.JSONWebKeys
}

func (c *DefaultRegisteredClient) GetRequestObjectSigningKeyID() string {
	return c.RequestObjectSigningKeyID
}

func (c *DefaultRegisteredClient) GetRequestObjectSigningAlg() string {
	return c.RequestObjectSigningAlg
}

func (c *DefaultRegisteredClient) GetRequestObjectEncryptionKeyID() string {
	return c.RequestObjectEncryptionKeyID
}

func (c *DefaultRegisteredClient) GetRequestObjectEncryptionAlg() string {
	return c.RequestObjectEncryptionAlg
}

func (c *DefaultRegisteredClient) GetRequestObjectEncryptionEnc() string {
	return c.RequestObjectEncryptionEnc
}

func (c *DefaultRegisteredClient) GetRequestURIs() []string {
	return c.RequestURIs
}

func (c *DefaultRegisteredClient) GetIDTokenSignedResponseKeyID() string {
	return c.IDTokenSignedResponseKeyID
}

// GetIDTokenSignedResponseAlg returns the 'id_token_signed_response_alg' value, defaulting to RS256 when unset per
// OpenID Connect Dynamic Client Registration 1.0's stated default.
func (c *DefaultRegisteredClient) GetIDTokenSignedResponseAlg() string {
	if c.IDTokenSignedResponseAlg == "" {
		return "RS256"
	}

	return c.IDTokenSignedResponseAlg
}

func (c *DefaultRegisteredClient) GetIDTokenEncryptedResponseKeyID() string {
	return c.IDTokenEncryptedResponseKeyID
}

func (c *DefaultRegisteredClient) GetIDTokenEncryptedResponseAlg() string {
	return c.IDTokenEncryptedResponseAlg
}

func (c *DefaultRegisteredClient) GetIDTokenEncryptedResponseEnc() string {
	return c.IDTokenEncryptedResponseEnc
}

func (c *DefaultRegisteredClient) GetUserinfoSignedResponseKeyID() string {
	return c.UserinfoSignedResponseKeyID
}

func (c *DefaultRegisteredClient) GetUserinfoSignedResponseAlg() string {
	return c.UserinfoSignedResponseAlg
}

func (c *DefaultRegisteredClient) GetUserinfoEncryptedResponseKeyID() string {
	return c.UserinfoEncryptedResponseKeyID
}

func (c *DefaultRegisteredClient) GetUserinfoEncryptedResponseAlg() string {
	return c.UserinfoEncryptedResponseAlg
}

func (c *DefaultRegisteredClient) GetUserinfoEncryptedResponseEnc() string {
	return c.UserinfoEncryptedResponseEnc
}

func (c *DefaultRegisteredClient) GetAuthorizationSignedResponseKeyID() string {
	return c.AuthorizationSignedResponseKeyID
}

func (c *DefaultRegisteredClient) GetAuthorizationSignedResponseAlg() string {
	return c.AuthorizationSignedResponseAlg
}

func (c *DefaultRegisteredClient) GetAuthorizationEncryptedResponseKeyID() string {
	return c.AuthorizationEncryptedResponseKeyID
}

func (c *DefaultRegisteredClient) GetAuthorizationEncryptedResponseAlg() string {
	return c.AuthorizationEncryptedResponseAlg
}

func (c *DefaultRegisteredClient) GetAuthorizationEncryptedResponseEnc() string {
	return c.AuthorizationEncryptedResponseEnc
}

// GetTokenEndpointAuthMethod returns the 'token_endpoint_auth_method' value, defaulting to client_secret_basic when
// unset per OpenID Connect Dynamic Client Registration 1.0 Section 2.
func (c *DefaultRegisteredClient) GetTokenEndpointAuthMethod() string {
	if c.TokenEndpointAuthMethod == "" {
		return "client_secret_basic"
	}

	return c.TokenEndpointAuthMethod
}

func (c *DefaultRegisteredClient) GetTokenEndpointAuthSigningAlg() string {
	return c.TokenEndpointAuthSigningAlg
}

func (c *DefaultRegisteredClient) GetIntrospectionEndpointAuthMethod() string {
	return c.IntrospectionEndpointAuthMethod
}

func (c *DefaultRegisteredClient) GetIntrospectionEndpointAuthSigningAlg() string {
	return c.IntrospectionEndpointAuthSigningAlg
}

func (c *DefaultRegisteredClient) GetRevocationEndpointAuthMethod() string {
	return c.RevocationEndpointAuthMethod
}

func (c *DefaultRegisteredClient) GetRevocationEndpointAuthSigningAlg() string {
	return c.RevocationEndpointAuthSigningAlg
}

func (c *DefaultRegisteredClient) GetPushedAuthorizationRequestEndpointAuthMethod() string {
	return c.PushedAuthorizationRequestEndpointAuthMethod
}

func (c *DefaultRegisteredClient) GetPushedAuthorizationRequestEndpointAuthSigningAlg() string {
	return c.PushedAuthorizationRequestEndpointAuthSigningAlg
}

func (c *DefaultRegisteredClient) GetResponseModes() []ResponseModeType {
	return c.ResponseModes
}

func (c *DefaultRegisteredClient) GetAccessTokenSignedResponseKeyID() string {
	return c.AccessTokenSignedResponseKeyID
}

func (c *DefaultRegisteredClient) GetAccessTokenSignedResponseAlg() string {
	return c.AccessTokenSignedResponseAlg
}

func (c *DefaultRegisteredClient) GetAccessTokenEncryptedResponseKeyID() string {
	return c.AccessTokenEncryptedResponseKeyID
}

func (c *DefaultRegisteredClient) GetAccessTokenEncryptedResponseAlg() string {
	return c.AccessTokenEncryptedResponseAlg
}

func (c *DefaultRegisteredClient) GetAccessTokenEncryptedResponseEnc() string {
	return c.AccessTokenEncryptedResponseEnc
}

func (c *DefaultRegisteredClient) GetEnableJWTProfileOAuthAccessTokens() bool {
	return c.EnableJWTProfileOAuthAccessTokens
}

func (c *DefaultRegisteredClient) GetIntrospectionSignedResponseKeyID() string {
	return c.IntrospectionSignedResponseKeyID
}

func (c *DefaultRegisteredClient) GetIntrospectionSignedResponseAlg() string {
	return c.IntrospectionSignedResponseAlg
}

func (c *DefaultRegisteredClient) GetIntrospectionEncryptedResponseKeyID() string {
	return c.IntrospectionEncryptedResponseKeyID
}

func (c *DefaultRegisteredClient) GetIntrospectionEncryptedResponseAlg() string {
	return c.IntrospectionEncryptedResponseAlg
}

func (c *DefaultRegisteredClient) GetIntrospectionEncryptedResponseEnc() string {
	return c.IntrospectionEncryptedResponseEnc
}

func (c *DefaultRegisteredClient) GetEnforcePKCE() bool {
	return c.EnforcePKCE
}

func (c *DefaultRegisteredClient) GetEnforcePKCEChallengeMethod() bool {
	return c.EnforcePKCEChallengeMethod
}

func (c *DefaultRegisteredClient) GetPKCEChallengeMethod() string {
	return c.PKCEChallengeMethod
}

func (c *DefaultRegisteredClient) GetRequirePushedAuthorizationRequests() bool {
	return c.RequirePushedAuthorizationRequests
}

func (c *DefaultRegisteredClient) GetPushedAuthorizeContextLifespan() time.Duration {
	return c.PushedAuthorizeContextLifespan
}

var (
	_ Client                           = (*DefaultRegisteredClient)(nil)
	_ RotatedClientSecretsClient       = (*DefaultRegisteredClient)(nil)
	_ JSONWebKeysClient                = (*DefaultRegisteredClient)(nil)
	_ JARClient                        = (*DefaultRegisteredClient)(nil)
	_ IDTokenClient                    = (*DefaultRegisteredClient)(nil)
	_ UserInfoClient                   = (*DefaultRegisteredClient)(nil)
	_ JARMClient                       = (*DefaultRegisteredClient)(nil)
	_ AuthenticationMethodClient       = (*DefaultRegisteredClient)(nil)
	_ ResponseModeClient               = (*DefaultRegisteredClient)(nil)
	_ DPoPClient                       = (*DefaultRegisteredClient)(nil)
	_ JWTProfileClient                 = (*DefaultRegisteredClient)(nil)
	_ IntrospectionJWTResponseClient   = (*DefaultRegisteredClient)(nil)
	_ ProofKeyCodeExchangeClient       = (*DefaultRegisteredClient)(nil)
	_ PushedAuthorizationRequestClient = (*DefaultRegisteredClient)(nil)
)
