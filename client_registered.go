// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"slices"
	"time"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2/internal/consts"
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
	DefaultMaxAge                *int64   `json:"default_max_age,omitempty"`
	RequireAuthTime              bool     `json:"require_auth_time"`
	DefaultACRValues             []string `json:"default_acr_values"`
	InitiateLoginURI             string   `json:"initiate_login_uri"`
	RequestURIs                  []string `json:"request_uris"`

	// RFC 8693 (OAuth 2.0 Token Exchange) restrictions. An empty value applies no restriction.
	TokenExchangeSubjectTokenTypes  []string `json:"token_exchange_subject_token_types"`
	TokenExchangeActorTokenTypes    []string `json:"token_exchange_actor_token_types"`
	TokenExchangeRequestTokenTypes  []string `json:"token_exchange_request_token_types"`
	TokenExchangePermittedClientIDs []string `json:"token_exchange_permitted_client_ids"`

	// AuthorizationGrantProfilesSupported is the advisory list of authorization grant profiles the client implements.
	AuthorizationGrantProfilesSupported []string `json:"authorization_grant_profiles_supported"`

	// RFC 9101 Section 10.5 (JWT-Secured Authorization Request) client metadata.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc9101#section-10.5

	RequireSignedRequestObject bool `json:"require_signed_request_object"`

	// RFC 9396 Section 10 (Rich Authorization Requests) client metadata. A nil value permits every type and a non-nil
	// empty value permits none.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9396#section-10

	AuthorizationDetailsTypes []string `json:"authorization_details_types"`

	// OpenID Connect RP-Initiated Logout 1.0 and OpenID Connect Back-Channel Logout 1.0 client metadata.
	//
	// See: https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ClientMetadata
	// See: https://openid.net/specs/openid-connect-backchannel-1_0.html#ClientMetadata

	PostLogoutRedirectURIs           []string `json:"post_logout_redirect_uris"`
	BackChannelLogoutURI             string   `json:"backchannel_logout_uri"`
	BackChannelLogoutSessionRequired bool     `json:"backchannel_logout_session_required"`

	// RFC 8705 Section 2.1.2 (Mutual-TLS Client Authentication) client metadata. A client registering the
	// 'tls_client_auth' method registers exactly one of these subject values. The
	// 'tls_client_certificate_bound_access_tokens' value of Section 3.4 is carried by the embedded DefaultClient.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc8705#section-2.1.2

	TLSClientAuthSubjectDN string `json:"tls_client_auth_subject_dn"`
	TLSClientAuthSANDNS    string `json:"tls_client_auth_san_dns"`
	TLSClientAuthSANURI    string `json:"tls_client_auth_san_uri"`
	TLSClientAuthSANIP     string `json:"tls_client_auth_san_ip"`
	TLSClientAuthSANEmail  string `json:"tls_client_auth_san_email"`

	// Values this codebase already models on its own client interfaces (see client.go), not already covered by
	// DefaultClient.

	IDTokenSignedResponseKeyID          string             `json:"id_token_signed_response_kid"`
	IDTokenEncryptedResponseKeyID       string             `json:"id_token_encrypted_response_kid"`
	UserinfoSignedResponseKeyID         string             `json:"userinfo_signed_response_kid"`
	UserinfoEncryptedResponseKeyID      string             `json:"userinfo_encrypted_response_kid"`
	RequestObjectSigningKeyID           string             `json:"request_object_signing_kid"`
	RequestObjectEncryptionKeyID        string             `json:"request_object_encryption_kid"`
	AuthorizationSignedResponseKeyID    string             `json:"authorization_signed_response_kid"`
	AuthorizationSignedResponseAlg      string             `json:"authorization_signed_response_alg"`
	AuthorizationEncryptedResponseKeyID string             `json:"authorization_encrypted_response_kid"`
	AuthorizationEncryptedResponseAlg   string             `json:"authorization_encrypted_response_alg"`
	AuthorizationEncryptedResponseEnc   string             `json:"authorization_encrypted_response_enc"`
	IntrospectionSignedResponseKeyID    string             `json:"introspection_signed_response_kid"`
	IntrospectionSignedResponseAlg      string             `json:"introspection_signed_response_alg"`
	IntrospectionEncryptedResponseKeyID string             `json:"introspection_encrypted_response_kid"`
	IntrospectionEncryptedResponseAlg   string             `json:"introspection_encrypted_response_alg"`
	IntrospectionEncryptedResponseEnc   string             `json:"introspection_encrypted_response_enc"`
	AccessTokenSignedResponseKeyID      string             `json:"access_token_signed_response_kid"`
	AccessTokenSignedResponseAlg        string             `json:"access_token_signed_response_alg"`
	AccessTokenEncryptedResponseKeyID   string             `json:"access_token_encrypted_response_kid"`
	AccessTokenEncryptedResponseAlg     string             `json:"access_token_encrypted_response_alg"`
	AccessTokenEncryptedResponseEnc     string             `json:"access_token_encrypted_response_enc"`
	IntrospectionEndpointAuthMethod     string             `json:"introspection_endpoint_auth_method"`
	IntrospectionEndpointAuthSigningAlg string             `json:"introspection_endpoint_auth_signing_alg"`
	RevocationEndpointAuthMethod        string             `json:"revocation_endpoint_auth_method"`
	RevocationEndpointAuthSigningAlg    string             `json:"revocation_endpoint_auth_signing_alg"`
	RequirePushedAuthorizationRequests  bool               `json:"require_pushed_authorization_requests"`
	ResponseModes                       []ResponseModeType `json:"response_modes"`

	// Client policy values which have no corresponding ClientRegistrationMetadata parameter because they are locally
	// administered rather than supplied by the registering client.

	EnableJWTProfileOAuthAccessTokens bool          `json:"-"`
	EnforcePKCE                       bool          `json:"-"`
	EnforcePKCEChallengeMethod        bool          `json:"-"`
	PKCEChallengeMethod               string        `json:"-"`
	PushedAuthorizeContextLifespan    time.Duration `json:"-"`

	RequireRedirectURIPushedAuthorizationRequests bool          `json:"-"`
	RequireRequestObjectAudienceAndLifetime       bool          `json:"-"`
	RequestObjectMaximumLifetime                  time.Duration `json:"-"`
	DisableRefreshTokenRotation                   bool          `json:"-"`

	// Extra holds every unregistered client metadata parameter carried by ClientRegistrationMetadata.Extra so it can
	// survive a registration round trip. This type only provides the storage location; converting to and from
	// ClientRegistrationMetadata.Extra is not this type's responsibility.
	Extra map[string]any `json:"-"`
}

// GetJSONWebKeysURI returns the 'jwks_uri' client metadata value.
func (c *DefaultRegisteredClient) GetJSONWebKeysURI() string {
	return c.JSONWebKeysURI
}

// GetJSONWebKeys returns the 'jwks' client metadata value.
func (c *DefaultRegisteredClient) GetJSONWebKeys() *jose.JSONWebKeySet {
	return c.JSONWebKeys
}

// GetRequireSignedRequestObject returns the 'require_signed_request_object' client metadata value.
func (c *DefaultRegisteredClient) GetRequireSignedRequestObject() bool {
	return c.RequireSignedRequestObject
}

// GetRequestObjectSigningKeyID returns the 'request_object_signing_kid' client metadata value.
func (c *DefaultRegisteredClient) GetRequestObjectSigningKeyID() string {
	return c.RequestObjectSigningKeyID
}

// GetRequestObjectSigningAlg returns the 'request_object_signing_alg' client metadata value.
func (c *DefaultRegisteredClient) GetRequestObjectSigningAlg() string {
	return c.RequestObjectSigningAlg
}

// GetRequestObjectEncryptionKeyID returns the 'request_object_encryption_kid' client metadata value.
func (c *DefaultRegisteredClient) GetRequestObjectEncryptionKeyID() string {
	return c.RequestObjectEncryptionKeyID
}

// GetRequestObjectEncryptionAlg returns the 'request_object_encryption_alg' client metadata value.
func (c *DefaultRegisteredClient) GetRequestObjectEncryptionAlg() string {
	return c.RequestObjectEncryptionAlg
}

// GetRequestObjectEncryptionEnc returns the 'request_object_encryption_enc' client metadata value.
func (c *DefaultRegisteredClient) GetRequestObjectEncryptionEnc() string {
	return c.RequestObjectEncryptionEnc
}

// GetRequestURIs returns the 'request_uris' client metadata value.
func (c *DefaultRegisteredClient) GetRequestURIs() []string {
	return c.RequestURIs
}

// GetIDTokenSignedResponseKeyID returns the 'id_token_signed_response_kid' client metadata value.
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

// GetIDTokenEncryptedResponseKeyID returns the 'id_token_encrypted_response_kid' client metadata value.
func (c *DefaultRegisteredClient) GetIDTokenEncryptedResponseKeyID() string {
	return c.IDTokenEncryptedResponseKeyID
}

// GetIDTokenEncryptedResponseAlg returns the 'id_token_encrypted_response_alg' client metadata value.
func (c *DefaultRegisteredClient) GetIDTokenEncryptedResponseAlg() string {
	return c.IDTokenEncryptedResponseAlg
}

// GetIDTokenEncryptedResponseEnc returns the 'id_token_encrypted_response_enc' client metadata value.
func (c *DefaultRegisteredClient) GetIDTokenEncryptedResponseEnc() string {
	return c.IDTokenEncryptedResponseEnc
}

// GetUserinfoSignedResponseKeyID returns the 'userinfo_signed_response_kid' client metadata value.
func (c *DefaultRegisteredClient) GetUserinfoSignedResponseKeyID() string {
	return c.UserinfoSignedResponseKeyID
}

// GetUserinfoSignedResponseAlg returns the 'userinfo_signed_response_alg' client metadata value.
func (c *DefaultRegisteredClient) GetUserinfoSignedResponseAlg() string {
	return c.UserinfoSignedResponseAlg
}

// GetUserinfoEncryptedResponseKeyID returns the 'userinfo_encrypted_response_kid' client metadata value.
func (c *DefaultRegisteredClient) GetUserinfoEncryptedResponseKeyID() string {
	return c.UserinfoEncryptedResponseKeyID
}

// GetUserinfoEncryptedResponseAlg returns the 'userinfo_encrypted_response_alg' client metadata value.
func (c *DefaultRegisteredClient) GetUserinfoEncryptedResponseAlg() string {
	return c.UserinfoEncryptedResponseAlg
}

// GetUserinfoEncryptedResponseEnc returns the 'userinfo_encrypted_response_enc' client metadata value.
func (c *DefaultRegisteredClient) GetUserinfoEncryptedResponseEnc() string {
	return c.UserinfoEncryptedResponseEnc
}

// GetAuthorizationSignedResponseKeyID returns the 'authorization_signed_response_kid' client metadata value.
func (c *DefaultRegisteredClient) GetAuthorizationSignedResponseKeyID() string {
	return c.AuthorizationSignedResponseKeyID
}

// GetAuthorizationSignedResponseAlg returns the 'authorization_signed_response_alg' client metadata value.
func (c *DefaultRegisteredClient) GetAuthorizationSignedResponseAlg() string {
	return c.AuthorizationSignedResponseAlg
}

// GetAuthorizationEncryptedResponseKeyID returns the 'authorization_encrypted_response_kid' client metadata value.
func (c *DefaultRegisteredClient) GetAuthorizationEncryptedResponseKeyID() string {
	return c.AuthorizationEncryptedResponseKeyID
}

// GetAuthorizationEncryptedResponseAlg returns the 'authorization_encrypted_response_alg' client metadata value.
func (c *DefaultRegisteredClient) GetAuthorizationEncryptedResponseAlg() string {
	return c.AuthorizationEncryptedResponseAlg
}

// GetAuthorizationEncryptedResponseEnc returns the 'authorization_encrypted_response_enc' client metadata value.
func (c *DefaultRegisteredClient) GetAuthorizationEncryptedResponseEnc() string {
	return c.AuthorizationEncryptedResponseEnc
}

// GetTokenEndpointAuthMethod returns the 'token_endpoint_auth_method' value, defaulting to client_secret_basic when
// unset per OpenID Connect Dynamic Client Registration 1.0 Section 2.
func (c *DefaultRegisteredClient) GetTokenEndpointAuthMethod() string {
	if c.TokenEndpointAuthMethod == "" {
		return consts.ClientAuthMethodClientSecretBasic
	}

	return c.TokenEndpointAuthMethod
}

// GetTokenEndpointAuthSigningAlg returns the 'token_endpoint_auth_signing_alg' client metadata value.
func (c *DefaultRegisteredClient) GetTokenEndpointAuthSigningAlg() string {
	return c.TokenEndpointAuthSigningAlg
}

// GetIntrospectionEndpointAuthMethod returns the 'introspection_endpoint_auth_method' value, falling back to the
// client's token endpoint method when unset, as an empty value would let the introspection endpoint accept any
// method.
func (c *DefaultRegisteredClient) GetIntrospectionEndpointAuthMethod() string {
	if c.IntrospectionEndpointAuthMethod == "" {
		return c.GetTokenEndpointAuthMethod()
	}

	return c.IntrospectionEndpointAuthMethod
}

// GetIntrospectionEndpointAuthSigningAlg returns the 'introspection_endpoint_auth_signing_alg' client metadata value.
func (c *DefaultRegisteredClient) GetIntrospectionEndpointAuthSigningAlg() string {
	return c.IntrospectionEndpointAuthSigningAlg
}

// GetRevocationEndpointAuthMethod returns the 'revocation_endpoint_auth_method' value, falling back to the client's
// token endpoint method when unset, for the reasons given on GetIntrospectionEndpointAuthMethod.
func (c *DefaultRegisteredClient) GetRevocationEndpointAuthMethod() string {
	if c.RevocationEndpointAuthMethod == "" {
		return c.GetTokenEndpointAuthMethod()
	}

	return c.RevocationEndpointAuthMethod
}

// GetRevocationEndpointAuthSigningAlg returns the 'revocation_endpoint_auth_signing_alg' client metadata value.
func (c *DefaultRegisteredClient) GetRevocationEndpointAuthSigningAlg() string {
	return c.RevocationEndpointAuthSigningAlg
}

// GetResponseModes returns the response modes the client is allowed to use.
func (c *DefaultRegisteredClient) GetResponseModes() []ResponseModeType {
	return c.ResponseModes
}

// GetAccessTokenSignedResponseKeyID returns the 'access_token_signed_response_kid' client metadata value.
func (c *DefaultRegisteredClient) GetAccessTokenSignedResponseKeyID() string {
	return c.AccessTokenSignedResponseKeyID
}

// GetAccessTokenSignedResponseAlg returns the 'access_token_signed_response_alg' client metadata value.
func (c *DefaultRegisteredClient) GetAccessTokenSignedResponseAlg() string {
	return c.AccessTokenSignedResponseAlg
}

// GetAccessTokenEncryptedResponseKeyID returns the 'access_token_encrypted_response_kid' client metadata value.
func (c *DefaultRegisteredClient) GetAccessTokenEncryptedResponseKeyID() string {
	return c.AccessTokenEncryptedResponseKeyID
}

// GetAccessTokenEncryptedResponseAlg returns the 'access_token_encrypted_response_alg' client metadata value.
func (c *DefaultRegisteredClient) GetAccessTokenEncryptedResponseAlg() string {
	return c.AccessTokenEncryptedResponseAlg
}

// GetAccessTokenEncryptedResponseEnc returns the 'access_token_encrypted_response_enc' client metadata value.
func (c *DefaultRegisteredClient) GetAccessTokenEncryptedResponseEnc() string {
	return c.AccessTokenEncryptedResponseEnc
}

// GetEnableJWTProfileOAuthAccessTokens returns true if JWT Profile Access Tokens should be issued to this client.
func (c *DefaultRegisteredClient) GetEnableJWTProfileOAuthAccessTokens() bool {
	return c.EnableJWTProfileOAuthAccessTokens
}

// GetIntrospectionSignedResponseKeyID returns the 'introspection_signed_response_kid' client metadata value.
func (c *DefaultRegisteredClient) GetIntrospectionSignedResponseKeyID() string {
	return c.IntrospectionSignedResponseKeyID
}

// GetIntrospectionSignedResponseAlg returns the 'introspection_signed_response_alg' client metadata value.
func (c *DefaultRegisteredClient) GetIntrospectionSignedResponseAlg() string {
	return c.IntrospectionSignedResponseAlg
}

// GetIntrospectionEncryptedResponseKeyID returns the 'introspection_encrypted_response_kid' client metadata value.
func (c *DefaultRegisteredClient) GetIntrospectionEncryptedResponseKeyID() string {
	return c.IntrospectionEncryptedResponseKeyID
}

// GetIntrospectionEncryptedResponseAlg returns the 'introspection_encrypted_response_alg' client metadata value.
func (c *DefaultRegisteredClient) GetIntrospectionEncryptedResponseAlg() string {
	return c.IntrospectionEncryptedResponseAlg
}

// GetIntrospectionEncryptedResponseEnc returns the 'introspection_encrypted_response_enc' client metadata value.
func (c *DefaultRegisteredClient) GetIntrospectionEncryptedResponseEnc() string {
	return c.IntrospectionEncryptedResponseEnc
}

// GetEnforcePKCE returns the client policy value which determines if PKCE is enforced for this client.
func (c *DefaultRegisteredClient) GetEnforcePKCE() bool {
	return c.EnforcePKCE
}

// GetEnforcePKCEChallengeMethod returns the client policy value which determines if the PKCE challenge method is
// enforced for this client.
func (c *DefaultRegisteredClient) GetEnforcePKCEChallengeMethod() bool {
	return c.EnforcePKCEChallengeMethod
}

// GetPKCEChallengeMethod returns the PKCE challenge method of the client policy.
func (c *DefaultRegisteredClient) GetPKCEChallengeMethod() string {
	return c.PKCEChallengeMethod
}

// GetRequirePushedAuthorizationRequests returns the 'require_pushed_authorization_requests' client metadata value.
func (c *DefaultRegisteredClient) GetRequirePushedAuthorizationRequests() bool {
	return c.RequirePushedAuthorizationRequests
}

// GetPushedAuthorizeContextLifespan returns the custom Pushed Authorization Request context lifespan for this client,
// or 0 to utilize the global lifespan.
func (c *DefaultRegisteredClient) GetPushedAuthorizeContextLifespan() time.Duration {
	return c.PushedAuthorizeContextLifespan
}

// GetRequireRedirectURIPushedAuthorizationRequests returns true if this client must include the 'redirect_uri'
// parameter in a Pushed Authorization Request.
func (c *DefaultRegisteredClient) GetRequireRedirectURIPushedAuthorizationRequests() bool {
	return c.RequireRedirectURIPushedAuthorizationRequests
}

// GetRequireRequestObjectAudienceAndLifetime returns true if this client's Request Objects must contain the 'aud',
// 'nbf' and 'exp' claims.
func (c *DefaultRegisteredClient) GetRequireRequestObjectAudienceAndLifetime() bool {
	return c.RequireRequestObjectAudienceAndLifetime
}

// GetRequestObjectMaximumLifetime returns the custom bound for this client's Request Object 'nbf' and 'exp' claims, or
// 0 to utilize the global lifetime.
func (c *DefaultRegisteredClient) GetRequestObjectMaximumLifetime() time.Duration {
	return c.RequestObjectMaximumLifetime
}

// GetDisableRefreshTokenRotation returns true if the refresh token grant should keep this client's refresh token rather
// than issue a new one.
func (c *DefaultRegisteredClient) GetDisableRefreshTokenRotation() bool {
	return c.DisableRefreshTokenRotation
}

// GetPostLogoutRedirectURIs returns the 'post_logout_redirect_uris' client metadata value.
func (c *DefaultRegisteredClient) GetPostLogoutRedirectURIs() (uris []string) {
	return c.PostLogoutRedirectURIs
}

// GetBackChannelLogoutURI returns the 'backchannel_logout_uri' client metadata value.
func (c *DefaultRegisteredClient) GetBackChannelLogoutURI() (uri string) {
	return c.BackChannelLogoutURI
}

// GetBackChannelLogoutSessionRequired returns the 'backchannel_logout_session_required' client metadata value.
func (c *DefaultRegisteredClient) GetBackChannelLogoutSessionRequired() (required bool) {
	return c.BackChannelLogoutSessionRequired
}

// GetTLSClientAuthSubjectDN returns the 'tls_client_auth_subject_dn' client metadata value.
func (c *DefaultRegisteredClient) GetTLSClientAuthSubjectDN() (dn string) {
	return c.TLSClientAuthSubjectDN
}

// GetTLSClientAuthSANDNS returns the 'tls_client_auth_san_dns' client metadata value.
func (c *DefaultRegisteredClient) GetTLSClientAuthSANDNS() (dns string) {
	return c.TLSClientAuthSANDNS
}

// GetTLSClientAuthSANURI returns the 'tls_client_auth_san_uri' client metadata value.
func (c *DefaultRegisteredClient) GetTLSClientAuthSANURI() (uri string) {
	return c.TLSClientAuthSANURI
}

// GetTLSClientAuthSANIP returns the 'tls_client_auth_san_ip' client metadata value.
func (c *DefaultRegisteredClient) GetTLSClientAuthSANIP() (ip string) {
	return c.TLSClientAuthSANIP
}

// GetTLSClientAuthSANEmail returns the 'tls_client_auth_san_email' client metadata value.
func (c *DefaultRegisteredClient) GetTLSClientAuthSANEmail() (email string) {
	return c.TLSClientAuthSANEmail
}

// GetAuthorizationDetailsTypes returns the RFC 9396 authorization details types this client may request.
func (c *DefaultRegisteredClient) GetAuthorizationDetailsTypes() (types []string) {
	return c.AuthorizationDetailsTypes
}

// GetClientIDIssuedAt returns the time the client identifier was issued, or the zero time when it is not recorded.
func (c *DefaultRegisteredClient) GetClientIDIssuedAt() (issued time.Time) {
	return c.ClientIDIssuedAt
}

// GetClientSecretExpiresAt returns the time the client secret expires, or the zero time when it does not.
func (c *DefaultRegisteredClient) GetClientSecretExpiresAt() (expires time.Time) {
	return c.ClientSecretExpiresAt
}

// GetSupportedSubjectTokenTypes returns the RFC 8693 'subject_token_type' values this client may present. Empty
// applies no restriction.
func (c *DefaultRegisteredClient) GetSupportedSubjectTokenTypes() (types []string) {
	return c.TokenExchangeSubjectTokenTypes
}

// GetSupportedActorTokenTypes returns the RFC 8693 'actor_token_type' values this client may present. Empty applies
// no restriction.
func (c *DefaultRegisteredClient) GetSupportedActorTokenTypes() (types []string) {
	return c.TokenExchangeActorTokenTypes
}

// GetSupportedRequestTokenTypes returns the RFC 8693 'requested_token_type' values this client may ask for. Empty
// applies no restriction.
func (c *DefaultRegisteredClient) GetSupportedRequestTokenTypes() (types []string) {
	return c.TokenExchangeRequestTokenTypes
}

// GetSupportedSubjectTokenIssuers returns no per-client issuer restriction, deferring to the token type's own issuer
// setting as the interface documents. There is no registered metadata for it.
func (c *DefaultRegisteredClient) GetSupportedSubjectTokenIssuers() (issuers []string) {
	return nil
}

// GetSupportedActorTokenIssuers returns no per-client issuer restriction, deferring to the token type's own issuer
// setting as the interface documents. There is no registered metadata for it.
func (c *DefaultRegisteredClient) GetSupportedActorTokenIssuers() (issuers []string) {
	return nil
}

// GetAuthorizationGrantProfilesSupported returns the authorization grant profiles the client implements.
func (c *DefaultRegisteredClient) GetAuthorizationGrantProfilesSupported() (profiles []string) {
	return c.AuthorizationGrantProfilesSupported
}

// GetTokenExchangePermitted reports whether client may exchange a token issued to this one, per RFC 8693 Section 5's
// recommendation that the exchange be restricted "to only those clients explicitly authorized to perform the exchange
// operation".
//
// An empty list permits any client, which is how a client expressing no policy behaves; the requested token type is
// not consulted, so a deployment needing a rule of that shape supplies its own client type.
func (c *DefaultRegisteredClient) GetTokenExchangePermitted(client Client, requestedTokenType RFC8693TokenType) (allowed bool) {
	if len(c.TokenExchangePermittedClientIDs) == 0 {
		return true
	}

	if client == nil {
		return false
	}

	return slices.Contains(c.TokenExchangePermittedClientIDs, client.GetID())
}

// GetAllowActorTokenWithoutMayAct reports false: delegation on a subject token carrying no 'may_act' claim requires
// an out-of-band authorization mechanism, which registered metadata cannot express.
func (c *DefaultRegisteredClient) GetAllowActorTokenWithoutMayAct() (allow bool) {
	return false
}

var (
	_ Client                                      = (*DefaultRegisteredClient)(nil)
	_ RotatedClientSecretsClient                  = (*DefaultRegisteredClient)(nil)
	_ JSONWebKeysClient                           = (*DefaultRegisteredClient)(nil)
	_ JARClient                                   = (*DefaultRegisteredClient)(nil)
	_ IDTokenClient                               = (*DefaultRegisteredClient)(nil)
	_ UserInfoClient                              = (*DefaultRegisteredClient)(nil)
	_ JARMClient                                  = (*DefaultRegisteredClient)(nil)
	_ AuthenticationMethodClient                  = (*DefaultRegisteredClient)(nil)
	_ ResponseModeClient                          = (*DefaultRegisteredClient)(nil)
	_ DPoPClient                                  = (*DefaultRegisteredClient)(nil)
	_ JWTProfileClient                            = (*DefaultRegisteredClient)(nil)
	_ IntrospectionJWTResponseClient              = (*DefaultRegisteredClient)(nil)
	_ ProofKeyCodeExchangeClient                  = (*DefaultRegisteredClient)(nil)
	_ PushedAuthorizationRequestClient            = (*DefaultRegisteredClient)(nil)
	_ PushedAuthorizationRequestRedirectURIClient = (*DefaultRegisteredClient)(nil)
	_ RequestObjectLifetimeClient                 = (*DefaultRegisteredClient)(nil)
	_ RefreshTokenRotationClient                  = (*DefaultRegisteredClient)(nil)
	_ RPInitiatedLogoutClient                     = (*DefaultRegisteredClient)(nil)
	_ BackChannelLogoutClient                     = (*DefaultRegisteredClient)(nil)
	_ TLSClientAuthClient                         = (*DefaultRegisteredClient)(nil)
	_ MTLSClient                                  = (*DefaultRegisteredClient)(nil)
	_ AuthorizationDetailsClient                  = (*DefaultRegisteredClient)(nil)
)
