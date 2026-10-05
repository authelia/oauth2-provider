// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"time"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2/internal/consts"
)

// Client represents a client or an app.
type Client interface {
	// GetID returns the client ID.
	GetID() (id string)

	// GetClientSecret returns the ClientSecret.
	GetClientSecret() (secret ClientSecret)

	// GetClientSecretPlainText returns the ClientSecret as plaintext if available. The semantics of this function
	// return values are important.
	// If the client is not configured with a secret the return should be:
	//   - secret with value nil, ok with value false, and err with value of nil
	// If the client is configured with a secret but is hashed or otherwise not a plaintext value:
	//   - secret with value nil, ok with value true, and err with value of nil
	// If an error occurs retrieving the secret other than this:
	//   - secret with value nil, ok with value true, and err with value of the error
	// If the plaintext secret is successful:
	//   - secret with value of the bytes of the plaintext secret, ok with value true, and err with value of nil
	GetClientSecretPlainText() (secret []byte, ok bool, err error)

	// GetRedirectURIs returns the client's allowed redirect URIs.
	GetRedirectURIs() []string

	// GetGrantTypes returns the client's allowed grant types.
	GetGrantTypes() (types Arguments)

	// GetResponseTypes returns the client's allowed response types.
	// All allowed combinations of response types have to be listed, each combination having
	// response types of the combination separated by a space.
	GetResponseTypes() (types Arguments)

	// GetScopes returns the scopes this client is allowed to request.
	GetScopes() (scopes Arguments)

	// IsPublic returns true, if this client is marked as public.
	IsPublic() (public bool)

	// GetAudience returns the allowed audience(s) for this client.
	GetAudience() (audience Arguments)

	// GetResource returns the allowed RFC 8707 resource indicator(s) for this client.
	GetResource() (resource Arguments)
}

// RotatedClientSecretsClient extends Client interface by a method providing a slice of rotated secrets.
type RotatedClientSecretsClient interface {
	GetRotatedClientSecrets() (secrets []ClientSecret)

	Client
}

// ClientIDIssuedAtClient extends Client interface by a method providing the time the client identifier was issued,
// being the RFC 7591 Section 3.2.1 'client_id_issued_at' value.
type ClientIDIssuedAtClient interface {
	GetClientIDIssuedAt() (issued time.Time)

	Client
}

// ExpiringClientSecretClient extends Client interface by a method providing the time the client secret expires. A
// zero time means the secret does not expire, which RFC 7591 Section 3.2.1 also assigns to a
// 'client_secret_expires_at' of 0.
type ExpiringClientSecretClient interface {
	GetClientSecretExpiresAt() (expires time.Time)

	Client
}

// ProofKeyCodeExchangeClient is a Client implementation which provides PKCE client policy values.
type ProofKeyCodeExchangeClient interface {
	GetEnforcePKCE() (enforce bool)
	GetEnforcePKCEChallengeMethod() (enforce bool)
	GetPKCEChallengeMethod() (method string)

	Client
}

// ClientAuthenticationPolicyClient is a Client implementation which also provides client authentication policy values.
type ClientAuthenticationPolicyClient interface {
	// GetAllowMultipleAuthenticationMethods should return true if the client policy allows multiple authentication
	// methods due to the client implementation breaching RFC6749 Section 2.3.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.
	GetAllowMultipleAuthenticationMethods() (allow bool)

	Client
}

// JSONWebKeysClient is a client base which includes a JSON Web Key Set registration.
type JSONWebKeysClient interface {
	// GetJSONWebKeys returns the JSON Web Key Set containing the public key used by the client to authenticate.
	GetJSONWebKeys() (jwks *jose.JSONWebKeySet)

	// GetJSONWebKeysURI returns the URL for lookup of JSON Web Key Set containing the
	// public key used by the client to authenticate.
	GetJSONWebKeysURI() (uri string)

	Client
}

// IDTokenClient is a client which can satisfy all JWS and JWE requirements of the ID Token responses.
type IDTokenClient interface {
	// GetIDTokenSignedResponseKeyID returns the specific key identifier used to satisfy JWS requirements of the ID
	// Token specifications. If unspecified the other available parameters will be utilized to select an appropriate
	// key.
	GetIDTokenSignedResponseKeyID() (kid string)

	// GetIDTokenSignedResponseAlg is equivalent to the 'id_token_signed_response_alg' client metadata value which
	// determines the JWS alg algorithm required for signing the ID Token issued to this client. The default, if
	// omitted, is RS256.
	//
	// See: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
	GetIDTokenSignedResponseAlg() (alg string)

	// GetIDTokenEncryptedResponseKeyID returns the specific key identifier used to satisfy JWE requirements of the ID
	// Token specifications. If unspecified the other available parameters will be utilized to select an appropriate
	// key.
	GetIDTokenEncryptedResponseKeyID() (kid string)

	// GetIDTokenEncryptedResponseAlg is equivalent to the 'id_token_encrypted_response_alg' client metadata value which
	// determines the JWE alg algorithm required for encrypting the ID Token issued to this client. The default, if
	// omitted, is that no encryption is performed.
	//
	// See: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
	GetIDTokenEncryptedResponseAlg() (alg string)

	// GetIDTokenEncryptedResponseEnc is equivalent to the 'id_token_encrypted_response_enc' client metadata value which
	// determines the JWE enc algorithm required for encrypting the ID Token issued to this client. The default is
	// A128CBC-HS256 when the alg is specified, and it must not be specified without the alg.
	//
	// See: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
	GetIDTokenEncryptedResponseEnc() (enc string)

	JSONWebKeysClient
}

// UserInfoClient is a client which can satisfy all JWS and JWE requirements of the User Info responses.
type UserInfoClient interface {
	// GetUserinfoSignedResponseKeyID returns the specific key identifier used to satisfy JWS requirements of the User
	// Info specifications. If unspecified the other available parameters will be utilized to select an appropriate
	// key.
	GetUserinfoSignedResponseKeyID() (kid string)

	// GetUserinfoSignedResponseAlg is equivalent to the 'userinfo_signed_response_alg' client metadata value which
	// determines the JWS alg algorithm required for signing UserInfo Responses. The default, if omitted, is an
	// unsigned JSON response.
	//
	// See: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
	GetUserinfoSignedResponseAlg() (alg string)

	// GetUserinfoEncryptedResponseKeyID returns the specific key identifier used to satisfy JWE requirements of the
	// User Info specifications. If unspecified the other available parameters will be utilized to select an appropriate
	// key.
	GetUserinfoEncryptedResponseKeyID() (kid string)

	// GetUserinfoEncryptedResponseAlg is equivalent to the 'userinfo_encrypted_response_alg' client metadata value
	// which determines the JWE alg algorithm required for encrypting UserInfo Responses. The default, if omitted, is
	// that no encryption is performed.
	//
	// See: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
	GetUserinfoEncryptedResponseAlg() (alg string)

	// GetUserinfoEncryptedResponseEnc is equivalent to the 'userinfo_encrypted_response_enc' client metadata value
	// which determines the JWE enc algorithm required for encrypting UserInfo Responses. The default is A128CBC-HS256
	// when the alg is specified, and it must not be specified without the alg.
	//
	// See: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
	GetUserinfoEncryptedResponseEnc() (enc string)

	JSONWebKeysClient
}

// JARClient represents a client capable of performing JWT-Secured Authorization Requests.
//
// See: https://www.rfc-editor.org/rfc/rfc9101
type JARClient interface {
	// GetRequireSignedRequestObject is equivalent to the 'require_signed_request_object' client metadata value which
	// indicates where authorization request needs to be protected as a Request Object and provided through either the
	// 'request' or 'request_uri' parameter. When true a request which does not include one of these parameters MUST be
	// rejected, and the Request Object MUST be signed; i.e. a 'request_object_signing_alg' value of 'none' is not
	// sufficient to satisfy this requirement.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9101#section-9.3
	GetRequireSignedRequestObject() (require bool)

	// GetRequestObjectSigningKeyID returns the specific key identifier used to satisfy JWS requirements of the request
	// object specifications. If unspecified the other available parameters will be utilized to select an appropriate
	// key.
	GetRequestObjectSigningKeyID() (kid string)

	// GetRequestObjectSigningAlg is equivalent to the 'request_object_signing_alg' client metadata value which
	// determines the JWS alg algorithm that must be used for signing Request Objects, whether passed by value or by
	// reference. The value none may be used. The default, if omitted, is that any supported algorithm may be used.
	//
	// See: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
	GetRequestObjectSigningAlg() (alg string)

	// GetRequestObjectEncryptionKeyID returns the specific key identifier used to satisfy JWE requirements of the
	// request object specifications. If unspecified the other available parameters will be utilized to select an
	// appropriate key.
	GetRequestObjectEncryptionKeyID() (kid string)

	// GetRequestObjectEncryptionAlg is equivalent to the 'request_object_encryption_alg' client metadata value which
	// determines the JWE alg algorithm the client declares it may use for encrypting Request Objects.
	//
	// See: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
	GetRequestObjectEncryptionAlg() (alg string)

	// GetRequestObjectEncryptionEnc is equivalent to the 'request_object_encryption_enc' client metadata value which
	// determines the JWE enc algorithm the client declares it may use for encrypting Request Objects. The default is
	// A128CBC-HS256 when the alg is specified, and it must not be specified without the alg.
	//
	// See: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
	GetRequestObjectEncryptionEnc() (enc string)

	// GetRequestURIs is equivalent to the 'request_uris' client metadata value which is the 'request_uri' values
	// pre-registered by the client.
	//
	// See: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
	GetRequestURIs() (requestURIs []string)

	JSONWebKeysClient
}

// RequestObjectLifetimeClient is a JARClient which requires the 'aud', 'nbf' and 'exp' claims in its own Request
// Objects. The requirement applies when either this or the provider-wide option is set.
//
// See: https://openid.net/specs/fapi-message-signing-2_0-final.html#section-5.3.1
type RequestObjectLifetimeClient interface {
	// GetRequireRequestObjectAudienceAndLifetime should return true if this client's Request Objects MUST contain the
	// 'aud', 'nbf' and 'exp' claims.
	GetRequireRequestObjectAudienceAndLifetime() (require bool)

	// GetRequestObjectMaximumLifetime should return a custom bound for this client's Request Object 'nbf' and 'exp'
	// claims, or a duration of 0 seconds to utilize the global lifetime.
	GetRequestObjectMaximumLifetime() (lifetime time.Duration)

	JARClient
}

// AuthenticationMethodClient represents a client which has specific authentication methods.
type AuthenticationMethodClient interface {
	// GetTokenEndpointAuthMethod is equivalent to the 'token_endpoint_auth_method' client metadata value which
	// determines the requested Client Authentication method for the Token Endpoint. The options are client_secret_post,
	// client_secret_basic, client_secret_jwt, private_key_jwt, and none.
	GetTokenEndpointAuthMethod() (method string)

	// GetTokenEndpointAuthSigningAlg is equivalent to the 'token_endpoint_auth_signing_alg' client metadata value which
	// determines the JWS [JWS] alg algorithm [JWA] that MUST be used for signing the JWT [JWT] used to authenticate the
	// Client at the Token Endpoint for the private_key_jwt and client_secret_jwt authentication methods.
	GetTokenEndpointAuthSigningAlg() (alg string)

	// GetIntrospectionEndpointAuthMethod is equivalent to the 'introspection_endpoint_auth_method' client metadata
	// value which determines the Client Authentication method for the Introspection Endpoint. The options are
	// client_secret_post, client_secret_basic, client_secret_jwt, private_key_jwt.
	GetIntrospectionEndpointAuthMethod() (method string)

	// GetIntrospectionEndpointAuthSigningAlg is equivalent to the 'introspection_endpoint_auth_signing_alg' client
	// metadata value which determines the JWS [JWS] alg algorithm [JWA] that MUST be used for signing the JWT [JWT]
	// used to authenticate the Client at the Introspection Endpoint for the private_key_jwt and client_secret_jwt
	// authentication methods.
	GetIntrospectionEndpointAuthSigningAlg() (alg string)

	// GetRevocationEndpointAuthMethod is equivalent to the 'revocation_endpoint_auth_method' client metadata value
	// which determines the Client Authentication method for the Revocation Endpoint. The options are
	// client_secret_post, client_secret_basic, client_secret_jwt, private_key_jwt.
	GetRevocationEndpointAuthMethod() (method string)

	// GetRevocationEndpointAuthSigningAlg is equivalent to the 'revocation_endpoint_auth_signing_alg' client metadata
	// value which determines the JWS [JWS] alg algorithm [JWA] that MUST be used for signing the JWT [JWT] used to
	// authenticate the Client at the Revocation Endpoint for the private_key_jwt and client_secret_jwt authentication
	// methods.
	GetRevocationEndpointAuthSigningAlg() (alg string)

	JSONWebKeysClient
}

// RefreshFlowScopeClient is a client which can be customized to ignore scopes that were not originally granted.
type RefreshFlowScopeClient interface {
	GetRefreshFlowIgnoreOriginalGrantedScopes(ctx context.Context) (ignoreOriginalGrantedScopes bool)

	Client
}

// RefreshTokenRotationClient is a client which keeps its refresh token during its own refresh token grants. Rotation
// is disabled when either this or the provider-wide option is set, except for a public client whose refresh token is
// not sender-constrained by an enabled DPoP or mTLS binding; see IsRefreshTokenRotationDisabledForRequest.
//
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.1
type RefreshTokenRotationClient interface {
	// GetDisableRefreshTokenRotation should return true if the refresh token grant should keep this client's refresh
	// token rather than issue a new one.
	GetDisableRefreshTokenRotation() (disable bool)

	Client
}

// RevokeFlowRevokeRefreshTokensExplicitClient is a client which can be customized to only revoke Refresh Tokens
// explicitly.
type RevokeFlowRevokeRefreshTokensExplicitClient interface {
	// GetRevokeRefreshTokensExplicit returns true if this client will only revoke refresh tokens explicitly.
	GetRevokeRefreshTokensExplicit(ctx context.Context) (explicit bool)

	Client
}

// JARMClient is a client which supports JARM.
//
// See: https://openid.net/specs/oauth-v2-jarm.html
type JARMClient interface {
	// GetAuthorizationSignedResponseKeyID returns the specific key identifier used to satisfy JWS requirements of the
	// JWT-secured Authorization Response Method (JARM) specifications. If unspecified the other available parameters
	// will be utilized to select an appropriate key.
	GetAuthorizationSignedResponseKeyID() (kid string)

	// GetAuthorizationSignedResponseAlg is equivalent to the 'authorization_signed_response_alg' client metadata
	// value which determines the JWS [RFC7515] alg algorithm JWA [RFC7518] REQUIRED for signing authorization
	// responses. If this is specified, the response will be signed using JWS and the configured algorithm. The
	// algorithm none is not allowed. The default, if omitted, is RS256.
	GetAuthorizationSignedResponseAlg() (alg string)

	// GetAuthorizationEncryptedResponseKeyID returns the specific key identifier used to satisfy JWE requirements of
	// the JWT-secured Authorization Response Method (JARM) specifications. If unspecified the other available parameters will be
	// utilized to select an appropriate key.
	GetAuthorizationEncryptedResponseKeyID() (kid string)

	// GetAuthorizationEncryptedResponseAlg is equivalent to the 'authorization_encrypted_response_alg' client metadata
	// value which determines the JWE alg algorithm required for encrypting authorization responses. The default, if
	// omitted, is that no encryption is performed.
	GetAuthorizationEncryptedResponseAlg() (alg string)

	// GetAuthorizationEncryptedResponseEnc is equivalent to the 'authorization_encrypted_response_enc' client
	// metadata value which determines the JWE enc algorithm required for encrypting authorization responses. The
	// default is A128CBC-HS256 when the alg is specified, and it must not be specified without the alg.
	GetAuthorizationEncryptedResponseEnc() (alg string)

	JSONWebKeysClient
}

// PushedAuthorizationRequestClient is a client with custom requirements for Pushed Authorization requests.
type PushedAuthorizationRequestClient interface {
	// GetRequirePushedAuthorizationRequests should return true if this client MUST use a Pushed Authorization Request.
	GetRequirePushedAuthorizationRequests() (require bool)

	// GetPushedAuthorizeContextLifespan should return a custom lifespan or a duration of 0 seconds to utilize the
	// global lifespan.
	GetPushedAuthorizeContextLifespan() (lifespan time.Duration)

	Client
}

// PushedAuthorizationRequestRedirectURIClient is a client which requires the 'redirect_uri' parameter in its own Pushed
// Authorization Requests. The requirement applies when either this or the provider-wide option is set.
//
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.2
type PushedAuthorizationRequestRedirectURIClient interface {
	// GetRequireRedirectURIPushedAuthorizationRequests should return true if this client MUST include the
	// 'redirect_uri' parameter in a Pushed Authorization Request.
	GetRequireRedirectURIPushedAuthorizationRequests() (require bool)

	Client
}

// ResponseModeClient represents a client capable of handling response_mode
type ResponseModeClient interface {
	// GetResponseModes returns the response modes that client is allowed to send
	GetResponseModes() (modes []ResponseModeType)

	Client
}

// RPInitiatedLogoutClient is a Client which has registered post logout redirect URIs for OpenID Connect
// RP-Initiated Logout.
//
// See: https://openid.net/specs/openid-connect-rpinitiated-1_0.html
type RPInitiatedLogoutClient interface {
	Client

	// GetPostLogoutRedirectURIs returns the client's registered post logout redirect URIs. A client with none
	// registered cannot use the 'post_logout_redirect_uri' parameter.
	GetPostLogoutRedirectURIs() (uris []string)
}

// BackChannelLogoutClient is a Client which has registered a back-channel logout URI for OpenID Connect
// Back-Channel Logout.
//
// As with post_logout_redirect_uris, this library does not validate the registered backchannel_logout_uri's
// scheme, host, or exposure to SSRF; validating it at registration time is the integrator's responsibility.
//
// See: https://openid.net/specs/openid-connect-backchannel-1_0.html
type BackChannelLogoutClient interface {
	Client

	// GetBackChannelLogoutURI returns the client's registered back-channel logout URI. A client with none
	// registered does not participate in back-channel logout.
	GetBackChannelLogoutURI() (uri string)

	// GetBackChannelLogoutSessionRequired returns true when the client requires the 'sid' claim in the Logout
	// Token. When it does and no session identifier is available the client is not notified.
	GetBackChannelLogoutSessionRequired() (required bool)
}

// JWTProfileClient represents a client with can handle RFC9068 responses; i.e. the JWT Profile for OAuth 2.0 Access
// Tokens.
type JWTProfileClient interface {
	// GetAccessTokenSignedResponseKeyID returns the specific key identifier used to satisfy JWS requirements for
	// JWT Profile for OAuth 2.0 Access Tokens specifications. If unspecified the other available parameters will be
	// utilized to select an appropriate key.
	GetAccessTokenSignedResponseKeyID() (kid string)

	// GetAccessTokenSignedResponseAlg determines the JWS [RFC7515] algorithm (alg value) as defined in JWA [RFC7518]
	// for signing JWT Profile Access Token responses. If this is specified, the response will be signed using JWS and
	// the configured algorithm. The default, if omitted, is none; i.e. unsigned responses unless the
	// GetEnableJWTProfileOAuthAccessTokens receiver returns true in which case the default is RS256.
	GetAccessTokenSignedResponseAlg() (alg string)

	// GetAccessTokenEncryptedResponseKeyID returns the specific key identifier used to satisfy JWE requirements for
	// JWT Profile for OAuth 2.0 Access Tokens specifications. If unspecified the other available parameters will be
	// utilized to select an appropriate key.
	GetAccessTokenEncryptedResponseKeyID() (kid string)

	// GetAccessTokenEncryptedResponseAlg determines the JWE alg algorithm for content key encryption of access token
	// responses. The default, if omitted, is that no encryption is performed.
	GetAccessTokenEncryptedResponseAlg() (alg string)

	// GetAccessTokenEncryptedResponseEnc determines the JWE [RFC7516] algorithm (enc value) as defined in JWA [RFC7518]
	// for content encryption of access token responses. The default, if omitted, is A128CBC-HS256. Note: This parameter
	// MUST NOT be specified without setting access_token_encrypted_response_alg.
	GetAccessTokenEncryptedResponseEnc() (alg string)

	// GetEnableJWTProfileOAuthAccessTokens indicates this client should or should not issue JWT Profile Access Tokens.
	GetEnableJWTProfileOAuthAccessTokens() (enforce bool)

	JSONWebKeysClient
}

// DPoPStrictRefreshTokenBindingClient is a client whose DPoP bound refresh tokens may only be redeemed with a proof
// for the key they are bound to, even though it is confidential. Strict binding applies when either this or the
// provider-wide option is set; see DPoPStrictRefreshTokenBindingProvider.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-5
type DPoPStrictRefreshTokenBindingClient interface {
	// GetDPoPStrictRefreshTokenBinding returns true if this client's refresh tokens stay bound to the DPoP key they
	// were issued for.
	GetDPoPStrictRefreshTokenBinding() (strict bool)

	Client
}

// IntrospectionTokenTypeClient is a client which, when it calls the introspection endpoint, decides whether the
// response includes the RFC 7662 Section 2.2 'token_type' member. When implemented it overrides
// IntrospectionTokenTypeEnabledProvider.
//
// See: https://www.rfc-editor.org/rfc/rfc7662#section-2.2
type IntrospectionTokenTypeClient interface {
	// GetIntrospectionTokenTypeEnabled returns true if introspection responses sent to this client include the
	// 'token_type' member.
	GetIntrospectionTokenTypeEnabled() (enabled bool)

	Client
}

// DPoPClient represents a client that can advertise the 'dpop_bound_access_tokens' metadata value per RFC 9449.
type DPoPClient interface {
	// GetEnableDPoPBoundAccessTokens returns the 'dpop_bound_access_tokens' client metadata value. When true, DPoP is
	// required for this client.
	GetEnableDPoPBoundAccessTokens() (enable bool)

	Client
}

// TLSClientAuthClient represents a client that authenticates using the RFC 8705 Section 2.1 'tls_client_auth' PKI
// method. A client using that method MUST register exactly one of these subject values, which is the value the
// certificate presented during the handshake is checked against.
type TLSClientAuthClient interface {
	// GetTLSClientAuthSubjectDN returns the 'tls_client_auth_subject_dn' client metadata value, being the RFC 4514
	// string representation of the expected certificate subject distinguished name.
	GetTLSClientAuthSubjectDN() (dn string)

	// GetTLSClientAuthSANDNS returns the 'tls_client_auth_san_dns' client metadata value, being the expected dNSName
	// subject alternative name entry.
	GetTLSClientAuthSANDNS() (dns string)

	// GetTLSClientAuthSANURI returns the 'tls_client_auth_san_uri' client metadata value, being the expected
	// uniformResourceIdentifier subject alternative name entry.
	GetTLSClientAuthSANURI() (uri string)

	// GetTLSClientAuthSANIP returns the 'tls_client_auth_san_ip' client metadata value, being the expected iPAddress
	// subject alternative name entry in dotted decimal or colon delimited hexadecimal notation.
	GetTLSClientAuthSANIP() (ip string)

	// GetTLSClientAuthSANEmail returns the 'tls_client_auth_san_email' client metadata value, being the expected
	// rfc822Name subject alternative name entry.
	GetTLSClientAuthSANEmail() (email string)

	Client
}

// MTLSStrictRefreshTokenBindingClient is a client whose certificate-bound refresh tokens may only be redeemed with
// the certificate they are bound to, even though it is confidential. Strict binding applies when either this or the
// provider-wide option is set; see MTLSStrictRefreshTokenBindingProvider.
//
// See: https://www.rfc-editor.org/rfc/rfc8705#section-7.1
type MTLSStrictRefreshTokenBindingClient interface {
	// GetMTLSStrictRefreshTokenBinding returns true if this client's refresh tokens stay bound to the certificate they
	// were issued for.
	GetMTLSStrictRefreshTokenBinding() (strict bool)

	Client
}

// MTLSClient represents a client that can advertise the 'tls_client_certificate_bound_access_tokens' metadata value
// per RFC 8705 Section 3.4.
type MTLSClient interface {
	// GetEnableTLSClientAuthBoundAccessTokens returns the 'tls_client_certificate_bound_access_tokens' client
	// metadata value. When true, tokens issued to this client are bound to the certificate it presents.
	GetEnableTLSClientAuthBoundAccessTokens() (enable bool)

	Client
}

// ClientCredentialsFlowRequestedScopeImplicitClient is a client which can allow implicit scopes in the client credentials flow.
type ClientCredentialsFlowRequestedScopeImplicitClient interface {
	// GetClientCredentialsFlowRequestedScopeImplicit is indicative of if a client will implicitly request all scopes it
	// is allowed to request in the absence of requested scopes during the Client Credentials Flow.
	GetClientCredentialsFlowRequestedScopeImplicit() (implicit bool)

	Client
}

// RequestedAudienceImplicitClient is a client which can potentially implicitly grant permitted audiences given the
// absence of a request parameter.
type RequestedAudienceImplicitClient interface {
	// GetRequestedAudienceImplicit is indicative of if a client will implicitly request all audiences it is allowed to
	// request in the absence of requested audience during an Authorization Endpoint Flow or Client Credentials Flow.
	GetRequestedAudienceImplicit() (implicit bool)

	Client
}

// IntrospectionJWTResponseClient is a client which can potentially sign Introspection responses.
//
// See: https://www.ietf.org/id/draft-ietf-oauth-jwt-introspection-response-12.html
type IntrospectionJWTResponseClient interface {
	// GetIntrospectionSignedResponseKeyID returns the specific key identifier used to satisfy JWS requirements for
	// OAuth 2.0 JWT introspection response specifications. If unspecified the other available parameters will be
	// utilized to select an appropriate key.
	GetIntrospectionSignedResponseKeyID() (kid string)

	// GetIntrospectionSignedResponseAlg is equivalent to the 'introspection_signed_response_alg' client metadata
	// value which determines the JWS [RFC7515] algorithm (alg value) as defined in JWA [RFC7518] for signing
	// introspection responses. If this is specified, the response will be signed using JWS and the configured
	// algorithm. The default, if omitted, is RS256.
	GetIntrospectionSignedResponseAlg() (alg string)

	// GetIntrospectionEncryptedResponseKeyID returns the specific key identifier used to satisfy JWE requirements for
	// OAuth 2.0 JWT introspection response specifications. If unspecified the other available parameters will be
	// utilized to select an appropriate key.
	GetIntrospectionEncryptedResponseKeyID() (kid string)

	// GetIntrospectionEncryptedResponseAlg is equivalent to the 'introspection_encrypted_response_alg' client metadata
	// value which determines the JWE alg algorithm for content key encryption of introspection responses. The default,
	// if omitted, is that no encryption is performed.
	GetIntrospectionEncryptedResponseAlg() (alg string)

	// GetIntrospectionEncryptedResponseEnc is equivalent to the 'introspection_encrypted_response_enc' client metadata
	// value which determines the  JWE [RFC7516] algorithm (enc value) as defined in JWA [RFC7518] for content
	// encryption of introspection responses. The default, if omitted, is A128CBC-HS256. Note: This parameter MUST NOT
	// be specified without setting introspection_encrypted_response_alg.
	GetIntrospectionEncryptedResponseEnc() (enc string)

	JSONWebKeysClient
}

// ClientAssertionJWTValidationOptionsClient allows extending the client assertion validation and strengthening the
// security posture of client assertion through strict typing.
type ClientAssertionJWTValidationOptionsClient interface {
	GetClientAssertionJWTValidationHeaderAllowEmptyType() (allow bool)
	GetClientAssertionJWTValidationHeaderAllowTypes() (algs []string)

	Client
}

// JWTSecuredAuthorizationRequestJWTValidationOptionsClient allows extending the JWT-Secured Authorization Request (JAR)
// validation and strengthening the security posture of JAR through strict typing.
type JWTSecuredAuthorizationRequestJWTValidationOptionsClient interface {
	GetJWTSecuredAuthorizationRequestJWTValidationHeaderAllowEmptyType() (allow bool)
	GetJWTSecuredAuthorizationRequestJWTValidationHeaderAllowTypes() (algs []string)

	Client
}

// DefaultClient is a simple default implementation of the Client interface.
type DefaultClient struct {
	ID                                    string         `json:"id"`
	ClientSecret                          ClientSecret   `json:"-"`
	RotatedClientSecrets                  []ClientSecret `json:"-"`
	RedirectURIs                          []string       `json:"redirect_uris"`
	GrantTypes                            []string       `json:"grant_types"`
	ResponseTypes                         []string       `json:"response_types"`
	Scopes                                []string       `json:"scopes"`
	Audience                              []string       `json:"audience"`
	Resource                              []string       `json:"resource"`
	Public                                bool           `json:"public"`
	DPoPBoundAccessTokens                 bool           `json:"dpop_bound_access_tokens"`
	TLSClientCertificateBoundAccessTokens bool           `json:"tls_client_certificate_bound_access_tokens"`
}

type DefaultJARClient struct {
	JSONWebKeysURI                      string              `json:"jwks_uri"`
	JSONWebKeys                         *jose.JSONWebKeySet `json:"jwks"`
	TokenEndpointAuthMethod             string              `json:"token_endpoint_auth_method"`
	IntrospectionEndpointAuthMethod     string              `json:"introspection_endpoint_auth_method"`
	RevocationEndpointAuthMethod        string              `json:"revocation_endpoint_auth_method"`
	RequestURIs                         []string            `json:"request_uris"`
	RequireSignedRequestObject          bool                `json:"require_signed_request_object"`
	RequestObjectSigningKeyID           string              `json:"request_object_signing_kid"`
	RequestObjectSigningAlg             string              `json:"request_object_signing_alg"`
	RequestObjectEncryptionKeyID        string              `json:"request_object_encryption_kid"`
	RequestObjectEncryptionAlg          string              `json:"request_object_encryption_alg"`
	RequestObjectEncryptionEnc          string              `json:"request_object_encryption_enc"`
	TokenEndpointAuthSigningAlg         string              `json:"token_endpoint_auth_signing_alg"`
	IntrospectionEndpointAuthSigningAlg string              `json:"introspection_endpoint_auth_signing_alg"`
	RevocationEndpointAuthSigningAlg    string              `json:"revocation_endpoint_auth_signing_alg"`

	RequireRequestObjectAudienceAndLifetime bool          `json:"-"`
	RequestObjectMaximumLifetime            time.Duration `json:"-"`

	*DefaultClient
}

type DefaultResponseModeClient struct {
	ResponseModes []ResponseModeType `json:"response_modes"`

	*DefaultClient
}

type DefaultRPInitiatedLogoutClient struct {
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`

	*DefaultClient
}

type DefaultBackChannelLogoutClient struct {
	BackChannelLogoutURI             string `json:"backchannel_logout_uri"`
	BackChannelLogoutSessionRequired bool   `json:"backchannel_logout_session_required"`

	*DefaultClient
}

// DefaultMTLSClient registers the RFC 8705 Section 2.1.2 certificate subject metadata required by the
// 'tls_client_auth' method.
//
// It must embed *DefaultJARClient rather than *DefaultClient: that type implements AuthenticationMethodClient, which
// both RFC 8705 authentication methods are read through, and supplies the 'jwks'/'jwks_uri' metadata
// 'self_signed_tls_client_auth' reads the accepted certificates from.
//
// See: https://www.rfc-editor.org/rfc/rfc8705#section-2.1.2 and https://www.rfc-editor.org/rfc/rfc8705#section-2.2.2
type DefaultMTLSClient struct {
	TLSClientAuthSubjectDN string `json:"tls_client_auth_subject_dn"`
	TLSClientAuthSANDNS    string `json:"tls_client_auth_san_dns"`
	TLSClientAuthSANURI    string `json:"tls_client_auth_san_uri"`
	TLSClientAuthSANIP     string `json:"tls_client_auth_san_ip"`
	TLSClientAuthSANEmail  string `json:"tls_client_auth_san_email"`

	*DefaultJARClient
}

// GetID returns the client ID.
func (c *DefaultClient) GetID() string {
	return c.ID
}

// IsPublic returns true if the client is marked as public.
func (c *DefaultClient) IsPublic() bool {
	return c.Public
}

// GetAudience returns the allowed audience(s) for the client.
func (c *DefaultClient) GetAudience() Arguments {
	return c.Audience
}

// GetResource returns the allowed RFC 8707 resource indicator(s) for the client.
func (c *DefaultClient) GetResource() Arguments {
	return c.Resource
}

// GetEnableDPoPBoundAccessTokens returns the 'dpop_bound_access_tokens' client metadata value.
func (c *DefaultClient) GetEnableDPoPBoundAccessTokens() bool {
	return c.DPoPBoundAccessTokens
}

// GetEnableTLSClientAuthBoundAccessTokens returns the 'tls_client_certificate_bound_access_tokens' client metadata
// value.
func (c *DefaultClient) GetEnableTLSClientAuthBoundAccessTokens() bool {
	return c.TLSClientCertificateBoundAccessTokens
}

// GetRedirectURIs returns the client's allowed redirect URIs.
func (c *DefaultClient) GetRedirectURIs() []string {
	return c.RedirectURIs
}

// GetClientSecret returns the ClientSecret.
func (c *DefaultClient) GetClientSecret() (secret ClientSecret) {
	return c.ClientSecret
}

// GetClientSecretPlainText returns the ClientSecret as plaintext if available. See Client for the semantics of the
// return values.
func (c *DefaultClient) GetClientSecretPlainText() (secret []byte, ok bool, err error) {
	if c.ClientSecret == nil || !c.ClientSecret.Valid() {
		return nil, false, nil
	}

	if !c.ClientSecret.IsPlainText() {
		return nil, true, nil
	}

	if secret, err = c.ClientSecret.GetPlainTextValue(); err != nil {
		return nil, true, err
	}

	return secret, true, nil
}

// GetRotatedClientSecrets returns the rotated client secrets.
func (c *DefaultClient) GetRotatedClientSecrets() (secrets []ClientSecret) {
	return c.RotatedClientSecrets
}

// GetScopes returns the scopes the client is allowed to request.
func (c *DefaultClient) GetScopes() Arguments {
	return c.Scopes
}

// GetGrantTypes returns the client's allowed grant types, defaulting to 'authorization_code' when none are set.
func (c *DefaultClient) GetGrantTypes() Arguments {
	// See: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
	if len(c.GrantTypes) == 0 {
		return Arguments{consts.GrantTypeAuthorizationCode}
	}

	return c.GrantTypes
}

// GetResponseTypes returns the client's allowed response types, defaulting to 'code' when none are set.
func (c *DefaultClient) GetResponseTypes() Arguments {
	// See: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
	if len(c.ResponseTypes) == 0 {
		return Arguments{"code"}
	}

	return c.ResponseTypes
}

// GetJSONWebKeysURI returns the 'jwks_uri' client metadata value.
func (c *DefaultJARClient) GetJSONWebKeysURI() string {
	return c.JSONWebKeysURI
}

// GetJSONWebKeys returns the 'jwks' client metadata value.
func (c *DefaultJARClient) GetJSONWebKeys() *jose.JSONWebKeySet {
	return c.JSONWebKeys
}

// GetTokenEndpointAuthSigningAlg returns the 'token_endpoint_auth_signing_alg' client metadata value. An empty value
// permits any supported algorithm per OpenID Connect Dynamic Client Registration 1.0 Section 2.
func (c *DefaultJARClient) GetTokenEndpointAuthSigningAlg() string {
	return c.TokenEndpointAuthSigningAlg
}

// GetIntrospectionEndpointAuthSigningAlg returns the 'introspection_endpoint_auth_signing_alg' client metadata value.
func (c *DefaultJARClient) GetIntrospectionEndpointAuthSigningAlg() string {
	return c.IntrospectionEndpointAuthSigningAlg
}

// GetRevocationEndpointAuthSigningAlg returns the 'revocation_endpoint_auth_signing_alg' client metadata value.
func (c *DefaultJARClient) GetRevocationEndpointAuthSigningAlg() string {
	return c.RevocationEndpointAuthSigningAlg
}

// GetRequireSignedRequestObject returns the 'require_signed_request_object' client metadata value.
func (c *DefaultJARClient) GetRequireSignedRequestObject() bool {
	return c.RequireSignedRequestObject
}

// GetRequestObjectSigningKeyID returns the 'request_object_signing_kid' client metadata value.
func (c *DefaultJARClient) GetRequestObjectSigningKeyID() string {
	return c.RequestObjectSigningKeyID
}

// GetRequestObjectSigningAlg returns the 'request_object_signing_alg' client metadata value.
func (c *DefaultJARClient) GetRequestObjectSigningAlg() string {
	return c.RequestObjectSigningAlg
}

// GetRequestObjectEncryptionKeyID returns the 'request_object_encryption_kid' client metadata value.
func (c *DefaultJARClient) GetRequestObjectEncryptionKeyID() string {
	return c.RequestObjectEncryptionKeyID
}

// GetRequestObjectEncryptionAlg returns the 'request_object_encryption_alg' client metadata value.
func (c *DefaultJARClient) GetRequestObjectEncryptionAlg() string {
	return c.RequestObjectEncryptionAlg
}

// GetRequestObjectEncryptionEnc returns the 'request_object_encryption_enc' client metadata value.
func (c *DefaultJARClient) GetRequestObjectEncryptionEnc() string {
	return c.RequestObjectEncryptionEnc
}

// GetTokenEndpointAuthMethod returns the 'token_endpoint_auth_method' client metadata value, defaulting to
// client_secret_basic when unset per RFC 7591 Section 2.
func (c *DefaultJARClient) GetTokenEndpointAuthMethod() string {
	if c.TokenEndpointAuthMethod == "" {
		return consts.ClientAuthMethodClientSecretBasic
	}

	return c.TokenEndpointAuthMethod
}

// GetIntrospectionEndpointAuthMethod returns the 'introspection_endpoint_auth_method' client metadata value.
func (c *DefaultJARClient) GetIntrospectionEndpointAuthMethod() string {
	return c.IntrospectionEndpointAuthMethod
}

// GetRevocationEndpointAuthMethod returns the 'revocation_endpoint_auth_method' client metadata value.
func (c *DefaultJARClient) GetRevocationEndpointAuthMethod() string {
	return c.RevocationEndpointAuthMethod
}

// GetRequestURIs returns the 'request_uris' client metadata value.
func (c *DefaultJARClient) GetRequestURIs() []string {
	return c.RequestURIs
}

// GetRequireRequestObjectAudienceAndLifetime returns true if this client's Request Objects must contain the 'aud',
// 'nbf' and 'exp' claims.
func (c *DefaultJARClient) GetRequireRequestObjectAudienceAndLifetime() bool {
	return c.RequireRequestObjectAudienceAndLifetime
}

// GetRequestObjectMaximumLifetime returns the custom bound for this client's Request Object 'nbf' and 'exp' claims, or
// 0 to utilize the global lifetime.
func (c *DefaultJARClient) GetRequestObjectMaximumLifetime() time.Duration {
	return c.RequestObjectMaximumLifetime
}

// GetResponseModes returns the response modes the client is allowed to use.
func (c *DefaultResponseModeClient) GetResponseModes() []ResponseModeType {
	return c.ResponseModes
}

// GetPostLogoutRedirectURIs returns the 'post_logout_redirect_uris' client metadata value.
func (c *DefaultRPInitiatedLogoutClient) GetPostLogoutRedirectURIs() (uris []string) {
	return c.PostLogoutRedirectURIs
}

// GetBackChannelLogoutURI returns the 'backchannel_logout_uri' client metadata value.
func (c *DefaultBackChannelLogoutClient) GetBackChannelLogoutURI() (uri string) {
	return c.BackChannelLogoutURI
}

// GetBackChannelLogoutSessionRequired returns the 'backchannel_logout_session_required' client metadata value.
func (c *DefaultBackChannelLogoutClient) GetBackChannelLogoutSessionRequired() (required bool) {
	return c.BackChannelLogoutSessionRequired
}

// GetTLSClientAuthSubjectDN returns the 'tls_client_auth_subject_dn' client metadata value.
func (c *DefaultMTLSClient) GetTLSClientAuthSubjectDN() string {
	return c.TLSClientAuthSubjectDN
}

// GetTLSClientAuthSANDNS returns the 'tls_client_auth_san_dns' client metadata value.
func (c *DefaultMTLSClient) GetTLSClientAuthSANDNS() string {
	return c.TLSClientAuthSANDNS
}

// GetTLSClientAuthSANURI returns the 'tls_client_auth_san_uri' client metadata value.
func (c *DefaultMTLSClient) GetTLSClientAuthSANURI() string {
	return c.TLSClientAuthSANURI
}

// GetTLSClientAuthSANIP returns the 'tls_client_auth_san_ip' client metadata value.
func (c *DefaultMTLSClient) GetTLSClientAuthSANIP() string {
	return c.TLSClientAuthSANIP
}

// GetTLSClientAuthSANEmail returns the 'tls_client_auth_san_email' client metadata value.
func (c *DefaultMTLSClient) GetTLSClientAuthSANEmail() string {
	return c.TLSClientAuthSANEmail
}

var (
	_ Client                      = (*DefaultClient)(nil)
	_ ResponseModeClient          = (*DefaultResponseModeClient)(nil)
	_ JARClient                   = (*DefaultJARClient)(nil)
	_ RequestObjectLifetimeClient = (*DefaultJARClient)(nil)
	_ RPInitiatedLogoutClient     = (*DefaultRPInitiatedLogoutClient)(nil)
	_ BackChannelLogoutClient     = (*DefaultBackChannelLogoutClient)(nil)
	_ TLSClientAuthClient         = (*DefaultMTLSClient)(nil)
	_ MTLSClient                  = (*DefaultMTLSClient)(nil)
	_ AuthenticationMethodClient  = (*DefaultMTLSClient)(nil)
)
