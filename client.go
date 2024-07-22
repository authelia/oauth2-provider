// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"time"

	"github.com/go-jose/go-jose/v4"

	"authelia.com/provider/oauth2/internal/consts"
)

// Client represents a client or an app.
type Client interface {
	// GetID returns the client ID.
	GetID() (id string)

	GetClientSecret() (secret ClientSecret)

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
}

// RotatedClientSecretsClient extends Client interface by a method providing a slice of rotated secrets.
type RotatedClientSecretsClient interface {
	GetRotatedClientSecrets() (secrets []ClientSecret)

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
	// determines the JWS alg algorithm [JWA] REQUIRED for signing the ID Token issued to this Client. The value none
	// MUST NOT be used as the ID Token alg value unless the Client uses only Response Types that return no ID Token
	// from the Authorization Endpoint (such as when only using the Authorization Code Flow). The default, if omitted,
	// is RS256. The public key for validating the signature is provided by retrieving the JWK Set referenced by the
	// jwks_uri element from OpenID Connect Discovery 1.0 [OpenID.Discovery].
	GetIDTokenSignedResponseAlg() (alg string)

	// GetIDTokenEncryptedResponseKeyID returns the specific key identifier used to satisfy JWE requirements of the ID
	// Token specifications. If unspecified the other available parameters will be utilized to select an appropriate
	// key.
	GetIDTokenEncryptedResponseKeyID() (kid string)

	// GetIDTokenEncryptedResponseAlg is equivalent to the 'id_token_encrypted_response_alg' client metadata value which
	// determines the JWE alg algorithm [JWA] REQUIRED for encrypting the ID Token issued to this Client. If this is
	// requested, the response will be signed then encrypted, with the result being a Nested JWT, as defined in [JWT].
	// The default, if omitted, is that no encryption is performed.
	GetIDTokenEncryptedResponseAlg() (alg string)

	// GetIDTokenEncryptedResponseEnc is equivalent to the 'id_token_encrypted_response_enc' client metadata value which
	// determines the JWE enc algorithm [JWA] REQUIRED for encrypting the ID Token issued to this Client. If
	// id_token_encrypted_response_alg is specified, the default id_token_encrypted_response_enc value is A128CBC-HS256.
	// When id_token_encrypted_response_enc is included, id_token_encrypted_response_alg MUST also be provided.
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
	// determines the JWS alg algorithm [JWA] REQUIRED for signing UserInfo Responses. If this is specified, the
	// response will be JWT [JWT] serialized, and signed using JWS. The default, if omitted, is for the UserInfo
	// Response to return the Claims as a UTF-8 [RFC3629] encoded JSON object using the application/json content-type.
	GetUserinfoSignedResponseAlg() (alg string)

	// GetUserinfoEncryptedResponseKeyID returns the specific key identifier used to satisfy JWE requirements of the
	// User Info specifications. If unspecified the other available parameters will be utilized to select an appropriate
	// key.
	GetUserinfoEncryptedResponseKeyID() (kid string)

	// GetUserinfoEncryptedResponseAlg is equivalent to the 'userinfo_encrypted_response_alg' client metadata value
	// which determines the JWE alg algorithm [JWA] REQUIRED for encrypting the ID Token issued to this Client. If
	// this is requested, the response will be signed then encrypted, with the result being a Nested JWT, as defined in
	// [JWT]. The default, if omitted, is that no encryption is performed.
	GetUserinfoEncryptedResponseAlg() (alg string)

	// GetUserinfoEncryptedResponseEnc is equivalent to the 'userinfo_encrypted_response_enc' client metadata value
	// which determines the JWE enc algorithm [JWA] REQUIRED for encrypting UserInfo Responses. If
	// userinfo_encrypted_response_alg is specified, the default userinfo_encrypted_response_enc value is A128CBC-HS256.
	// When userinfo_encrypted_response_enc is included, userinfo_encrypted_response_alg MUST also be provided.
	GetUserinfoEncryptedResponseEnc() (enc string)

	JSONWebKeysClient
}

// JWTSecuredAuthorizationRequestClient represents a client capable of performing OpenID Connect requests.
type JWTSecuredAuthorizationRequestClient interface {
	// GetRequestObjectSigningKeyID returns the specific key identifier used to satisfy JWS requirements of the request
	// object specifications. If unspecified the other available parameters will be utilized to select an appropriate
	// key.
	GetRequestObjectSigningKeyID() (kid string)

	// GetRequestObjectSigningAlg is equivalent to the 'request_object_signing_alg' client metadata
	// value which determines the JWS alg algorithm [JWA] that MUST be used for signing Request Objects sent to the OP.
	// All Request Objects from this Client MUST be rejected, if not signed with this algorithm. Request Objects are
	// described in Section 6.1 of OpenID Connect Core 1.0 [OpenID.Core]. This algorithm MUST be used both when the
	// Request Object is passed by value (using the request parameter) and when it is passed by reference (using the
	// request_uri parameter). Servers SHOULD support RS256. The value none MAY be used. The default, if omitted, is
	// that any algorithm supported by the OP and the RP MAY be used.
	GetRequestObjectSigningAlg() (alg string)

	// GetRequestObjectEncryptionKeyID returns the specific key identifier used to satisfy JWE requirements of the
	// request object specifications. If unspecified the other available parameters will be utilized to select an
	// appropriate key.
	GetRequestObjectEncryptionKeyID() (kid string)

	// GetRequestObjectEncryptionAlg is equivalent to the 'request_object_encryption_alg' client metadata value which
	// determines the JWE alg algorithm [JWA] the RP is declaring that it may use for encrypting Request Objects sent to
	// the OP. This parameter SHOULD be included when symmetric encryption will be used, since this signals to the OP
	// that a client_secret value needs to be returned from which the symmetric key will be derived, that might not
	// otherwise be returned. The RP MAY still use other supported encryption algorithms or send unencrypted Request
	// Objects, even when this parameter is present. If both signing and encryption are requested, the Request Object
	// will be signed then encrypted, with the result being a Nested JWT, as defined in [JWT]. The default, if omitted,
	// is that the RP is not declaring whether it might encrypt any Request Objects.
	GetRequestObjectEncryptionAlg() (alg string)

	// GetRequestObjectEncryptionEnc is equivalent to the 'request_object_encryption_enc' client metadata value which
	// determines the JWE enc algorithm [JWA] the RP is declaring that it may use for encrypting Request Objects sent to
	// the OP. If request_object_encryption_alg is specified, the default request_object_encryption_enc value is
	// A128CBC-HS256. When request_object_encryption_enc is included, request_object_encryption_alg MUST also be
	// provided.
	GetRequestObjectEncryptionEnc() (enc string)

	// GetRequestURIs is an array of request_uri values that are pre-registered by the RP for use at the OP. Servers MAY
	// cache the contents of the files referenced by these URIs and not retrieve them at the time they are used in a request.
	// OPs can require that request_uri values used be pre-registered with the require_request_uri_registration
	// discovery parameter.
	GetRequestURIs() (requestURIs []string)

	JSONWebKeysClient
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

// RevokeFlowRevokeRefreshTokensExplicitClient is a client which can be customized to only revoke Refresh Tokens
// explicitly.
type RevokeFlowRevokeRefreshTokensExplicitClient interface {
	// GetRevokeRefreshTokensExplicit returns true if this client will only revoke refresh tokens explicitly.
	GetRevokeRefreshTokensExplicit(ctx context.Context) (explicit bool)

	Client
}

// JARMClient is a client which supports JARM.
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
	// value which determines the JWE [RFC7516] alg algorithm JWA [RFC7518] REQUIRED for encrypting authorization
	// responses. If both signing and encryption are requested, the response will be signed then encrypted, with the
	// result being a Nested JWT, as defined in JWT [RFC7519]. The default, if omitted, is that no encryption is
	// performed.
	GetAuthorizationEncryptedResponseAlg() (alg string)

	// GetAuthorizationEncryptedResponseEnc is equivalent to the 'authorization_encrypted_response_enc' client
	// metadata value which determines the JWE [RFC7516] enc algorithm JWA [RFC7518] REQUIRED for encrypting
	// authorization responses. If authorization_encrypted_response_alg is specified, the default for this value is
	// A128CBC-HS256. When authorization_encrypted_response_enc is included, authorization_encrypted_response_alg MUST
	// also be provided.
	GetAuthorizationEncryptedResponseEnc() (alg string)

	Client
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

// ResponseModeClient represents a client capable of handling response_mode
type ResponseModeClient interface {
	// GetResponseModes returns the response modes that client is allowed to send
	GetResponseModes() (modes []ResponseModeType)

	Client
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

	// GetAccessTokenEncryptedResponseAlg determines the JWE [RFC7516] algorithm (alg value) as defined in JWA [RFC7518]
	// for content key encryption. If this is specified, the response will be encrypted using JWE and the configured
	// content encryption algorithm (access_token_encrypted_response_enc). The default, if omitted, is that no
	// encryption is performed. If both signing and encryption are requested, the response will be signed then
	// encrypted, with the result being a Nested JWT, as defined in JWT [RFC7519].
	GetAccessTokenEncryptedResponseAlg() (alg string)

	// GetAccessTokenEncryptedResponseEnc determines the JWE [RFC7516] algorithm (enc value) as defined in JWA [RFC7518]
	// for content encryption of access token responses. The default, if omitted, is A128CBC-HS256. Note: This parameter
	// MUST NOT be specified without setting access_token_encrypted_response_alg.
	GetAccessTokenEncryptedResponseEnc() (alg string)

	// GetEnableJWTProfileOAuthAccessTokens indicates this client should or should not issue JWT Profile Access Tokens.
	GetEnableJWTProfileOAuthAccessTokens() (enforce bool)

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
	//	// utilized to select an appropriate key.
	GetIntrospectionSignedResponseKeyID() (kid string)

	// GetIntrospectionSignedResponseAlg is equivalent to the 'introspection_signed_response_alg' client metadata
	// value which determines the JWS [RFC7515] algorithm (alg value) as defined in JWA [RFC7518] for signing
	// introspection responses. If this is specified, the response will be signed using JWS and the configured
	// algorithm. The default, if omitted, is RS256.
	GetIntrospectionSignedResponseAlg() (alg string)

	// GetIntrospectionEncryptedResponseKeyID returns the specific key identifier used to satisfy JWE requirements for
	// OAuth 2.0 JWT introspection response specifications. If unspecified the other available parameters will be
	//	// utilized to select an appropriate key.
	GetIntrospectionEncryptedResponseKeyID() (kid string)

	// GetIntrospectionEncryptedResponseAlg is equivalent to the 'introspection_encrypted_response_alg' client metadata
	// value which determines the JWE [RFC7516] algorithm (alg value) as defined in JWA [RFC7518] for content key
	// encryption. If this is specified, the response will be encrypted using JWE and the configured content encryption
	// algorithm (introspection_encrypted_response_enc). The default, if omitted, is that no encryption is performed.
	// If both signing and encryption are requested, the response will be signed then encrypted, with the result being
	// a Nested JWT, as defined in JWT [RFC7519].
	GetIntrospectionEncryptedResponseAlg() (alg string)

	// GetIntrospectionEncryptedResponseEnc is equivalent to the 'introspection_encrypted_response_enc' client metadata
	// value which determines the  JWE [RFC7516] algorithm (enc value) as defined in JWA [RFC7518] for content
	// encryption of introspection responses. The default, if omitted, is A128CBC-HS256. Note: This parameter MUST NOT
	// be specified without setting introspection_encrypted_response_alg.
	GetIntrospectionEncryptedResponseEnc() (enc string)

	Client
}

// DefaultClient is a simple default implementation of the Client interface.
type DefaultClient struct {
	ID                   string         `json:"id"`
	ClientSecret         ClientSecret   `json:"-"`
	RotatedClientSecrets []ClientSecret `json:"-"`
	RedirectURIs         []string       `json:"redirect_uris"`
	GrantTypes           []string       `json:"grant_types"`
	ResponseTypes        []string       `json:"response_types"`
	Scopes               []string       `json:"scopes"`
	Audience             []string       `json:"audience"`
	Public               bool           `json:"public"`
}

type DefaultJWTSecuredAuthorizationRequest struct {
	*DefaultClient
	JSONWebKeysURI                      string              `json:"jwks_uri"`
	JSONWebKeys                         *jose.JSONWebKeySet `json:"jwks"`
	TokenEndpointAuthMethod             string              `json:"token_endpoint_auth_method"`
	IntrospectionEndpointAuthMethod     string              `json:"introspection_endpoint_auth_method"`
	RevocationEndpointAuthMethod        string              `json:"revocation_endpoint_auth_method"`
	RequestURIs                         []string            `json:"request_uris"`
	RequestObjectSigningKeyID           string              `json:"request_object_signing_kid"`
	RequestObjectSigningAlg             string              `json:"request_object_signing_alg"`
	RequestObjectEncryptionKeyID        string              `json:"request_object_encryption_kid"`
	RequestObjectEncryptionAlg          string              `json:"request_object_encryption_alg"`
	RequestObjectEncryptionEnc          string              `json:"request_object_encryption_enc"`
	TokenEndpointAuthSigningAlg         string              `json:"token_endpoint_auth_signing_alg"`
	IntrospectionEndpointAuthSigningAlg string              `json:"introspection_endpoint_auth_signing_alg"`
	RevocationEndpointAuthSigningAlg    string              `json:"revocation_endpoint_auth_signing_alg"`
}

type DefaultResponseModeClient struct {
	*DefaultClient
	ResponseModes []ResponseModeType `json:"response_modes"`
}

func (c *DefaultClient) GetID() string {
	return c.ID
}

func (c *DefaultClient) IsPublic() bool {
	return c.Public
}

func (c *DefaultClient) GetAudience() Arguments {
	return c.Audience
}

func (c *DefaultClient) GetRedirectURIs() []string {
	return c.RedirectURIs
}

func (c *DefaultClient) GetClientSecret() (secret ClientSecret) {
	return c.ClientSecret
}

func (c *DefaultClient) GetRotatedClientSecrets() (secrets []ClientSecret) {
	return c.RotatedClientSecrets
}

func (c *DefaultClient) GetScopes() Arguments {
	return c.Scopes
}

func (c *DefaultClient) GetGrantTypes() Arguments {
	// https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
	//
	// JSON array containing a list of the OAuth 2.0 Grant Types that the Client is declaring
	// that it will restrict itself to using.
	// If omitted, the default is that the Client will use only the authorization_code Grant Type.
	if len(c.GrantTypes) == 0 {
		return Arguments{consts.GrantTypeAuthorizationCode}
	}

	return c.GrantTypes
}

func (c *DefaultClient) GetResponseTypes() Arguments {
	// https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
	//
	// JSON array containing a list of the OAuth 2.0 response_type values that the Client is declaring
	// that it will restrict itself to using. If omitted, the default is that the Client will use
	// only the code Response Type.
	if len(c.ResponseTypes) == 0 {
		return Arguments{"code"}
	}

	return c.ResponseTypes
}

func (c *DefaultJWTSecuredAuthorizationRequest) GetJSONWebKeysURI() string {
	return c.JSONWebKeysURI
}

func (c *DefaultJWTSecuredAuthorizationRequest) GetJSONWebKeys() *jose.JSONWebKeySet {
	return c.JSONWebKeys
}

func (c *DefaultJWTSecuredAuthorizationRequest) GetTokenEndpointAuthSigningAlg() string {
	if c.TokenEndpointAuthSigningAlg == "" {
		return "RS256"
	} else {
		return c.TokenEndpointAuthSigningAlg
	}
}

func (c *DefaultJWTSecuredAuthorizationRequest) GetIntrospectionEndpointAuthSigningAlg() string {
	return c.IntrospectionEndpointAuthSigningAlg
}

func (c *DefaultJWTSecuredAuthorizationRequest) GetRevocationEndpointAuthSigningAlg() string {
	return c.RevocationEndpointAuthSigningAlg
}

func (c *DefaultJWTSecuredAuthorizationRequest) GetRequestObjectSigningKeyID() string {
	return c.RequestObjectSigningKeyID
}

func (c *DefaultJWTSecuredAuthorizationRequest) GetRequestObjectSigningAlg() string {
	return c.RequestObjectSigningAlg
}

func (c *DefaultJWTSecuredAuthorizationRequest) GetRequestObjectEncryptionKeyID() string {
	return c.RequestObjectEncryptionKeyID
}

func (c *DefaultJWTSecuredAuthorizationRequest) GetRequestObjectEncryptionAlg() string {
	return c.RequestObjectEncryptionAlg
}

func (c *DefaultJWTSecuredAuthorizationRequest) GetRequestObjectEncryptionEnc() string {
	return c.RequestObjectEncryptionEnc
}

func (c *DefaultJWTSecuredAuthorizationRequest) GetTokenEndpointAuthMethod() string {
	return c.TokenEndpointAuthMethod
}

func (c *DefaultJWTSecuredAuthorizationRequest) GetIntrospectionEndpointAuthMethod() string {
	return c.IntrospectionEndpointAuthMethod
}

func (c *DefaultJWTSecuredAuthorizationRequest) GetRevocationEndpointAuthMethod() string {
	return c.RevocationEndpointAuthMethod
}

func (c *DefaultJWTSecuredAuthorizationRequest) GetRequestURIs() []string {
	return c.RequestURIs
}

func (c *DefaultResponseModeClient) GetResponseModes() []ResponseModeType {
	return c.ResponseModes
}

var (
	_ Client                               = (*DefaultClient)(nil)
	_ ResponseModeClient                   = (*DefaultResponseModeClient)(nil)
	_ JWTSecuredAuthorizationRequestClient = (*DefaultJWTSecuredAuthorizationRequest)(nil)
)
