// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"

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
	GetAllowMultipleAuthenticationMethods(ctx context.Context) (allow bool)

	Client
}

// OpenIDConnectClient represents a client capable of performing OpenID Connect requests.
type OpenIDConnectClient interface {
	// GetRequestURIs is an array of request_uri values that are pre-registered by the RP for use at the OP. Servers MAY
	// cache the contents of the files referenced by these URIs and not retrieve them at the time they are used in a request.
	// OPs can require that request_uri values used be pre-registered with the require_request_uri_registration
	// discovery parameter.
	GetRequestURIs() (requestURIs []string)

	// GetJSONWebKeys returns the JSON Web Key Set containing the public key used by the client to authenticate.
	GetJSONWebKeys() (jwks *jose.JSONWebKeySet)

	// GetJSONWebKeysURI returns the URL for lookup of JSON Web Key Set containing the
	// public key used by the client to authenticate.
	GetJSONWebKeysURI() (uri string)

	// GetRequestObjectSigningAlg returns the JWS [JWS] alg algorithm [JWA] that MUST be used for signing Request
	// Objects sent to the OP. All Request Objects from this Client MUST be rejected, if not signed with this algorithm.
	GetRequestObjectSigningAlg() (alg string)

	// GetTokenEndpointAuthMethod requested Client Authentication method for the Token Endpoint. The options are
	// client_secret_post, client_secret_basic, client_secret_jwt, private_key_jwt, and none.
	GetTokenEndpointAuthMethod() (method string)

	// GetTokenEndpointAuthSigningAlg returns the JWS [JWS] alg algorithm [JWA] that MUST be used for signing the
	// JWT [JWT] used to authenticate the Client at the Token Endpoint for the private_key_jwt and client_secret_jwt
	// authentication methods.
	GetTokenEndpointAuthSigningAlg() (alg string)

	Client
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
	GetAuthorizationSignedResponseKeyID() (kid string)
	GetAuthorizationSignedResponseAlg() (alg string)
	GetAuthorizationEncryptedResponseAlg() (alg string)
	GetAuthorizationEncryptedResponseEncryptionAlg() (alg string)

	Client
}

// ResponseModeClient represents a client capable of handling response_mode
type ResponseModeClient interface {
	// GetResponseModes returns the response modes that client is allowed to send
	GetResponseModes() (modes []ResponseModeType)

	Client
}

// ClientCredentialsFlowPolicyClient is a client which can allow implicit scopes in the client credentials flow.
type ClientCredentialsFlowPolicyClient interface {
	GetClientCredentialsFlowAllowImplicitScope() (allow bool)

	Client
}

type JWTProfileClient interface {
	// GetAccessTokenSignedResponseAlg returns the algorithm used for signing Access Tokens.
	GetAccessTokenSignedResponseAlg() (alg string)

	// GetAccessTokenSignedResponseKeyID returns the key id used for signing Access Tokens.
	GetAccessTokenSignedResponseKeyID() (kid string)

	// GetEnableJWTProfileOAuthAccessTokens indicates this client should or should not issue JWT Profile Access Tokens.
	GetEnableJWTProfileOAuthAccessTokens() (enforce bool)

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

type DefaultOpenIDConnectClient struct {
	*DefaultClient
	JSONWebKeysURI              string              `json:"jwks_uri"`
	JSONWebKeys                 *jose.JSONWebKeySet `json:"jwks"`
	TokenEndpointAuthMethod     string              `json:"token_endpoint_auth_method"`
	RequestURIs                 []string            `json:"request_uris"`
	RequestObjectSigningAlg     string              `json:"request_object_signing_alg"`
	TokenEndpointAuthSigningAlg string              `json:"token_endpoint_auth_signing_alg"`
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

func (c *DefaultOpenIDConnectClient) GetJSONWebKeysURI() string {
	return c.JSONWebKeysURI
}

func (c *DefaultOpenIDConnectClient) GetJSONWebKeys() *jose.JSONWebKeySet {
	return c.JSONWebKeys
}

func (c *DefaultOpenIDConnectClient) GetTokenEndpointAuthSigningAlg() string {
	if c.TokenEndpointAuthSigningAlg == "" {
		return "RS256"
	} else {
		return c.TokenEndpointAuthSigningAlg
	}
}

func (c *DefaultOpenIDConnectClient) GetRequestObjectSigningAlg() string {
	return c.RequestObjectSigningAlg
}

func (c *DefaultOpenIDConnectClient) GetTokenEndpointAuthMethod() string {
	return c.TokenEndpointAuthMethod
}

func (c *DefaultOpenIDConnectClient) GetRequestURIs() []string {
	return c.RequestURIs
}

func (c *DefaultResponseModeClient) GetResponseModes() []ResponseModeType {
	return c.ResponseModes
}

var (
	_ Client              = (*DefaultClient)(nil)
	_ ResponseModeClient  = (*DefaultResponseModeClient)(nil)
	_ OpenIDConnectClient = (*DefaultOpenIDConnectClient)(nil)
)
