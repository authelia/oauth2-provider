// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"hash"
	"html/template"
	"net/url"
	"sync"
	"time"

	"github.com/hashicorp/go-retryablehttp"

	"authelia.com/provider/oauth2/i18n"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

const (
	defaultPARPrefix                    = consts.PrefixRequestURI
	defaultPARContextLifetime           = 5 * time.Minute
	defaultBackChannelLogoutLifespan    = 5 * time.Minute
	defaultBackChannelLogoutConcurrency = 10
	defaultDPoPClockSkew                = 10 * time.Second
	defaultDPoPProofLifespan            = 10 * time.Second
)

type Config struct {
	// AccessTokenLifespan sets how long an access token is going to be valid. Defaults to one hour.
	AccessTokenLifespan time.Duration

	// VerifiableCredentialsNonceLifespan sets how long a verifiable credentials nonce is going to be valid. Defaults to one hour.
	VerifiableCredentialsNonceLifespan time.Duration

	// RefreshTokenLifespan sets how long a refresh token is going to be valid. Defaults to 30 days. Set to -1 for
	// refresh tokens that never expire.
	RefreshTokenLifespan time.Duration

	// AuthorizeCodeLifespan sets how long an authorize code is going to be valid. Defaults to fifteen minutes.
	AuthorizeCodeLifespan time.Duration

	// IDTokenLifespan sets the default id token lifetime. Defaults to one hour.
	IDTokenLifespan time.Duration

	// Sets how long a device user/device code pair is valid for
	RFC8628CodeLifespan time.Duration

	// IDTokenIssuer sets the default issuer of the ID Token.
	IDTokenIssuer string

	// AccessTokenIssuer is the issuer to be used when generating access tokens.
	AccessTokenIssuer string

	// 	AuthorizationServerIdentificationIssuer string sets the issuer identifier for authorization responses (RFC9207).
	AuthorizationServerIdentificationIssuer string

	// IntrospectionIssuer is the issuer to be used when generating signed introspection responses.
	IntrospectionIssuer string

	// IntrospectionJWTResponseStrategy is the signer for Introspection Responses. Has no default.
	IntrospectionJWTResponseStrategy jwt.Strategy

	// IDTokenValidationStrategy validates ID Tokens presented to the authorization server by a client, such as the
	// 'id_token_hint' of an RP-Initiated Logout request. Has no default.
	IDTokenValidationStrategy TokenValidationStrategy

	// BackChannelLogoutTokenStrategy generates the Logout Tokens delivered to Relying Parties for OpenID
	// Connect Back-Channel Logout. Has no default.
	BackChannelLogoutTokenStrategy BackChannelLogoutTokenStrategy

	// BackChannelLogoutLifespan is the lifespan of a Logout Token. Defaults to 5 minutes.
	BackChannelLogoutLifespan time.Duration

	// BackChannelLogoutConcurrency is the maximum number of Back-Channel Logout requests delivered
	// concurrently. Defaults to 10.
	BackChannelLogoutConcurrency int

	// HashCost sets the cost of the password hashing cost. Defaults to 12.
	HashCost int

	// DisableRefreshTokenValidation sets the introspection endpoint to disable refresh token validation.
	DisableRefreshTokenValidation bool

	// SendDebugMessagesToClients if set to true, includes error debug messages in response payloads. Be aware that sensitive
	// data may be exposed, depending on your implementation of Fosite. Such sensitive data might include database error
	// codes or other information. Proceed with caution!
	SendDebugMessagesToClients bool

	// RevokeRefreshTokensExplicit determines if Refresh Tokens should only be revoked explicitly.
	RevokeRefreshTokensExplicit bool

	// EnforceRevokeFlowRevokeRefreshTokensExplicitClient determines if a RevokeFlowRevokeRefreshTokensExplicitClient
	// should be prioritized even if it returns false.
	EnforceRevokeFlowRevokeRefreshTokensExplicitClient bool

	// ScopeStrategy sets the scope strategy that should be supported, for example oauth2.WildcardScopeStrategy.
	ScopeStrategy ScopeStrategy

	// AudienceStrategy sets the audience matching strategy that should be supported, defaults to oauth2.ExactAudienceStrategy.
	AudienceStrategy AudienceStrategy

	// ResourceStrategy sets the RFC 8707 resource indicator matching strategy, defaults to oauth2.DefaultAudienceStrategy.
	ResourceStrategy ResourceStrategy

	ClientCredentialsFlowImplicitGrantRequested bool

	// EnforcePKCE, if set to true, requires clients to perform authorize code flows with PKCE. Defaults to false.
	EnforcePKCE bool

	// EnforcePKCEForPublicClients requires only public clients to use PKCE with the authorize code flow. Defaults to false.
	EnforcePKCEForPublicClients bool

	// EnablePKCEPlainChallengeMethod sets whether or not to allow the plain challenge method (S256 should be used whenever possible, plain is really discouraged). Defaults to false.
	EnablePKCEPlainChallengeMethod bool

	// AllowedPromptValues sets which OpenID Connect prompt values the server supports. Defaults to []string{"login", "none", "consent", "select_account"}.
	AllowedPromptValues []string

	// EnforceClientAssertionIssuerAudience requires a JWT client authentication assertion to carry the issuer
	// identifier as the sole value of its 'aud' claim. See GetEnforceClientAssertionIssuerAudience.
	EnforceClientAssertionIssuerAudience bool

	// AllowedJWTAssertionAudiences is a list of permitted client assertion audiences. If the authorization server is
	// intended to be compatible with the client_secret_jwt or private_key_jwt client authentication methods
	// (see http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth), this value MUST be set.
	AllowedJWTAssertionAudiences []string

	// AllowedIntrospectionAudiences is a list of audiences permitted for an Access Token used to authenticate a request
	// to the introspection endpoint. Such an Access Token MUST have at least one of these values within its granted
	// audience or granted RFC 8707 resource indicators. Defaults to empty, which does not disable the check: it means
	// the URL the request was made to is expected instead.
	AllowedIntrospectionAudiences []string

	// AllowedIntrospectionScopes is a list of scopes permitted for an Access Token used to authenticate a request to
	// the introspection endpoint. Such an Access Token MUST have at least one of these values within its granted
	// scopes. Defaults to consts.ScopeIntrospection.
	AllowedIntrospectionScopes []string

	// JWKSFetcherStrategy is responsible for fetching JSON Web Keys from remote URLs. This is required when the private_key_jwt
	// client authentication method is used. Defaults to oauth2.DefaultJWKSFetcherStrategy.
	JWKSFetcherStrategy jwt.JWKSFetcherStrategy

	// TokenEntropy indicates the entropy of the random string, used as the "message" part of the HMAC token.
	// Defaults to 32.
	TokenEntropy int

	// RFC8628UserVerificationURL is the URL of the device verification endpoint, this is is included with the device code request responses
	RFC8628UserVerificationURL string

	// RFC8628TokenPollingInterval sets the interval that clients should check for device code grants
	RFC8628TokenPollingInterval time.Duration

	// RedirectSecureChecker is a function that returns true if the provided URL can be securely used as a redirect URL.
	RedirectSecureChecker func(context.Context, *url.URL) bool

	// RefreshTokenScopes defines which OAuth scopes will be given refresh tokens during the authorization code grant exchange. This defaults to "offline" and "offline_access". When set to an empty array, all exchanges will be given refresh tokens.
	RefreshTokenScopes []string

	// MinParameterEntropy controls the minimum size of state and nonce parameters. Defaults to oauth2.MinParameterEntropy.
	MinParameterEntropy int

	// UseLegacyErrorFormat controls whether the legacy error format (with `error_debug`, `error_hint`, ...)
	// should be used or not.
	UseLegacyErrorFormat bool

	// GrantTypeJWTBearerCanSkipClientAuth indicates, if client authentication can be skipped, when using jwt as assertion.
	GrantTypeJWTBearerCanSkipClientAuth bool

	// GrantTypeJWTBearerIDOptional indicates, if jti (JWT ID) claim required or not in JWT.
	GrantTypeJWTBearerIDOptional bool

	// GrantTypeJWTBearerIssuedDateOptional indicates, if "iat" (issued at) claim required or not in JWT.
	GrantTypeJWTBearerIssuedDateOptional bool

	// GrantTypeJWTBearerMaxDuration sets the maximum time after JWT issued date, during which the JWT is considered valid.
	GrantTypeJWTBearerMaxDuration time.Duration

	// ClientAuthenticationStrategy indicates the Strategy to authenticate client requests
	ClientAuthenticationStrategy ClientAuthenticationStrategy

	// TokenEndpointClientAuthStrategy indicates the EndpointClientAuthStrategy used to authenticate clients at the token
	// endpoint. Defaults to a TokenEndpointClientAuthStrategy.
	TokenEndpointClientAuthStrategy EndpointClientAuthStrategy

	// IntrospectionEndpointClientAuthStrategy indicates the EndpointClientAuthStrategy used to authenticate clients at
	// the introspection endpoint. Defaults to an IntrospectionEndpointClientAuthStrategy.
	IntrospectionEndpointClientAuthStrategy EndpointClientAuthStrategy

	// IntrospectionEndpointClientAuthDisabled turns off client authentication at the introspection endpoint, leaving
	// an Access Token presented as a bearer credential the only way to authorize a call to it. Defaults to false,
	// which permits both. See IntrospectionEndpointClientAuthDisabledProvider for why a deployment would set it.
	IntrospectionEndpointClientAuthDisabled bool

	// RevocationEndpointClientAuthStrategy indicates the EndpointClientAuthStrategy used to authenticate clients at the
	// revocation endpoint. Defaults to a RevocationEndpointClientAuthStrategy.
	RevocationEndpointClientAuthStrategy EndpointClientAuthStrategy

	// AuthorizeErrorFieldResponseStrategy handles authorize error responses when the user can't be redirected in a
	// normal way for example when the redirect uri is invalid or for any other reason, just writing the fields in some
	// way to the response. By default this happens as a JSON document but this may also be a redirect to a internal
	// page as well.
	AuthorizeErrorFieldResponseStrategy AuthorizeErrorFieldResponseStrategy

	// ResponseModeHandlers provides the handlers for performing response mode formatting.
	ResponseModeHandlers ResponseModeHandlers

	// ResponseModeParameterHandlers provides handlers for injecting additional parameters into the authorize responses.
	ResponseModeParameterHandlers ResponseModeParameterHandlers

	// MessageCatalog is the message bundle used for i18n
	MessageCatalog i18n.MessageCatalog

	// FormPostHTMLTemplate sets html template for rendering the authorization response when the request has response_mode=form_post.
	FormPostHTMLTemplate *template.Template

	// FormPostResponseWriter is the FormPostResponseWriter used for writing the form post response. Useful for
	// overwriting the behaviour of this element.
	FormPostResponseWriter FormPostResponseWriter

	// OmitRedirectScopeParam indicates whether the "scope" parameter should be omitted from the redirect URL.
	OmitRedirectScopeParam bool

	// SanitationWhiteList is a whitelist of form values that are required by the token endpoint. These values
	// are safe for storage in a database (cleartext).
	SanitationWhiteList []string

	// JWTScopeClaimKey defines the claim key to be used to set the scope in. Valid fields are "scope" or "scp" or both.
	JWTScopeClaimKey jwt.JWTScopeFieldEnum

	// JWTSecuredAuthorizeResponseModeIssuer sets the default issuer for the JWT Secured Authorization Response Mode.
	JWTSecuredAuthorizeResponseModeIssuer string

	// JWTSecuredAuthorizeResponseModeLifespan sets the default lifetime for the tokens issued in the
	// JWT Secured Authorization Response Mode. Defaults to 10 minutes.
	JWTSecuredAuthorizeResponseModeLifespan time.Duration

	// JWTSecuredAuthorizeResponseModeStrategy is the signer for JWT Secured Authorization Response Mode. Has no default.
	JWTSecuredAuthorizeResponseModeStrategy jwt.Strategy

	// JWTStrategy handles less specific jwt.Strategy cases.
	JWTStrategy jwt.Strategy

	// EnforceJWTProfileAccessTokens forces the issuer to return JWT Profile Access Tokens to all clients.
	EnforceJWTProfileAccessTokens bool

	// HTTPClient is the HTTP client to use for requests.
	HTTPClient *retryablehttp.Client

	// AuthorizeEndpointHandlers is a list of handlers that are called before the authorization endpoint is served.
	AuthorizeEndpointHandlers AuthorizeEndpointHandlers

	// TokenEndpointHandlers is a list of handlers that are called before the token endpoint is served.
	TokenEndpointHandlers TokenEndpointHandlers

	// AuthorizeEndpointBindingHandlers is a list of handlers that record a proof-of-possession binding on an
	// authorize request before the authorize endpoint handlers run.
	AuthorizeEndpointBindingHandlers AuthorizeEndpointBindingHandlers

	// TokenEndpointBindingHandlers is a list of handlers that record and enforce a proof-of-possession binding on
	// an access request a grant handler has accepted.
	TokenEndpointBindingHandlers TokenEndpointBindingHandlers

	// TokenIntrospectionHandlers is a list of handlers that are called before the token introspection endpoint is served.
	TokenIntrospectionHandlers TokenIntrospectionHandlers

	// RevocationHandlers is a list of handlers that are called before the revocation endpoint is served.
	RevocationHandlers RevocationHandlers

	// PushedAuthorizeEndpointHandlers is a list of handlers that are called before the PAR endpoint is served.
	PushedAuthorizeEndpointHandlers PushedAuthorizeEndpointHandlers

	// RFC8628DeviceAuthorizeEndpointHandlers is a list of handlers that are called before the device authorization endpoint is served.
	RFC8628DeviceAuthorizeEndpointHandlers RFC8628DeviceAuthorizeEndpointHandlers

	// RFC8628UserAuthorizeEndpointHandlers is a list of handlers that are called before the device grant user interaction endpoint is served.
	RFC8628UserAuthorizeEndpointHandlers RFC8628UserAuthorizeEndpointHandlers

	// RFC7591ClientRegistrationEndpointHandlers is a list of handlers that are called before the client registration endpoint is served.
	RFC7591ClientRegistrationEndpointHandlers RFC7591ClientRegistrationEndpointHandlers

	// RFC7592ClientConfigurationEndpointHandlers is a list of handlers that are called before the client configuration endpoint is served.
	RFC7592ClientConfigurationEndpointHandlers RFC7592ClientConfigurationEndpointHandlers

	// GlobalSecret is the global secret used to sign and verify signatures.
	GlobalSecret []byte

	// RotatedGlobalSecrets is a list of global secrets that are used to verify signatures.
	RotatedGlobalSecrets [][]byte

	// HMACHasher is the hasher used to generate HMAC signatures.
	HMACHasher func() hash.Hash

	// PushedAuthorizeRequestURIPrefix is the URI prefix for the PAR request_uri.
	// This is defaulted to 'urn:ietf:params:oauth:request_uri:'.
	PushedAuthorizeRequestURIPrefix string

	// PushedAuthorizeContextLifespan is the lifespan of the PAR context
	PushedAuthorizeContextLifespan time.Duration

	// RequirePushedAuthorizationRequests requires pushed authorization request for /authorize
	RequirePushedAuthorizationRequests bool

	// RequireSignedRequestObject requires all authorization requests be protected as a signed Request Object provided
	// by either the 'request' or 'request_uri' parameter. This is equivalent to the 'require_signed_request_object'
	// authorization server metadata value.
	RequireSignedRequestObject bool

	// RequireSignedRequestObjectSkipPushedAuthorizationRequests skips the signed Request Object requirement for
	// requests made directly to the Pushed Authorization Request endpoint. This applies to the requirement from both
	// the authorization server and client metadata values.
	RequireSignedRequestObjectSkipPushedAuthorizationRequests bool

	RFC8693TokenTypes map[string]RFC8693TokenType

	DefaultRequestedTokenType string

	// DPoPEnabled enables RFC 9449 DPoP handling.
	DPoPEnabled bool

	// DPoPEnforce requires DPoP for all clients regardless of client metadata.
	DPoPEnforce bool

	// DPoPAllowedJWSAlgorithms is the permitted asymmetric DPoP proof signing algorithms.
	DPoPAllowedJWSAlgorithms []string

	// DPoPClockSkew is the tolerance allowed for disagreement between this server's clock and the client's when
	// judging a DPoP proof's 'iat' claim. Defaults to ten seconds.
	//
	// It is not how long a proof lasts; that is DPoPProofLifespan. Skew widens the acceptance window at both ends,
	// so a proof is accepted from DPoPClockSkew before its 'iat' until DPoPProofLifespan+DPoPClockSkew after it.
	// Raise this, and only this, to tolerate clients whose clocks are not synchronized.
	DPoPClockSkew time.Duration

	// DPoPProofLifespan is how long a DPoP proof remains valid after the 'iat' it was minted with. Defaults to ten
	// seconds.
	//
	// A proof is single use, so this bounds how long a captured one could be replayed if the replay record were
	// lost, and how long a client may sit on a proof before sending it. Combined with the default DPoPClockSkew a
	// proof is usable for at most 20 seconds after it was minted.
	DPoPProofLifespan time.Duration

	// DPoPNonceRequired requires a server nonce in DPoP proofs.
	DPoPNonceRequired bool

	// DPoPNonceLifespan is the lifespan of issued DPoP server nonces. Defaults to one hour.
	DPoPNonceLifespan time.Duration

	// DPoPStrategy is the configured DPoP strategy.
	DPoPStrategy DPoPStrategy

	// MTLSEnabled enables RFC 8705 Mutual-TLS handling.
	MTLSEnabled bool

	// MTLSEnforce requires certificate-bound access tokens for all clients regardless of client metadata.
	MTLSEnforce bool

	// MTLSClientCertificateHeader is the name of the header a trusted TLS terminating proxy forwards the client
	// certificate in, for example 'X-Forwarded-Tls-Client-Cert'. It is empty by default, which disables the header
	// entirely so that only a certificate from the TLS connection itself is used.
	//
	// Setting this is a decision to trust the named header absolutely. It is not authenticated, and a request that
	// reaches this server without transiting the proxy can set it to any value, authenticating the sender as any
	// client registered with an mTLS authentication method and binding tokens to a certificate it does not hold. A
	// deployment that sets this MUST ensure the proxy unconditionally overwrites the header on every inbound request,
	// and that the server is unreachable except through that proxy.
	//
	// The certificate chain is not validated here. For a certificate from the TLS connection Go has already done so
	// against the listener's ClientCAs; for a forwarded one the proxy that performed the handshake is the component
	// that validated it, and RFC 8705 Section 6.5 places that channel out of scope. Per Section 7.4 the trust anchors
	// accepted there SHOULD be limited to CAs whose issuance policy meets this server's requirements.
	MTLSClientCertificateHeader string

	// RFC7591ClientRegistrationGlobalSecret is the secret used to sign client registration tokens. It is
	// deliberately separate from GlobalSecret: a client management token never expires and RFC 7592 provides no way
	// to re-issue one, so signing it with the global secret would mean routine rotation of that secret permanently
	// locked every registered client out of its own registration.
	RFC7591ClientRegistrationGlobalSecret []byte

	// RFC7591ClientRegistrationRotatedGlobalSecrets is a list of rotated client registration token secrets, which
	// remain valid for verification but are not used for signing.
	RFC7591ClientRegistrationRotatedGlobalSecrets [][]byte

	// RFC7591ClientRegistrationEndpointURL is the absolute URL of the client registration endpoint.
	RFC7591ClientRegistrationEndpointURL string

	// RFC7591ClientSecretLifespan is the lifespan used to derive 'client_secret_expires_at'. Zero means the secret
	// does not expire.
	RFC7591ClientSecretLifespan time.Duration

	// RFC7591ClientRegistrationStrategy is the strategy used to construct and patch clients.
	RFC7591ClientRegistrationStrategy ClientRegistrationStrategy

	// RFC7591ClientRegistrationMetadataStrategy is the strategy used to filter client metadata before it reaches
	// the client registration strategy and before it is returned to the client.
	RFC7591ClientRegistrationMetadataStrategy ClientRegistrationMetadataStrategy

	// RFC7591ClientRegistrationEndpointAuthStrategy is the strategy used to authenticate requests at the client
	// registration and client configuration endpoints.
	RFC7591ClientRegistrationEndpointAuthStrategy ClientRegistrationEndpointAuthStrategy

	// RFC7591ClientRegistrationValidators are the validators run in order against submitted metadata.
	RFC7591ClientRegistrationValidators []ClientRegistrationValidator

	// RFC7591ClientRegistrationEndpointAudiences are the audiences a client creation token may carry. The token must
	// carry at least one of them. Empty means the configured registration endpoint URL is expected, falling back to
	// the request URL.
	RFC7591ClientRegistrationEndpointAudiences []string

	// RFC7591ClientRegistrationScopes are the scopes a client creation token may carry. The token must carry at least
	// one of them. Empty means consts.ScopeClientRegistration.
	RFC7591ClientRegistrationScopes []string

	// RFC7591ClientRegistrationGrantTypes are the grant types a client may register for. Empty permits any grant.
	// See GetRFC7591ClientRegistrationGrantTypes for why, and when a deployment should set it.
	RFC7591ClientRegistrationGrantTypes []string

	formPostResponseWriterOnce                  sync.Once
	responseModeHandlersOnce                    sync.Once
	jwtStrategyOnce                             sync.Once
	scopeStrategyOnce                           sync.Once
	audienceStrategyOnce                        sync.Once
	resourceStrategyOnce                        sync.Once
	jwksFetcherStrategyOnce                     sync.Once
	authorizeErrorFieldResponseStrategyOnce     sync.Once
	tokenEndpointClientAuthStrategyOnce         sync.Once
	introspectionEndpointClientAuthStrategyOnce sync.Once
	revocationEndpointClientAuthStrategyOnce    sync.Once
}

func (c *Config) GetGlobalSecret(ctx context.Context) ([]byte, error) {
	return c.GlobalSecret, nil
}

func (c *Config) GetUseLegacyErrorFormat(ctx context.Context) bool {
	return c.UseLegacyErrorFormat
}

func (c *Config) GetRotatedGlobalSecrets(ctx context.Context) ([][]byte, error) {
	return c.RotatedGlobalSecrets, nil
}

func (c *Config) GetHMACHasher(ctx context.Context) func() hash.Hash {
	return c.HMACHasher
}

func (c *Config) GetAuthorizeEndpointHandlers(ctx context.Context) AuthorizeEndpointHandlers {
	return c.AuthorizeEndpointHandlers
}

func (c *Config) GetTokenEndpointHandlers(ctx context.Context) TokenEndpointHandlers {
	return c.TokenEndpointHandlers
}

func (c *Config) GetAuthorizeEndpointBindingHandlers(ctx context.Context) AuthorizeEndpointBindingHandlers {
	return c.AuthorizeEndpointBindingHandlers
}

func (c *Config) GetTokenEndpointBindingHandlers(ctx context.Context) TokenEndpointBindingHandlers {
	return c.TokenEndpointBindingHandlers
}

func (c *Config) GetTokenIntrospectionHandlers(ctx context.Context) TokenIntrospectionHandlers {
	return c.TokenIntrospectionHandlers
}

func (c *Config) GetRevocationHandlers(ctx context.Context) RevocationHandlers {
	return c.RevocationHandlers
}

func (c *Config) GetRFC8628DeviceAuthorizeEndpointHandlers(_ context.Context) RFC8628DeviceAuthorizeEndpointHandlers {
	return c.RFC8628DeviceAuthorizeEndpointHandlers
}

func (c *Config) GetRFC8628UserAuthorizeEndpointHandlers(_ context.Context) RFC8628UserAuthorizeEndpointHandlers {
	return c.RFC8628UserAuthorizeEndpointHandlers
}

func (c *Config) GetRFC7591ClientRegistrationEndpointHandlers(_ context.Context) RFC7591ClientRegistrationEndpointHandlers {
	return c.RFC7591ClientRegistrationEndpointHandlers
}

func (c *Config) GetRFC7592ClientConfigurationEndpointHandlers(_ context.Context) RFC7592ClientConfigurationEndpointHandlers {
	return c.RFC7592ClientConfigurationEndpointHandlers
}

func (c *Config) GetHTTPClient(ctx context.Context) *retryablehttp.Client {
	if c.HTTPClient == nil {
		return retryablehttp.NewClient()
	}

	return c.HTTPClient
}

func (c *Config) GetAllowedJWTAssertionAudiences(ctx context.Context) []string {
	return c.AllowedJWTAssertionAudiences
}

// GetEnforceClientAssertionIssuerAudience returns whether a JWT client authentication assertion must carry this
// server's issuer identifier as the sole value of its 'aud' claim.
//
// draft-ietf-oauth-rfc7523bis Section 4 replaces RFC 7523 Section 3 item 3 and differentiates two cases: the
// authorization grant MAY identify the server by "either its issuer identifier or its token endpoint URL", while for
// client authentication the value "MUST use the issuer identifier of the authorization server as its sole value",
// adding that "the token endpoint URL ... MUST NOT be used as an audience value". Accepting either at both endpoints
// is the ambiguity Audience.Injection exploits: an assertion minted for one endpoint is replayed at another.
//
// It is off by default because the tightening lives in a draft, while published RFC 7523 permits the token endpoint
// URL, so enabling it rejects assertions from clients that conform to the published specification. A deployment
// whose clients have adopted the draft should turn it on; the default should be revisited when the draft is
// published.
func (c *Config) GetEnforceClientAssertionIssuerAudience(ctx context.Context) (enforce bool) {
	return c.EnforceClientAssertionIssuerAudience
}

func (c *Config) GetAllowedIntrospectionAudiences(ctx context.Context) (audiences []string) {
	return c.AllowedIntrospectionAudiences
}

func (c *Config) GetAllowedIntrospectionScopes(ctx context.Context) (scopes []string) {
	if len(c.AllowedIntrospectionScopes) == 0 {
		return []string{consts.ScopeIntrospection}
	}

	return c.AllowedIntrospectionScopes
}

func (c *Config) GetFormPostHTMLTemplate(ctx context.Context) *template.Template {
	return c.FormPostHTMLTemplate
}

func (c *Config) GetFormPostResponseWriter(ctx context.Context) FormPostResponseWriter {
	c.formPostResponseWriterOnce.Do(func() {
		if c.FormPostResponseWriter == nil {
			c.FormPostResponseWriter = DefaultFormPostResponseWriter
		}
	})

	return c.FormPostResponseWriter
}

func (c *Config) GetMessageCatalog(ctx context.Context) i18n.MessageCatalog {
	return c.MessageCatalog
}

func (c *Config) GetResponseModeHandlers(ctx context.Context) ResponseModeHandlers {
	c.responseModeHandlersOnce.Do(func() {
		if len(c.ResponseModeHandlers) == 0 {
			c.ResponseModeHandlers = []ResponseModeHandler{&DefaultResponseModeHandler{Config: c}}
		}
	})

	return c.ResponseModeHandlers
}

func (c *Config) GetResponseModeParameterHandlers(ctx context.Context) ResponseModeParameterHandlers {
	return c.ResponseModeParameterHandlers
}

func (c *Config) GetSendDebugMessagesToClients(ctx context.Context) bool {
	return c.SendDebugMessagesToClients
}

func (c *Config) GetRevokeRefreshTokensExplicit(ctx context.Context) bool {
	return c.RevokeRefreshTokensExplicit
}

func (c *Config) GetEnforceRevokeFlowRevokeRefreshTokensExplicitClient(ctx context.Context) bool {
	return c.EnforceRevokeFlowRevokeRefreshTokensExplicitClient
}

func (c *Config) GetIDTokenIssuer(ctx context.Context) string {
	return c.IDTokenIssuer
}

func (c *Config) GetIDTokenValidationStrategy(ctx context.Context) (strategy TokenValidationStrategy) {
	return c.IDTokenValidationStrategy
}

func (c *Config) GetBackChannelLogoutTokenStrategy(ctx context.Context) (strategy BackChannelLogoutTokenStrategy) {
	return c.BackChannelLogoutTokenStrategy
}

func (c *Config) GetBackChannelLogoutLifespan(ctx context.Context) (lifespan time.Duration) {
	if c.BackChannelLogoutLifespan <= 0 {
		return defaultBackChannelLogoutLifespan
	}

	return c.BackChannelLogoutLifespan
}

func (c *Config) GetBackChannelLogoutConcurrency(ctx context.Context) (n int) {
	if c.BackChannelLogoutConcurrency <= 0 {
		return defaultBackChannelLogoutConcurrency
	}

	return c.BackChannelLogoutConcurrency
}

func (c *Config) GetAuthorizationServerIdentificationIssuer(ctx context.Context) (issuer string) {
	return c.AuthorizationServerIdentificationIssuer
}

func (c *Config) GetIntrospectionIssuer(ctx context.Context) string {
	return c.IntrospectionIssuer
}

func (c *Config) GetIntrospectionJWTResponseStrategy(ctx context.Context) jwt.Strategy {
	return c.IntrospectionJWTResponseStrategy
}

// GetGrantTypeJWTBearerIssuedDateOptional returns the GrantTypeJWTBearerIssuedDateOptional field.
func (c *Config) GetGrantTypeJWTBearerIssuedDateOptional(ctx context.Context) bool {
	return c.GrantTypeJWTBearerIssuedDateOptional
}

// GetGrantTypeJWTBearerIDOptional returns the GrantTypeJWTBearerIDOptional field.
func (c *Config) GetGrantTypeJWTBearerIDOptional(ctx context.Context) bool {
	return c.GrantTypeJWTBearerIDOptional
}

// GetGrantTypeJWTBearerCanSkipClientAuth returns the GrantTypeJWTBearerCanSkipClientAuth field.
func (c *Config) GetGrantTypeJWTBearerCanSkipClientAuth(ctx context.Context) bool {
	return c.GrantTypeJWTBearerCanSkipClientAuth
}

// GetEnforcePKCE If set to true, public clients must use PKCE.
func (c *Config) GetEnforcePKCE(ctx context.Context) bool {
	return c.EnforcePKCE
}

// GetEnablePKCEPlainChallengeMethod returns whether or not to allow the plain challenge method (S256 should be used whenever possible, plain is really discouraged).
func (c *Config) GetEnablePKCEPlainChallengeMethod(ctx context.Context) bool {
	return c.EnablePKCEPlainChallengeMethod
}

// GetEnforcePKCEForPublicClients returns the value of EnforcePKCEForPublicClients.
func (c *Config) GetEnforcePKCEForPublicClients(ctx context.Context) bool {
	return c.EnforcePKCEForPublicClients
}

// GetSanitationWhiteList returns a list of allowed form values that are required by the token endpoint. These values
// are safe for storage in a database (cleartext).
func (c *Config) GetSanitationWhiteList(ctx context.Context) []string {
	return c.SanitationWhiteList
}

func (c *Config) GetOmitRedirectScopeParam(ctx context.Context) bool {
	return c.OmitRedirectScopeParam
}

// GetAccessTokenIssuer returns the issuer for JWT profile access tokens, falling back to the ID Token issuer. RFC 9068
// Section 2.2 makes 'iss' a required claim, and RFC 8414 gives an authorization server one issuer identifier, so the
// value that identifies it as an ID Token issuer identifies it here too. Without the fallback a deployment that
// enabled JWT profile access tokens without setting this minted tokens carrying no 'iss' at all.
func (c *Config) GetAccessTokenIssuer(ctx context.Context) string {
	if c.AccessTokenIssuer == "" {
		return c.IDTokenIssuer
	}

	return c.AccessTokenIssuer
}

func (c *Config) GetJWTScopeField(ctx context.Context) jwt.JWTScopeFieldEnum {
	return c.JWTScopeClaimKey
}

func (c *Config) GetJWTSecuredAuthorizeResponseModeIssuer(ctx context.Context) string {
	return c.IDTokenIssuer
}

func (c *Config) GetJWTSecuredAuthorizeResponseModeStrategy(ctx context.Context) jwt.Strategy {
	return c.JWTSecuredAuthorizeResponseModeStrategy
}

func (c *Config) GetJWTStrategy(ctx context.Context) jwt.Strategy {
	c.jwtStrategyOnce.Do(func() {
		if c.JWTStrategy == nil {
			c.JWTStrategy = &jwt.DefaultStrategy{
				Config: c,
			}
		}
	})

	return c.JWTStrategy
}

func (c *Config) GetEnforceJWTProfileAccessTokens(ctx context.Context) (enable bool) {
	return c.EnforceJWTProfileAccessTokens
}

func (c *Config) GetAllowedPrompts(_ context.Context) []string {
	return c.AllowedPromptValues
}

// GetScopeStrategy returns the scope strategy to be used. Defaults to glob scope strategy.
func (c *Config) GetScopeStrategy(_ context.Context) ScopeStrategy {
	c.scopeStrategyOnce.Do(func() {
		if c.ScopeStrategy == nil {
			c.ScopeStrategy = WildcardScopeStrategy
		}
	})

	return c.ScopeStrategy
}

// GetAudienceStrategy returns the audience matching strategy. Defaults to ExactAudienceStrategy
// (audience parameter values are matched against the client's allowed audience list via exact string equality).
func (c *Config) GetAudienceStrategy(_ context.Context) AudienceStrategy {
	c.audienceStrategyOnce.Do(func() {
		if c.AudienceStrategy == nil {
			c.AudienceStrategy = DefaultAudienceStrategy
		}
	})

	return c.AudienceStrategy
}

// GetResourceStrategy returns the RFC 8707 resource indicator matching strategy. Defaults to
// DefaultAudienceStrategy (URL-based matching against the client's allowed audience list).
func (c *Config) GetResourceStrategy(_ context.Context) ResourceStrategy {
	c.resourceStrategyOnce.Do(func() {
		if c.ResourceStrategy == nil {
			c.ResourceStrategy = DefaultAudienceStrategy
		}
	})

	return c.ResourceStrategy
}

func (c *Config) GetClientCredentialsFlowImplicitGrantRequested(_ context.Context) bool {
	return c.ClientCredentialsFlowImplicitGrantRequested
}

// GetAuthorizeCodeLifespan returns how long an authorize code should be valid. Defaults to one fifteen minutes.
func (c *Config) GetAuthorizeCodeLifespan(_ context.Context) time.Duration {
	if c.AuthorizeCodeLifespan == 0 {
		return time.Minute * 15
	}

	return c.AuthorizeCodeLifespan
}

// GetIDTokenLifespan returns how long an id token should be valid. Defaults to one hour.
func (c *Config) GetIDTokenLifespan(_ context.Context) time.Duration {
	if c.IDTokenLifespan == 0 {
		return time.Hour
	}

	return c.IDTokenLifespan
}

// GetRFC8628CodeLifespan returns the device and user code lifespan.
func (c *Config) GetRFC8628CodeLifespan(_ context.Context) time.Duration {
	if c.RFC8628CodeLifespan == 0 {
		return time.Minute * 10
	}

	return c.RFC8628CodeLifespan
}

// GetAccessTokenLifespan returns how long an access token should be valid. Defaults to one hour.
func (c *Config) GetAccessTokenLifespan(_ context.Context) time.Duration {
	if c.AccessTokenLifespan == 0 {
		return time.Hour
	}

	return c.AccessTokenLifespan
}

// GetVerifiableCredentialsNonceLifespan returns how long a nonce should be valid. Defaults to one hour.
func (c *Config) GetVerifiableCredentialsNonceLifespan(_ context.Context) time.Duration {
	if c.VerifiableCredentialsNonceLifespan == 0 {
		return time.Hour
	}

	return c.VerifiableCredentialsNonceLifespan
}

// GetRefreshTokenLifespan sets how long a refresh token is going to be valid. Defaults to 30 days. Set to -1 for
// refresh tokens that never expire.
func (c *Config) GetRefreshTokenLifespan(_ context.Context) time.Duration {
	if c.RefreshTokenLifespan == 0 {
		return time.Hour * 24 * 30
	}

	return c.RefreshTokenLifespan
}

// GetJWTSecuredAuthorizeResponseModeLifespan returns how long a JWT issued by the JWT Secured Authorize Response Mode should be valid. Defaults to 10 minutes.
func (c *Config) GetJWTSecuredAuthorizeResponseModeLifespan(_ context.Context) time.Duration {
	if c.JWTSecuredAuthorizeResponseModeLifespan == 0 {
		return time.Minute * 10
	}

	return c.JWTSecuredAuthorizeResponseModeLifespan
}

// GetBCryptCost returns the bcrypt cost factor. Defaults to 12.
func (c *Config) GetBCryptCost(_ context.Context) int {
	if c.HashCost == 0 {
		return DefaultBCryptWorkFactor
	}

	return c.HashCost
}

// GetJWKSFetcherStrategy returns the jwt.JWKSFetcherStrategy.
func (c *Config) GetJWKSFetcherStrategy(_ context.Context) jwt.JWKSFetcherStrategy {
	c.jwksFetcherStrategyOnce.Do(func() {
		if c.JWKSFetcherStrategy == nil {
			c.JWKSFetcherStrategy = NewDefaultJWKSFetcherStrategy()
		}
	})

	return c.JWKSFetcherStrategy
}

// GetTokenEntropy returns the entropy of the "message" part of a HMAC Token. Defaults to 32.
func (c *Config) GetTokenEntropy(_ context.Context) int {
	if c.TokenEntropy == 0 {
		return 32
	}

	return c.TokenEntropy
}

// GetRedirectSecureChecker returns the checker to check if redirect URI is secure. Defaults to oauth2.IsRedirectURISecure.
func (c *Config) GetRedirectSecureChecker(_ context.Context) func(context.Context, *url.URL) bool {
	if c.RedirectSecureChecker == nil {
		return IsRedirectURISecure
	}

	return c.RedirectSecureChecker
}

// GetRefreshTokenScopes returns which scopes will provide refresh tokens.
func (c *Config) GetRefreshTokenScopes(_ context.Context) []string {
	if c.RefreshTokenScopes == nil {
		return []string{consts.ScopeOffline, consts.ScopeOfflineAccess}
	}

	return c.RefreshTokenScopes
}

// GetMinParameterEntropy returns MinParameterEntropy if set. Defaults to oauth2.MinParameterEntropy.
func (c *Config) GetMinParameterEntropy(_ context.Context) int {
	if c.MinParameterEntropy == 0 {
		return MinParameterEntropy
	}

	return c.MinParameterEntropy
}

// GetJWTMaxDuration specified the maximum amount of allowed `exp` time for a JWT. It compares
// the time with the JWT's `exp` time if the JWT time is larger, will cause the JWT to be invalid.
//
// Defaults to a day.
func (c *Config) GetJWTMaxDuration(_ context.Context) time.Duration {
	if c.GrantTypeJWTBearerMaxDuration == 0 {
		return time.Hour * 24
	}

	return c.GrantTypeJWTBearerMaxDuration
}

// GetClientAuthenticationStrategy returns the configured client authentication strategy.
// Defaults to nil.
// Note that on a nil strategy `oauth2.Fosite` fallbacks to its default client authentication strategy
// `oauth2.Fosite.DefaultClientAuthenticationStrategy`
func (c *Config) GetClientAuthenticationStrategy(_ context.Context) ClientAuthenticationStrategy {
	return c.ClientAuthenticationStrategy
}

// GetDisableRefreshTokenValidation returns whether to disable the validation of the refresh token.
func (c *Config) GetDisableRefreshTokenValidation(_ context.Context) bool {
	return c.DisableRefreshTokenValidation
}

// GetPushedAuthorizeEndpointHandlers returns the handlers.
func (c *Config) GetPushedAuthorizeEndpointHandlers(ctx context.Context) PushedAuthorizeEndpointHandlers {
	return c.PushedAuthorizeEndpointHandlers
}

// GetPushedAuthorizeRequestURIPrefix is the request URI prefix. This is
// usually 'urn:ietf:params:oauth:request_uri:'.
func (c *Config) GetPushedAuthorizeRequestURIPrefix(ctx context.Context) string {
	if c.PushedAuthorizeRequestURIPrefix == "" {
		return defaultPARPrefix
	}

	return c.PushedAuthorizeRequestURIPrefix
}

// GetPushedAuthorizeContextLifespan is the lifespan of the short-lived PAR context.
func (c *Config) GetPushedAuthorizeContextLifespan(ctx context.Context) time.Duration {
	if c.PushedAuthorizeContextLifespan <= 0 {
		return defaultPARContextLifetime
	}

	return c.PushedAuthorizeContextLifespan
}

// GetRequirePushedAuthorizationRequests indicates if PAR is enforced. In this mode, a client
// cannot pass authorize parameters at the 'authorize' endpoint. The 'authorize' endpoint
// must contain the PAR request_uri.
func (c *Config) GetRequirePushedAuthorizationRequests(ctx context.Context) bool {
	return c.RequirePushedAuthorizationRequests
}

// GetRequireSignedRequestObject indicates if JWT-Secured Authorization Requests are enforced. In this mode, a client
// cannot pass authorization parameters via the OAuth 2.0 request syntax alone; the request must be protected as a
// signed Request Object provided by either the 'request' or 'request_uri' parameter.
func (c *Config) GetRequireSignedRequestObject(ctx context.Context) bool {
	return c.RequireSignedRequestObject
}

// GetRequireSignedRequestObjectSkipPushedAuthorizationRequests indicates if the signed Request Object requirement is
// skipped for requests made directly to the Pushed Authorization Request endpoint.
func (c *Config) GetRequireSignedRequestObjectSkipPushedAuthorizationRequests(ctx context.Context) bool {
	return c.RequireSignedRequestObjectSkipPushedAuthorizationRequests
}

func (c *Config) GetRFC8693TokenTypes(ctx context.Context) map[string]RFC8693TokenType {
	return c.RFC8693TokenTypes
}

func (c *Config) GetDefaultRFC8693RequestedTokenType(ctx context.Context) string {
	return c.DefaultRequestedTokenType
}

func (c *Config) GetRFC8628UserVerificationURL(_ context.Context) string {
	return c.RFC8628UserVerificationURL
}

func (c *Config) GetRFC8628TokenPollingInterval(_ context.Context) time.Duration {
	if c.RFC8628TokenPollingInterval == 0 {
		return time.Second * 10
	}

	return c.RFC8628TokenPollingInterval
}

func (c *Config) GetAuthorizeErrorFieldResponseStrategy(ctx context.Context) (strategy AuthorizeErrorFieldResponseStrategy) {
	c.authorizeErrorFieldResponseStrategyOnce.Do(func() {
		if c.AuthorizeErrorFieldResponseStrategy == nil {
			c.AuthorizeErrorFieldResponseStrategy = &JSONAuthorizeErrorFieldResponseStrategy{Config: c}
		}
	})

	return c.AuthorizeErrorFieldResponseStrategy
}

func (c *Config) GetTokenEndpointClientAuthStrategy(ctx context.Context) (strategy EndpointClientAuthStrategy) {
	c.tokenEndpointClientAuthStrategyOnce.Do(func() {
		if c.TokenEndpointClientAuthStrategy == nil {
			c.TokenEndpointClientAuthStrategy = &TokenEndpointClientAuthStrategy{}
		}
	})

	return c.TokenEndpointClientAuthStrategy
}

func (c *Config) GetIntrospectionEndpointClientAuthStrategy(ctx context.Context) (strategy EndpointClientAuthStrategy) {
	c.introspectionEndpointClientAuthStrategyOnce.Do(func() {
		if c.IntrospectionEndpointClientAuthStrategy == nil {
			c.IntrospectionEndpointClientAuthStrategy = &IntrospectionEndpointClientAuthStrategy{}
		}
	})

	return c.IntrospectionEndpointClientAuthStrategy
}

func (c *Config) GetIntrospectionEndpointClientAuthDisabled(ctx context.Context) (disabled bool) {
	return c.IntrospectionEndpointClientAuthDisabled
}

func (c *Config) GetRevocationEndpointClientAuthStrategy(ctx context.Context) (strategy EndpointClientAuthStrategy) {
	c.revocationEndpointClientAuthStrategyOnce.Do(func() {
		if c.RevocationEndpointClientAuthStrategy == nil {
			c.RevocationEndpointClientAuthStrategy = &RevocationEndpointClientAuthStrategy{}
		}
	})

	return c.RevocationEndpointClientAuthStrategy
}

func (c *Config) GetDPoPEnabled(ctx context.Context) (enabled bool) {
	return c.DPoPEnabled || c.DPoPEnforce
}

func (c *Config) GetDPoPEnforce(ctx context.Context) (enforce bool) {
	return c.DPoPEnforce
}

// GetDPoPAllowedJWSAlgorithms returns the asymmetric algorithms a DPoP proof may be signed with.
//
// Both Edwards-curve identifiers are listed: 'EdDSA' from RFC 8037 Section 3.1, and the fully-specified 'Ed25519'
// that RFC 9864 Table 2 registers for the same parameter set and recommends in its place, so a client using either
// identifier is accepted. RFC 9864's 'Ed448' is absent because token/jose does not implement it.
func (c *Config) GetDPoPAllowedJWSAlgorithms(ctx context.Context) (algs []string) {
	if len(c.DPoPAllowedJWSAlgorithms) == 0 {
		return []string{"ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512", "EdDSA", "Ed25519"}
	}

	return c.DPoPAllowedJWSAlgorithms
}

func (c *Config) GetDPoPClockSkew(ctx context.Context) (skew time.Duration) {
	if c.DPoPClockSkew <= 0 {
		return defaultDPoPClockSkew
	}

	return c.DPoPClockSkew
}

func (c *Config) GetDPoPProofLifespan(ctx context.Context) (lifespan time.Duration) {
	if c.DPoPProofLifespan <= 0 {
		return defaultDPoPProofLifespan
	}

	return c.DPoPProofLifespan
}

func (c *Config) GetDPoPNonceRequired(ctx context.Context) (required bool) {
	return c.DPoPNonceRequired
}

func (c *Config) GetDPoPNonceLifespan(ctx context.Context) (lifespan time.Duration) {
	if c.DPoPNonceLifespan <= 0 {
		return time.Hour
	}

	return c.DPoPNonceLifespan
}

func (c *Config) GetDPoPStrategy(ctx context.Context) (strategy DPoPStrategy) {
	return c.DPoPStrategy
}

func (c *Config) GetMTLSEnabled(ctx context.Context) (enabled bool) {
	return c.MTLSEnabled || c.MTLSEnforce
}

func (c *Config) GetMTLSEnforce(ctx context.Context) (enforce bool) {
	return c.MTLSEnforce
}

func (c *Config) GetMTLSClientCertificateHeader(ctx context.Context) (header string) {
	return c.MTLSClientCertificateHeader
}

func (c *Config) GetRFC7591ClientRegistrationGlobalSecret(ctx context.Context) (secret []byte, err error) {
	return c.RFC7591ClientRegistrationGlobalSecret, nil
}

func (c *Config) GetRFC7591ClientRegistrationRotatedGlobalSecrets(ctx context.Context) (secrets [][]byte, err error) {
	return c.RFC7591ClientRegistrationRotatedGlobalSecrets, nil
}

func (c *Config) GetRFC7591ClientRegistrationEndpointURL(ctx context.Context) (endpoint string) {
	return c.RFC7591ClientRegistrationEndpointURL
}

func (c *Config) GetRFC7591ClientSecretLifespan(ctx context.Context) (lifespan time.Duration) {
	return c.RFC7591ClientSecretLifespan
}

func (c *Config) GetRFC7591ClientRegistrationStrategy(ctx context.Context) (strategy ClientRegistrationStrategy) {
	return c.RFC7591ClientRegistrationStrategy
}

func (c *Config) GetRFC7591ClientRegistrationMetadataStrategy(ctx context.Context) (strategy ClientRegistrationMetadataStrategy) {
	return c.RFC7591ClientRegistrationMetadataStrategy
}

func (c *Config) GetRFC7591ClientRegistrationEndpointAuthStrategy(ctx context.Context) (strategy ClientRegistrationEndpointAuthStrategy) {
	return c.RFC7591ClientRegistrationEndpointAuthStrategy
}

func (c *Config) GetRFC7591ClientRegistrationValidators(ctx context.Context) (validators []ClientRegistrationValidator) {
	return c.RFC7591ClientRegistrationValidators
}

func (c *Config) GetRFC7591ClientRegistrationEndpointAudiences(ctx context.Context) (audiences []string) {
	return c.RFC7591ClientRegistrationEndpointAudiences
}

// GetRFC7591ClientRegistrationGrantTypes returns the grant types a client may register for, or nil to permit any.
//
// RFC 7591 Section 2 permits the authorization server to "reject any requested client metadata values ... by
// returning an error response". The registrant chooses 'grant_types' and every token endpoint authorization check in
// this library is a GetGrantTypes().Has call, so a client that can register unrestricted grants its own authority:
// asserting 'client_credentials' produces a client that acts with no resource owner, and 'password' one that
// RFC 9700 Section 2.4 says MUST NOT be used at all.
//
// It is empty by default, permitting any grant, because registering a non-redirecting grant is legitimate and
// specified: an mTLS client registered under RFC 8705 is a client credentials client, and Section 2 requires only
// that 'grant_types' and 'response_types' be internally coherent. A deployment whose registration endpoint is open,
// or is reachable by parties it does not intend to grant every flow to, should set this to the grants it means to
// hand out.
func (c *Config) GetRFC7591ClientRegistrationGrantTypes(ctx context.Context) (grantTypes []string) {
	return c.RFC7591ClientRegistrationGrantTypes
}

func (c *Config) GetRFC7591ClientRegistrationScopes(ctx context.Context) (scopes []string) {
	if len(c.RFC7591ClientRegistrationScopes) == 0 {
		return []string{consts.ScopeClientRegistration}
	}

	return c.RFC7591ClientRegistrationScopes
}

var (
	_ AuthorizeCodeLifespanProvider                      = (*Config)(nil)
	_ RefreshTokenLifespanProvider                       = (*Config)(nil)
	_ AccessTokenLifespanProvider                        = (*Config)(nil)
	_ ScopeStrategyProvider                              = (*Config)(nil)
	_ AudienceStrategyProvider                           = (*Config)(nil)
	_ RedirectSecureCheckerProvider                      = (*Config)(nil)
	_ RefreshTokenScopesProvider                         = (*Config)(nil)
	_ DisableRefreshTokenValidationProvider              = (*Config)(nil)
	_ AccessTokenIssuerProvider                          = (*Config)(nil)
	_ JWTScopeFieldProvider                              = (*Config)(nil)
	_ JWTSecuredAuthorizeResponseModeIssuerProvider      = (*Config)(nil)
	_ JWTSecuredAuthorizeResponseModeStrategyProvider    = (*Config)(nil)
	_ JWTSecuredAuthorizeResponseModeLifespanProvider    = (*Config)(nil)
	_ JWTProfileAccessTokensProvider                     = (*Config)(nil)
	_ AllowedPromptsProvider                             = (*Config)(nil)
	_ OmitRedirectScopeParamProvider                     = (*Config)(nil)
	_ MinParameterEntropyProvider                        = (*Config)(nil)
	_ SanitationAllowedProvider                          = (*Config)(nil)
	_ EnforcePKCEForPublicClientsProvider                = (*Config)(nil)
	_ EnablePKCEPlainChallengeMethodProvider             = (*Config)(nil)
	_ EnforcePKCEProvider                                = (*Config)(nil)
	_ GrantTypeJWTBearerCanSkipClientAuthProvider        = (*Config)(nil)
	_ GrantTypeJWTBearerIDOptionalProvider               = (*Config)(nil)
	_ GrantTypeJWTBearerIssuedDateOptionalProvider       = (*Config)(nil)
	_ GetJWTMaxDurationProvider                          = (*Config)(nil)
	_ IDTokenLifespanProvider                            = (*Config)(nil)
	_ IDTokenIssuerProvider                              = (*Config)(nil)
	_ IDTokenValidationStrategyProvider                  = (*Config)(nil)
	_ BackChannelLogoutTokenStrategyProvider             = (*Config)(nil)
	_ BackChannelLogoutLifespanProvider                  = (*Config)(nil)
	_ BackChannelLogoutConcurrencyProvider               = (*Config)(nil)
	_ AuthorizationServerIssuerIdentificationProvider    = (*Config)(nil)
	_ JWKSFetcherStrategyProvider                        = (*Config)(nil)
	_ ClientAuthenticationStrategyProvider               = (*Config)(nil)
	_ SendDebugMessagesToClientsProvider                 = (*Config)(nil)
	_ ResponseModeHandlerProvider                        = (*Config)(nil)
	_ MessageCatalogProvider                             = (*Config)(nil)
	_ FormPostHTMLTemplateProvider                       = (*Config)(nil)
	_ FormPostResponseProvider                           = (*Config)(nil)
	_ AllowedJWTAssertionAudiencesProvider               = (*Config)(nil)
	_ AllowedIntrospectionAudiencesProvider              = (*Config)(nil)
	_ AllowedIntrospectionScopesProvider                 = (*Config)(nil)
	_ HTTPClientProvider                                 = (*Config)(nil)
	_ HMACHashingProvider                                = (*Config)(nil)
	_ AuthorizeEndpointHandlersProvider                  = (*Config)(nil)
	_ TokenEndpointHandlersProvider                      = (*Config)(nil)
	_ AuthorizeEndpointBindingHandlersProvider           = (*Config)(nil)
	_ TokenEndpointBindingHandlersProvider               = (*Config)(nil)
	_ TokenIntrospectionHandlersProvider                 = (*Config)(nil)
	_ RevocationHandlersProvider                         = (*Config)(nil)
	_ PushedAuthorizeRequestHandlersProvider             = (*Config)(nil)
	_ PushedAuthorizeRequestConfigProvider               = (*Config)(nil)
	_ RFC8693ConfigProvider                              = (*Config)(nil)
	_ RFC8628DeviceAuthorizeConfigProvider               = (*Config)(nil)
	_ RFC8628DeviceAuthorizeEndpointHandlersProvider     = (*Config)(nil)
	_ RFC8628UserAuthorizeEndpointHandlersProvider       = (*Config)(nil)
	_ IntrospectionIssuerProvider                        = (*Config)(nil)
	_ IntrospectionJWTResponseStrategyProvider           = (*Config)(nil)
	_ AuthorizeErrorFieldResponseStrategyProvider        = (*Config)(nil)
	_ TokenEndpointClientAuthStrategyProvider            = (*Config)(nil)
	_ IntrospectionEndpointClientAuthStrategyProvider    = (*Config)(nil)
	_ IntrospectionEndpointClientAuthDisabledProvider    = (*Config)(nil)
	_ RevocationEndpointClientAuthStrategyProvider       = (*Config)(nil)
	_ DPoPConfigProvider                                 = (*Config)(nil)
	_ MTLSConfigProvider                                 = (*Config)(nil)
	_ RFC7591ClientRegistrationConfigProvider            = (*Config)(nil)
	_ RFC7591ClientRegistrationEndpointHandlersProvider  = (*Config)(nil)
	_ RFC7592ClientConfigurationEndpointHandlersProvider = (*Config)(nil)
)
