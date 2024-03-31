// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"hash"
	"html/template"
	"net/url"
	"time"

	"github.com/hashicorp/go-retryablehttp"

	"authelia.com/provider/oauth2/i18n"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

const (
	defaultPARPrefix          = consts.PrefixRequestURI
	defaultPARContextLifetime = 5 * time.Minute
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

	// IntrospectionJWTResponseSigner is the signer for Introspection Responses. Has no default.
	IntrospectionJWTResponseSigner jwt.Signer

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

	// AudienceMatchingStrategy sets the audience matching strategy that should be supported, defaults to oauth2.DefaultsAudienceMatchingStrategy.
	AudienceMatchingStrategy AudienceMatchingStrategy

	ClientCredentialsFlowImplicitGrantRequested bool

	// EnforcePKCE, if set to true, requires clients to perform authorize code flows with PKCE. Defaults to false.
	EnforcePKCE bool

	// EnforcePKCEForPublicClients requires only public clients to use PKCE with the authorize code flow. Defaults to false.
	EnforcePKCEForPublicClients bool

	// EnablePKCEPlainChallengeMethod sets whether or not to allow the plain challenge method (S256 should be used whenever possible, plain is really discouraged). Defaults to false.
	EnablePKCEPlainChallengeMethod bool

	// AllowedPromptValues sets which OpenID Connect prompt values the server supports. Defaults to []string{"login", "none", "consent", "select_account"}.
	AllowedPromptValues []string

	// TokenURL is the the URL of the Authorization Server's Token Endpoint. If the authorization server is intended
	// to be compatible with the private_key_jwt client authentication method (see http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth),
	// this value MUST be set.
	TokenURL string

	// JWKSFetcherStrategy is responsible for fetching JSON Web Keys from remote URLs. This is required when the private_key_jwt
	// client authentication method is used. Defaults to oauth2.DefaultJWKSFetcherStrategy.
	JWKSFetcherStrategy JWKSFetcherStrategy

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

	// JWTSecuredAuthorizeResponseModeSigner is the signer for JWT Secured Authorization Response Mode. Has no default.
	JWTSecuredAuthorizeResponseModeSigner jwt.Signer

	// EnforceJWTProfileAccessTokens forces the issuer to return JWT Profile Access Tokens to all clients.
	EnforceJWTProfileAccessTokens bool

	// HTTPClient is the HTTP client to use for requests.
	HTTPClient *retryablehttp.Client

	// AuthorizeEndpointHandlers is a list of handlers that are called before the authorization endpoint is served.
	AuthorizeEndpointHandlers AuthorizeEndpointHandlers

	// TokenEndpointHandlers is a list of handlers that are called before the token endpoint is served.
	TokenEndpointHandlers TokenEndpointHandlers

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

	RFC8693TokenTypes map[string]RFC8693TokenType

	DefaultRequestedTokenType string
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

func (c *Config) GetHTTPClient(ctx context.Context) *retryablehttp.Client {
	if c.HTTPClient == nil {
		return retryablehttp.NewClient()
	}

	return c.HTTPClient
}

func (c *Config) GetTokenURL(ctx context.Context) string {
	return c.TokenURL
}

func (c *Config) GetFormPostHTMLTemplate(ctx context.Context) *template.Template {
	return c.FormPostHTMLTemplate
}

func (c *Config) GetFormPostResponseWriter(ctx context.Context) FormPostResponseWriter {
	if c.FormPostResponseWriter == nil {
		c.FormPostResponseWriter = DefaultFormPostResponseWriter
	}

	return c.FormPostResponseWriter
}

func (c *Config) GetMessageCatalog(ctx context.Context) i18n.MessageCatalog {
	return c.MessageCatalog
}

func (c *Config) GetResponseModeHandlers(ctx context.Context) ResponseModeHandlers {
	if len(c.ResponseModeHandlers) == 0 {
		c.ResponseModeHandlers = []ResponseModeHandler{&DefaultResponseModeHandler{Config: c}}
	}

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

func (c *Config) GetAuthorizationServerIdentificationIssuer(ctx context.Context) (issuer string) {
	return c.AuthorizationServerIdentificationIssuer
}

func (c *Config) GetIntrospectionIssuer(ctx context.Context) string {
	return c.IntrospectionIssuer
}

func (c *Config) GetIntrospectionJWTResponseSigner(ctx context.Context) jwt.Signer {
	return c.IntrospectionJWTResponseSigner
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

func (c *Config) GetAccessTokenIssuer(ctx context.Context) string {
	return c.AccessTokenIssuer
}

func (c *Config) GetJWTScopeField(ctx context.Context) jwt.JWTScopeFieldEnum {
	return c.JWTScopeClaimKey
}

func (c *Config) GetJWTSecuredAuthorizeResponseModeIssuer(ctx context.Context) string {
	return c.IDTokenIssuer
}

func (c *Config) GetJWTSecuredAuthorizeResponseModeSigner(ctx context.Context) jwt.Signer {
	return c.JWTSecuredAuthorizeResponseModeSigner
}

func (c *Config) GetEnforceJWTProfileAccessTokens(ctx context.Context) (enable bool) {
	return c.EnforceJWTProfileAccessTokens
}

func (c *Config) GetAllowedPrompts(_ context.Context) []string {
	return c.AllowedPromptValues
}

// GetScopeStrategy returns the scope strategy to be used. Defaults to glob scope strategy.
func (c *Config) GetScopeStrategy(_ context.Context) ScopeStrategy {
	if c.ScopeStrategy == nil {
		c.ScopeStrategy = WildcardScopeStrategy
	}

	return c.ScopeStrategy
}

// GetAudienceStrategy returns the scope strategy to be used. Defaults to glob scope strategy.
func (c *Config) GetAudienceStrategy(_ context.Context) AudienceMatchingStrategy {
	if c.AudienceMatchingStrategy == nil {
		c.AudienceMatchingStrategy = DefaultAudienceMatchingStrategy
	}

	return c.AudienceMatchingStrategy
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

// GetJWKSFetcherStrategy returns the JWKSFetcherStrategy.
func (c *Config) GetJWKSFetcherStrategy(_ context.Context) JWKSFetcherStrategy {
	if c.JWKSFetcherStrategy == nil {
		c.JWKSFetcherStrategy = NewDefaultJWKSFetcherStrategy()
	}

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

// EnforcePushedAuthorize indicates if PAR is enforced. In this mode, a client
// cannot pass authorize parameters at the 'authorize' endpoint. The 'authorize' endpoint
// must contain the PAR request_uri.
func (c *Config) GetRequirePushedAuthorizationRequests(ctx context.Context) bool {
	return c.RequirePushedAuthorizationRequests
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

var (
	_ AuthorizeCodeLifespanProvider                   = (*Config)(nil)
	_ RefreshTokenLifespanProvider                    = (*Config)(nil)
	_ AccessTokenLifespanProvider                     = (*Config)(nil)
	_ ScopeStrategyProvider                           = (*Config)(nil)
	_ AudienceStrategyProvider                        = (*Config)(nil)
	_ RedirectSecureCheckerProvider                   = (*Config)(nil)
	_ RefreshTokenScopesProvider                      = (*Config)(nil)
	_ DisableRefreshTokenValidationProvider           = (*Config)(nil)
	_ AccessTokenIssuerProvider                       = (*Config)(nil)
	_ JWTScopeFieldProvider                           = (*Config)(nil)
	_ JWTSecuredAuthorizeResponseModeIssuerProvider   = (*Config)(nil)
	_ JWTSecuredAuthorizeResponseModeSignerProvider   = (*Config)(nil)
	_ JWTSecuredAuthorizeResponseModeLifespanProvider = (*Config)(nil)
	_ JWTProfileAccessTokensProvider                  = (*Config)(nil)
	_ AllowedPromptsProvider                          = (*Config)(nil)
	_ OmitRedirectScopeParamProvider                  = (*Config)(nil)
	_ MinParameterEntropyProvider                     = (*Config)(nil)
	_ SanitationAllowedProvider                       = (*Config)(nil)
	_ EnforcePKCEForPublicClientsProvider             = (*Config)(nil)
	_ EnablePKCEPlainChallengeMethodProvider          = (*Config)(nil)
	_ EnforcePKCEProvider                             = (*Config)(nil)
	_ GrantTypeJWTBearerCanSkipClientAuthProvider     = (*Config)(nil)
	_ GrantTypeJWTBearerIDOptionalProvider            = (*Config)(nil)
	_ GrantTypeJWTBearerIssuedDateOptionalProvider    = (*Config)(nil)
	_ GetJWTMaxDurationProvider                       = (*Config)(nil)
	_ IDTokenLifespanProvider                         = (*Config)(nil)
	_ IDTokenIssuerProvider                           = (*Config)(nil)
	_ AuthorizationServerIssuerIdentificationProvider = (*Config)(nil)
	_ JWKSFetcherStrategyProvider                     = (*Config)(nil)
	_ ClientAuthenticationStrategyProvider            = (*Config)(nil)
	_ SendDebugMessagesToClientsProvider              = (*Config)(nil)
	_ ResponseModeHandlerProvider                     = (*Config)(nil)
	_ MessageCatalogProvider                          = (*Config)(nil)
	_ FormPostHTMLTemplateProvider                    = (*Config)(nil)
	_ FormPostResponseProvider                        = (*Config)(nil)
	_ TokenURLProvider                                = (*Config)(nil)
	_ HTTPClientProvider                              = (*Config)(nil)
	_ HMACHashingProvider                             = (*Config)(nil)
	_ AuthorizeEndpointHandlersProvider               = (*Config)(nil)
	_ TokenEndpointHandlersProvider                   = (*Config)(nil)
	_ TokenIntrospectionHandlersProvider              = (*Config)(nil)
	_ RevocationHandlersProvider                      = (*Config)(nil)
	_ PushedAuthorizeRequestHandlersProvider          = (*Config)(nil)
	_ PushedAuthorizeRequestConfigProvider            = (*Config)(nil)
	_ RFC8693ConfigProvider                           = (*Config)(nil)
	_ RFC9628DeviceAuthorizeConfigProvider            = (*Config)(nil)
	_ RFC8628DeviceAuthorizeEndpointHandlersProvider  = (*Config)(nil)
	_ RFC8628UserAuthorizeEndpointHandlersProvider    = (*Config)(nil)
	_ IntrospectionIssuerProvider                     = (*Config)(nil)
	_ IntrospectionJWTResponseSignerProvider          = (*Config)(nil)
)
