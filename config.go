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
	"authelia.com/provider/oauth2/token/jwt"
)

// AuthorizeCodeLifespanProvider returns the provider for configuring the authorization code lifespan.
type AuthorizeCodeLifespanProvider interface {
	// GetAuthorizeCodeLifespan returns the authorization code lifespan.
	GetAuthorizeCodeLifespan(ctx context.Context) time.Duration
}

// RefreshTokenLifespanProvider returns the provider for configuring the refresh token lifespan.
type RefreshTokenLifespanProvider interface {
	// GetRefreshTokenLifespan returns the refresh token lifespan.
	GetRefreshTokenLifespan(ctx context.Context) time.Duration
}

// AccessTokenLifespanProvider returns the provider for configuring the access token lifespan.
type AccessTokenLifespanProvider interface {
	// GetAccessTokenLifespan returns the access token lifespan.
	GetAccessTokenLifespan(ctx context.Context) time.Duration
}

// VerifiableCredentialsNonceLifespanProvider returns the provider for configuring the access token lifespan.
type VerifiableCredentialsNonceLifespanProvider interface {
	// GetVerifiableCredentialsNonceLifespan returns the nonce lifespan.
	GetVerifiableCredentialsNonceLifespan(ctx context.Context) time.Duration
}

// IDTokenLifespanProvider returns the provider for configuring the ID token lifespan.
type IDTokenLifespanProvider interface {
	// GetIDTokenLifespan returns the ID token lifespan.
	GetIDTokenLifespan(ctx context.Context) time.Duration
}

// ScopeStrategyProvider returns the provider for configuring the scope strategy.
type ScopeStrategyProvider interface {
	// GetScopeStrategy returns the scope strategy.
	GetScopeStrategy(ctx context.Context) ScopeStrategy
}

// AudienceStrategyProvider returns the provider for configuring the audience strategy.
type AudienceStrategyProvider interface {
	// GetAudienceStrategy returns the audience strategy.
	GetAudienceStrategy(ctx context.Context) AudienceMatchingStrategy
}

// RedirectSecureCheckerProvider returns the provider for configuring the redirect URL security validator.
type RedirectSecureCheckerProvider interface {
	// GetRedirectSecureChecker returns the redirect URL security validator.
	GetRedirectSecureChecker(ctx context.Context) func(context.Context, *url.URL) bool
}

// RefreshTokenScopesProvider returns the provider for configuring the refresh token scopes.
type RefreshTokenScopesProvider interface {
	// GetRefreshTokenScopes returns the refresh token scopes.
	GetRefreshTokenScopes(ctx context.Context) []string
}

// DisableRefreshTokenValidationProvider returns the provider for configuring the refresh token validation.
type DisableRefreshTokenValidationProvider interface {
	// GetDisableRefreshTokenValidation returns the disable refresh token validation flag.
	GetDisableRefreshTokenValidation(ctx context.Context) bool
}

// AllowedPromptValuesProvider returns the provider for configuring the allowed prompt values.
type AllowedPromptValuesProvider interface {
	// GetAllowedPromptValues returns the allowed prompt values.
	GetAllowedPromptValues(ctx context.Context) int
}

// AccessTokenIssuerProvider returns the provider for configuring the JWT issuer.
type AccessTokenIssuerProvider interface {
	// GetAccessTokenIssuer returns the access token issuer.
	GetAccessTokenIssuer(ctx context.Context) string
}

// IDTokenIssuerProvider returns the provider for configuring the ID token issuer.
type IDTokenIssuerProvider interface {
	// GetIDTokenIssuer returns the ID token issuer.
	GetIDTokenIssuer(ctx context.Context) string
}

// AuthorizationServerIssuerIdentificationProvider provides OAuth 2.0 Authorization Server Issuer Identification related methods.
type AuthorizationServerIssuerIdentificationProvider interface {
	GetAuthorizationServerIdentificationIssuer(ctx context.Context) (issuer string)
}

// JWTScopeFieldProvider returns the provider for configuring the JWT scope field.
type JWTScopeFieldProvider interface {
	// GetJWTScopeField returns the JWT scope field.
	GetJWTScopeField(ctx context.Context) jwt.JWTScopeFieldEnum
}

// JWTSecuredAuthorizeResponseModeIssuerProvider returns the provider for configuring the JARM issuer.
type JWTSecuredAuthorizeResponseModeIssuerProvider interface {
	// GetJWTSecuredAuthorizeResponseModeIssuer returns the JARM issuer.
	GetJWTSecuredAuthorizeResponseModeIssuer(ctx context.Context) string
}

// JWTSecuredAuthorizeResponseModeSignerProvider returns the provider for configuring the JARM signer.
type JWTSecuredAuthorizeResponseModeSignerProvider interface {
	// GetJWTSecuredAuthorizeResponseModeSigner returns the JARM signer.
	GetJWTSecuredAuthorizeResponseModeSigner(ctx context.Context) jwt.Signer
}

// JWTSecuredAuthorizeResponseModeLifespanProvider returns the provider for configuring the JWT Secured Authorize Response Mode token lifespan.
type JWTSecuredAuthorizeResponseModeLifespanProvider interface {
	GetJWTSecuredAuthorizeResponseModeLifespan(ctx context.Context) time.Duration
}

// AllowedPromptsProvider returns the provider for configuring the allowed prompts.
type AllowedPromptsProvider interface {
	// GetAllowedPrompts returns the allowed prompts.
	GetAllowedPrompts(ctx context.Context) []string
}

// MinParameterEntropyProvider returns the provider for configuring the minimum parameter entropy.
type MinParameterEntropyProvider interface {
	// GetMinParameterEntropy returns the minimum parameter entropy.
	GetMinParameterEntropy(_ context.Context) int
}

// SanitationAllowedProvider returns the provider for configuring the sanitation white list.
type SanitationAllowedProvider interface {
	// GetSanitationWhiteList is a whitelist of form values that are required by the token endpoint. These values
	// are safe for storage in a database (cleartext).
	GetSanitationWhiteList(ctx context.Context) []string
}

// OmitRedirectScopeParamProvider returns the provider for configuring the omit redirect scope param.
type OmitRedirectScopeParamProvider interface {
	// GetOmitRedirectScopeParam must be set to true if the scope query param is to be omitted
	// in the authorization's redirect URI
	GetOmitRedirectScopeParam(ctx context.Context) bool
}

// EnforcePKCEProvider returns the provider for configuring the enforcement of PKCE.
type EnforcePKCEProvider interface {
	// GetEnforcePKCE returns the enforcement of PKCE.
	GetEnforcePKCE(ctx context.Context) bool
}

// EnforcePKCEForPublicClientsProvider returns the provider for configuring the enforcement of PKCE for public clients.
type EnforcePKCEForPublicClientsProvider interface {
	// GetEnforcePKCEForPublicClients returns the enforcement of PKCE for public clients.
	GetEnforcePKCEForPublicClients(ctx context.Context) bool
}

// EnablePKCEPlainChallengeMethodProvider returns the provider for configuring the enable PKCE plain challenge method.
type EnablePKCEPlainChallengeMethodProvider interface {
	// GetEnablePKCEPlainChallengeMethod returns the enable PKCE plain challenge method.
	GetEnablePKCEPlainChallengeMethod(ctx context.Context) bool
}

// GrantTypeJWTBearerCanSkipClientAuthProvider returns the provider for configuring the grant type JWT bearer can skip client auth.
type GrantTypeJWTBearerCanSkipClientAuthProvider interface {
	// GetGrantTypeJWTBearerCanSkipClientAuth returns the grant type JWT bearer can skip client auth.
	GetGrantTypeJWTBearerCanSkipClientAuth(ctx context.Context) bool
}

// GrantTypeJWTBearerIDOptionalProvider returns the provider for configuring the grant type JWT bearer ID optional.
type GrantTypeJWTBearerIDOptionalProvider interface {
	// GetGrantTypeJWTBearerIDOptional returns the grant type JWT bearer ID optional.
	GetGrantTypeJWTBearerIDOptional(ctx context.Context) bool
}

// GrantTypeJWTBearerIssuedDateOptionalProvider returns the provider for configuring the grant type JWT bearer issued date optional.
type GrantTypeJWTBearerIssuedDateOptionalProvider interface {
	// GetGrantTypeJWTBearerIssuedDateOptional returns the grant type JWT bearer issued date optional.
	GetGrantTypeJWTBearerIssuedDateOptional(ctx context.Context) bool
}

// GetJWTMaxDurationProvider returns the provider for configuring the JWT max duration.
type GetJWTMaxDurationProvider interface {
	// GetJWTMaxDuration returns the JWT max duration.
	GetJWTMaxDuration(ctx context.Context) time.Duration
}

// TokenEntropyProvider returns the provider for configuring the token entropy.
type TokenEntropyProvider interface {
	// GetTokenEntropy returns the token entropy.
	GetTokenEntropy(ctx context.Context) int
}

// GlobalSecretProvider returns the provider for configuring the global secret.
type GlobalSecretProvider interface {
	// GetGlobalSecret returns the global secret.
	GetGlobalSecret(ctx context.Context) ([]byte, error)
}

// RotatedGlobalSecretsProvider returns the provider for configuring the rotated global secrets.
type RotatedGlobalSecretsProvider interface {
	// GetRotatedGlobalSecrets returns the rotated global secrets.
	GetRotatedGlobalSecrets(ctx context.Context) ([][]byte, error)
}

// HMACHashingProvider returns the provider for configuring the hash function.
type HMACHashingProvider interface {
	// GetHMACHasher returns the hash function.
	GetHMACHasher(ctx context.Context) func() hash.Hash
}

// SendDebugMessagesToClientsProvider returns the provider for configuring the send debug messages to clients.
type SendDebugMessagesToClientsProvider interface {
	// GetSendDebugMessagesToClients returns the send debug messages to clients.
	GetSendDebugMessagesToClients(ctx context.Context) bool
}

// RevokeRefreshTokensExplicitlyProvider returns the provider for configuring the Refresh Token Explicit Revocation policy.
type RevokeRefreshTokensExplicitlyProvider interface {
	// GetRevokeRefreshTokensExplicit returns true if a refresh token should only be revoked explicitly.
	GetRevokeRefreshTokensExplicit(ctx context.Context) bool

	// GetEnforceRevokeFlowRevokeRefreshTokensExplicitClient returns true if a
	// RevokeFlowRevokeRefreshTokensExplicitClient returning false should be enforced.
	GetEnforceRevokeFlowRevokeRefreshTokensExplicitClient(ctx context.Context) bool
}

// JWKSFetcherStrategyProvider returns the provider for configuring the JWKS fetcher strategy.
type JWKSFetcherStrategyProvider interface {
	// GetJWKSFetcherStrategy returns the JWKS fetcher strategy.
	GetJWKSFetcherStrategy(ctx context.Context) JWKSFetcherStrategy
}

// HTTPClientProvider returns the provider for configuring the HTTP client.
type HTTPClientProvider interface {
	// GetHTTPClient returns the HTTP client provider.
	GetHTTPClient(ctx context.Context) *retryablehttp.Client
}

// ClientAuthenticationStrategyProvider returns the provider for configuring the client authentication strategy.
type ClientAuthenticationStrategyProvider interface {
	// GetClientAuthenticationStrategy returns the client authentication strategy.
	GetClientAuthenticationStrategy(ctx context.Context) ClientAuthenticationStrategy
}

// ResponseModeHandlerProvider returns the provider for configuring the response mode handlers.
type ResponseModeHandlerProvider interface {
	// GetResponseModeHandlers returns the response mode handlers in order of execution.
	GetResponseModeHandlers(ctx context.Context) []ResponseModeHandler
}

// MessageCatalogProvider returns the provider for configuring the message catalog.
type MessageCatalogProvider interface {
	// GetMessageCatalog returns the message catalog.
	GetMessageCatalog(ctx context.Context) i18n.MessageCatalog
}

// FormPostHTMLTemplateProvider returns the provider for configuring the form post HTML template.
type FormPostHTMLTemplateProvider interface {
	// GetFormPostHTMLTemplate returns the form post HTML template.
	GetFormPostHTMLTemplate(ctx context.Context) *template.Template
}

type TokenURLProvider interface {
	// GetTokenURL returns the token URL.
	GetTokenURL(ctx context.Context) string
}

// AuthorizeEndpointHandlersProvider returns the provider for configuring the authorize endpoint handlers.
type AuthorizeEndpointHandlersProvider interface {
	// GetAuthorizeEndpointHandlers returns the authorize endpoint handlers.
	GetAuthorizeEndpointHandlers(ctx context.Context) AuthorizeEndpointHandlers
}

// TokenEndpointHandlersProvider returns the provider for configuring the token endpoint handlers.
type TokenEndpointHandlersProvider interface {
	// GetTokenEndpointHandlers returns the token endpoint handlers.
	GetTokenEndpointHandlers(ctx context.Context) TokenEndpointHandlers
}

// TokenIntrospectionHandlersProvider returns the provider for configuring the token introspection handlers.
type TokenIntrospectionHandlersProvider interface {
	// GetTokenIntrospectionHandlers returns the token introspection handlers.
	GetTokenIntrospectionHandlers(ctx context.Context) TokenIntrospectionHandlers
}

// RevocationHandlersProvider returns the provider for configuring the revocation handlers.
type RevocationHandlersProvider interface {
	// GetRevocationHandlers returns the revocation handlers.
	GetRevocationHandlers(ctx context.Context) RevocationHandlers
}

// PushedAuthorizeRequestHandlersProvider returns the provider for configuring the PAR handlers.
type PushedAuthorizeRequestHandlersProvider interface {
	// GetPushedAuthorizeEndpointHandlers returns the handlers.
	GetPushedAuthorizeEndpointHandlers(ctx context.Context) PushedAuthorizeEndpointHandlers
}

// RFC9628DeviceAuthorizeConfigProvider returns the provider for configuring the device authorization response.
//
// See: https://www.rfc-editor.org/rfc/rfc8628#section-3.2
type RFC9628DeviceAuthorizeConfigProvider interface {
	// GetRFC8628CodeLifespan returns the device and user code lifespan.
	GetRFC8628CodeLifespan(ctx context.Context) (lifespan time.Duration)

	GetRFC8628UserVerificationURL(ctx context.Context) (url string)

	GetRFC8628TokenPollingInterval(ctx context.Context) (interval time.Duration)
}

// RFC8628DeviceAuthorizeEndpointHandlersProvider returns the provider for setting up the Device authorization handlers.
type RFC8628DeviceAuthorizeEndpointHandlersProvider interface {
	// GetRFC8628DeviceAuthorizeEndpointHandlers returns the handlers.
	GetRFC8628DeviceAuthorizeEndpointHandlers(ctx context.Context) RFC8628DeviceAuthorizeEndpointHandlers
}

// RFC8628UserAuthorizeEndpointHandlersProvider returns the provider for setting up the Device grant user interaction handlers.
type RFC8628UserAuthorizeEndpointHandlersProvider interface {
	// GetRFC8628UserAuthorizeEndpointHandlers returns the handlers.
	GetRFC8628UserAuthorizeEndpointHandlers(ctx context.Context) RFC8628UserAuthorizeEndpointHandlers
}

// RFC8693ConfigProvider is the configuration provider for RFC8693 Token Exchange.
type RFC8693ConfigProvider interface {
	GetRFC8693TokenTypes(ctx context.Context) map[string]RFC8693TokenType

	GetDefaultRFC8693RequestedTokenType(ctx context.Context) string
}

// UseLegacyErrorFormatProvider returns the provider for configuring whether to use the legacy error format.
//
// Deprecated: Do not use this flag anymore.
type UseLegacyErrorFormatProvider interface {
	// GetUseLegacyErrorFormat returns whether to use the legacy error format.
	//
	// Deprecated: Do not use this flag anymore.
	GetUseLegacyErrorFormat(ctx context.Context) bool
}

// PushedAuthorizeRequestConfigProvider is the configuration provider for pushed
// authorization request.
type PushedAuthorizeRequestConfigProvider interface {
	// GetPushedAuthorizeRequestURIPrefix is the request URI prefix. This is
	// usually 'urn:ietf:params:oauth:request_uri:'.
	GetPushedAuthorizeRequestURIPrefix(ctx context.Context) string

	// GetPushedAuthorizeContextLifespan is the lifespan of the short-lived PAR context.
	GetPushedAuthorizeContextLifespan(ctx context.Context) time.Duration

	// EnforcePushedAuthorize indicates if PAR is enforced. In this mode, a client
	// cannot pass authorize parameters at the 'authorize' endpoint. The 'authorize' endpoint
	// must contain the PAR request_uri.
	EnforcePushedAuthorize(ctx context.Context) bool
}
