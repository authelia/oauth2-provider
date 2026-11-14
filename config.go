// SPDX-FileCopyrightText: 2026 Authelia
//
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
	GetAuthorizeCodeLifespan(ctx context.Context) (lifespan time.Duration)
}

// RefreshTokenLifespanProvider returns the provider for configuring the refresh token lifespan.
type RefreshTokenLifespanProvider interface {
	// GetRefreshTokenLifespan returns the refresh token lifespan.
	GetRefreshTokenLifespan(ctx context.Context) (lifespan time.Duration)
}

// DisableRefreshTokenExpirationParametersProvider returns the provider for configuring whether the refresh token
// expiration parameters are disabled.
type DisableRefreshTokenExpirationParametersProvider interface {
	// GetDisableRefreshTokenExpirationParameters returns true when the refresh_token_timeout and
	// authorization_expires_in parameters, the matching introspection members and the metadata member are omitted.
	GetDisableRefreshTokenExpirationParameters(ctx context.Context) (disable bool)
}

// AccessTokenLifespanProvider returns the provider for configuring the access token lifespan.
type AccessTokenLifespanProvider interface {
	// GetAccessTokenLifespan returns the access token lifespan.
	GetAccessTokenLifespan(ctx context.Context) (lifespan time.Duration)
}

// VerifiableCredentialsNonceLifespanProvider returns the provider for configuring the access token lifespan.
type VerifiableCredentialsNonceLifespanProvider interface {
	// GetVerifiableCredentialsNonceLifespan returns the nonce lifespan.
	GetVerifiableCredentialsNonceLifespan(ctx context.Context) (lifespan time.Duration)
}

// IDTokenLifespanProvider returns the provider for configuring the ID token lifespan.
type IDTokenLifespanProvider interface {
	// GetIDTokenLifespan returns the ID token lifespan.
	GetIDTokenLifespan(ctx context.Context) (lifespan time.Duration)
}

// ScopeStrategyProvider returns the provider for configuring the scope strategy.
type ScopeStrategyProvider interface {
	// GetScopeStrategy returns the scope strategy.
	GetScopeStrategy(ctx context.Context) (strategy ScopeStrategy)
}

// AudienceStrategyProvider returns the provider for configuring the audience strategy.
type AudienceStrategyProvider interface {
	// GetAudienceStrategy returns the audience strategy.
	GetAudienceStrategy(ctx context.Context) (strategy AudienceStrategy)
}

// ResourceStrategyProvider returns the provider for configuring the RFC 8707 resource indicator strategy.
type ResourceStrategyProvider interface {
	// GetResourceStrategy returns the resource indicator matching strategy.
	GetResourceStrategy(ctx context.Context) (strategy ResourceStrategy)
}

// AudienceResourceStrategyProvider returns the provider for configuring both the audience strategy and the RFC 8707
// resource indicator strategy.
type AudienceResourceStrategyProvider interface {
	AudienceStrategyProvider
	ResourceStrategyProvider
}

// AuthorizationDetailsTypeHandlersProvider returns the provider for configuring the RFC 9396 authorization details
// type handlers.
type AuthorizationDetailsTypeHandlersProvider interface {
	// GetAuthorizationDetailsTypeHandlers returns the handlers keyed by authorization details type. RFC 9396 Rich
	// Authorization Requests are disabled when it is empty. The map must not contain nil handlers.
	GetAuthorizationDetailsTypeHandlers(ctx context.Context) (handlers map[string]AuthorizationDetailsTypeHandler)
}

// AuthorizationDetailsMaxObjectsProvider returns the provider for configuring the maximum number of RFC 9396
// authorization details objects accepted in a single 'authorization_details' parameter.
type AuthorizationDetailsMaxObjectsProvider interface {
	// GetAuthorizationDetailsMaxObjects returns the maximum number of authorization details objects accepted in a
	// single 'authorization_details' parameter.
	GetAuthorizationDetailsMaxObjects(ctx context.Context) (maximum int)
}

// ClaimsParameterMaxLengthProvider returns the provider for configuring the maximum length of the OpenID Connect 1.0
// 'claims' request parameter.
type ClaimsParameterMaxLengthProvider interface {
	// GetClaimsParameterMaxLength returns the maximum length in bytes of the 'claims' request parameter. A value
	// which is not positive selects the default.
	GetClaimsParameterMaxLength(ctx context.Context) (maximum int)
}

// ClientCredentialsImplicitProvider describes the provider of the Client Credentials Flow Implicit actions.
type ClientCredentialsImplicitProvider interface {
	// GetClientCredentialsFlowImplicitGrantRequested returns true if the PopulateTokenEndpointResponse portion of the
	// oauth2.ClientCredentialsGrantHandler should implicitly grant all requested and validated scopes and audiences.
	GetClientCredentialsFlowImplicitGrantRequested(ctx context.Context) (implicit bool)
}

// PublicClientIdentityCheckerProvider returns the provider for configuring the public client identity validator.
type PublicClientIdentityCheckerProvider interface {
	// GetPublicClientIdentityChecker returns the validator which reports whether an authorization request assures the
	// identity of a public client, as required to process it without user interaction.
	GetPublicClientIdentityChecker(ctx context.Context) func(context.Context, AuthorizeRequester) bool
}

// RedirectSecureCheckerProvider returns the provider for configuring the redirect URL security validator.
type RedirectSecureCheckerProvider interface {
	// GetRedirectSecureChecker returns the redirect URL security validator.
	GetRedirectSecureChecker(ctx context.Context) func(context.Context, *url.URL) bool
}

// AllowInsecureRedirectURIForPublicClientsProvider returns the provider for configuring whether public clients are
// exempt from the redirect URL security validator.
type AllowInsecureRedirectURIForPublicClientsProvider interface {
	// GetAllowInsecureRedirectURIForPublicClients returns true if public clients are exempt from the redirect URL
	// security validator.
	GetAllowInsecureRedirectURIForPublicClients(ctx context.Context) (allow bool)
}

// RedirectURISecurityProvider returns the providers ValidateRedirectURISecurity requires.
type RedirectURISecurityProvider interface {
	RedirectSecureCheckerProvider
	AllowInsecureRedirectURIForPublicClientsProvider
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

// DisableRefreshTokenRotationProvider returns the provider for configuring refresh token rotation.
type DisableRefreshTokenRotationProvider interface {
	// GetDisableRefreshTokenRotation returns true if the refresh token grant should keep the presented refresh token
	// rather than issue a new one.
	//
	// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.1
	GetDisableRefreshTokenRotation(ctx context.Context) (disable bool)
}

// RefreshTokenMaximumLifespanProvider returns the provider for configuring the maximum lifespan of a grant's refresh
// tokens.
//
// See: https://datatracker.ietf.org/doc/html/rfc10017#section-6.3.2.3
type RefreshTokenMaximumLifespanProvider interface {
	// GetRefreshTokenMaximumLifespan returns the time after the first refresh token of a grant is issued beyond which
	// no refresh token of the grant may expire, or a duration of 0 seconds or less for no limit.
	GetRefreshTokenMaximumLifespan(ctx context.Context) (lifespan time.Duration)
}

// JWTProfileAccessTokenDefaultAudienceProvider is optionally implemented by the configuration to provide the default
// resource indicators of a JWT profile access token.
type JWTProfileAccessTokenDefaultAudienceProvider interface {
	// GetJWTProfileAccessTokenDefaultAudience returns the 'aud' values of a JWT profile access token whose request
	// granted no audience or resource.
	GetJWTProfileAccessTokenDefaultAudience(ctx context.Context) (audience []string)
}

// IssuerProvider provides the canonical issuer identifier of the authorization server.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
type IssuerProvider interface {
	// GetIssuer returns the canonical issuer identifier, which is the issuer of every token and response the
	// authorization server issues.
	GetIssuer(ctx context.Context) (issuer string)
}

// EndpointURLs are the absolute URLs of the endpoints of an authorization server. An empty value means the endpoint
// is not exposed.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
type EndpointURLs struct {
	Authorization              string
	Token                      string
	UserInfo                   string
	JWKS                       string
	Revocation                 string
	Introspection              string
	PushedAuthorizationRequest string
	DeviceAuthorization        string
	EndSession                 string

	// Registration is the RFC 7591 client registration endpoint URL.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc7591#section-3
	Registration string

	// MutualTLSAliases are the endpoint aliases advertised for mutual TLS clients.
	MutualTLSAliases RFC8705MutualTLSEndpointAliases
}

// EndpointName identifies an endpoint which has both an EndpointURLs value and an RFC 8705 mutual TLS alias.
type EndpointName string

const (
	EndpointToken                      EndpointName = "token"
	EndpointRevocation                 EndpointName = "revocation"
	EndpointIntrospection              EndpointName = "introspection"
	EndpointPushedAuthorizationRequest EndpointName = "pushed_authorization_request"
	EndpointDeviceAuthorization        EndpointName = "device_authorization"
	EndpointUserInfo                   EndpointName = "userinfo"
	EndpointRegistration               EndpointName = "registration"
	EndpointEndSession                 EndpointName = "end_session"
)

// URLs returns the URL of the endpoint followed by its RFC 8705 mutual TLS alias, omitting empty values, or nil for
// an unknown endpoint.
//
// See: https://datatracker.ietf.org/doc/html/rfc8705#section-5
func (u EndpointURLs) URLs(name EndpointName) (urls []string) {
	var url, alias string

	switch name {
	case EndpointToken:
		url, alias = u.Token, u.MutualTLSAliases.Token
	case EndpointRevocation:
		url, alias = u.Revocation, u.MutualTLSAliases.Revocation
	case EndpointIntrospection:
		url, alias = u.Introspection, u.MutualTLSAliases.Introspection
	case EndpointPushedAuthorizationRequest:
		url, alias = u.PushedAuthorizationRequest, u.MutualTLSAliases.PushedAuthorizationRequest
	case EndpointDeviceAuthorization:
		url, alias = u.DeviceAuthorization, u.MutualTLSAliases.DeviceAuthorization
	case EndpointUserInfo:
		url, alias = u.UserInfo, u.MutualTLSAliases.UserInfo
	case EndpointRegistration:
		url, alias = u.Registration, u.MutualTLSAliases.Registration
	case EndpointEndSession:
		url, alias = u.EndSession, u.MutualTLSAliases.EndSession
	}

	for _, value := range []string{url, alias} {
		if value != "" {
			urls = append(urls, value)
		}
	}

	return urls
}

// EndpointURLsProvider provides the absolute URLs of the endpoints of the authorization server.
type EndpointURLsProvider interface {
	// GetEndpointURLs returns the endpoint URLs.
	GetEndpointURLs(ctx context.Context) (urls EndpointURLs)
}

// IDTokenValidationStrategyProvider returns the provider for configuring the ID Token validation strategy, which
// validates ID Tokens presented to the authorization server by a client.
type IDTokenValidationStrategyProvider interface {
	// GetIDTokenValidationStrategy returns the ID Token validation strategy. Has no default and may be nil.
	GetIDTokenValidationStrategy(ctx context.Context) (strategy TokenValidationStrategy)
}

// BackChannelLogoutTokenStrategyProvider returns the provider for configuring the Back-Channel Logout token
// strategy, which generates the Logout Tokens delivered to Relying Parties.
type BackChannelLogoutTokenStrategyProvider interface {
	// GetBackChannelLogoutTokenStrategy returns the Back-Channel Logout token strategy. Has no default and may
	// be nil.
	GetBackChannelLogoutTokenStrategy(ctx context.Context) (strategy BackChannelLogoutTokenStrategy)
}

// BackChannelLogoutLifespanProvider returns the provider for configuring the Logout Token lifespan.
type BackChannelLogoutLifespanProvider interface {
	// GetBackChannelLogoutLifespan returns the Logout Token lifespan. Defaults to 5 minutes.
	GetBackChannelLogoutLifespan(ctx context.Context) (lifespan time.Duration)
}

// BackChannelLogoutConcurrencyProvider returns the provider for configuring how many Back-Channel Logout
// requests are delivered concurrently.
type BackChannelLogoutConcurrencyProvider interface {
	// GetBackChannelLogoutConcurrency returns the maximum number of Back-Channel Logout requests delivered
	// concurrently. Defaults to 10.
	GetBackChannelLogoutConcurrency(ctx context.Context) (n int)
}

// IntrospectionJWTResponseStrategyProvider returns the provider for configuring the Introspection jwt.Strategy.
type IntrospectionJWTResponseStrategyProvider interface {
	// GetIntrospectionJWTResponseStrategy returns the Introspection JWT Strategy.
	GetIntrospectionJWTResponseStrategy(ctx context.Context) jwt.Strategy
}

// AuthorizationServerIdentificationProvider provides the OAuth 2.0 Authorization Server Issuer Identification switch.
// When the switch is on and GetIssuer is not empty, the 'iss' authorization response parameter is returned by an
// RFC9207ResponseModeParameterHandler and to a client resolved from a Client ID Metadata Document.
//
// See: https://datatracker.ietf.org/doc/html/rfc9207#section-2
type AuthorizationServerIdentificationProvider interface {
	// GetAuthorizationServerIdentificationEnabled returns true when the 'iss' authorization response parameter may be
	// returned.
	GetAuthorizationServerIdentificationEnabled(ctx context.Context) (enabled bool)
}

func getAuthorizationServerIdentificationIssuer(ctx context.Context, config any) (issuer string) {
	if provider, ok := config.(AuthorizationServerIdentificationProvider); !ok || !provider.GetAuthorizationServerIdentificationEnabled(ctx) {
		return ""
	}

	if provider, ok := config.(IssuerProvider); ok {
		return provider.GetIssuer(ctx)
	}

	return ""
}

// JWTScopeFieldProvider returns the provider for configuring the JWT scope field.
type JWTScopeFieldProvider interface {
	// GetJWTScopeField returns the JWT scope field.
	GetJWTScopeField(ctx context.Context) jwt.JWTScopeFieldEnum
}

// JWTSecuredAuthorizeResponseModeStrategyProvider returns the provider for configuring the JARM jwt.Strategy.
type JWTSecuredAuthorizeResponseModeStrategyProvider interface {
	// GetJWTSecuredAuthorizeResponseModeStrategy returns the JARM Strategy.
	GetJWTSecuredAuthorizeResponseModeStrategy(ctx context.Context) jwt.Strategy
}

// JWTStrategyProvider returns the provider for configuring the jwt.Strategy.
type JWTStrategyProvider interface {
	GetJWTStrategy(ctx context.Context) jwt.Strategy
}

// JWTSecuredAuthorizeResponseModeLifespanProvider returns the provider for configuring the JWT Secured Authorize Response Mode token lifespan.
type JWTSecuredAuthorizeResponseModeLifespanProvider interface {
	GetJWTSecuredAuthorizeResponseModeLifespan(ctx context.Context) time.Duration
}

// JWTProfileAccessTokensProvider provides configuration options to the JWT Profile strategies.
type JWTProfileAccessTokensProvider interface {
	// GetEnforceJWTProfileAccessTokens when returning true will disregard the registered client capabilities for
	// Access Token generation and produce only JWT Profile Access Tokens.
	GetEnforceJWTProfileAccessTokens(ctx context.Context) (enable bool)
}

// AllowedPromptsProvider returns the provider for configuring the allowed prompts.
type AllowedPromptsProvider interface {
	// GetAllowedPrompts returns the allowed prompts.
	GetAllowedPrompts(ctx context.Context) (prompts []string)
}

// MinParameterEntropyProvider returns the provider for configuring the minimum parameter entropy.
type MinParameterEntropyProvider interface {
	// GetMinParameterEntropy returns the minimum parameter entropy.
	GetMinParameterEntropy(_ context.Context) (min int)
}

// SanitationAllowedProvider returns the provider for configuring the sanitation white list.
type SanitationAllowedProvider interface {
	// GetSanitationWhiteList returns additional form values retained when an authorize request is stored for the token
	// endpoint. These values must be safe for storage in a database (cleartext). The list extends the parameters the
	// token endpoint always requires ('scope' and 'redirect_uri') and cannot remove them.
	GetSanitationWhiteList(ctx context.Context) (whitelist []string)
}

// PostLogoutRedirectWithoutIDTokenHintProvider returns the provider for configuring whether a validated
// 'post_logout_redirect_uri' is exposed by an RP-Initiated Logout request that carries no 'id_token_hint'.
//
// See: https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RedirectionAfterLogout
type PostLogoutRedirectWithoutIDTokenHintProvider interface {
	// GetAllowPostLogoutRedirectWithoutIDTokenHint returns true if a registered 'post_logout_redirect_uri' is exposed
	// when the request carries no 'id_token_hint'. The caller must then have other means of confirming the legitimacy
	// of the post-logout redirection target.
	GetAllowPostLogoutRedirectWithoutIDTokenHint(ctx context.Context) (allow bool)
}

// OmitRedirectScopeParamProvider returns the provider for configuring the omit redirect scope param.
// RedirectFragmentGuardProvider returns the provider for configuring whether an arbitrary fragment is appended to
// authorization response redirects in the query response modes.
type RedirectFragmentGuardProvider interface {
	// GetEnableRedirectFragmentGuard returns true if the '#_' fragment is appended to the 'Location' of an authorization
	// response redirect in a query response mode, so a browser does not reattach the fragment of the request URL.
	GetEnableRedirectFragmentGuard(ctx context.Context) (enable bool)
}

type OmitRedirectScopeParamProvider interface {
	// GetOmitRedirectScopeParam must be set to true if the scope query param is to be omitted
	// in the authorization's redirect URI
	GetOmitRedirectScopeParam(ctx context.Context) (omit bool)
}

// EnforcePKCEProvider returns the provider for configuring the enforcement of PKCE.
type EnforcePKCEProvider interface {
	// GetEnforcePKCE returns the enforcement of PKCE.
	GetEnforcePKCE(ctx context.Context) (enforce bool)
}

// AuthenticationRequirementsEnforcementProvider returns the provider for configuring the enforcement of the 'acr_values'
// and 'max_age' authorization request parameters.
type AuthenticationRequirementsEnforcementProvider interface {
	// GetEnforceAuthenticationRequirements returns true if an authorization request, or the approval of a device
	// authorization request, fails unless the End-User authentication satisfied the requested 'acr_values' and 'max_age'.
	GetEnforceAuthenticationRequirements(ctx context.Context) (enforce bool)
}

// ClaimsParameterEnforcementProvider returns the provider for configuring the enforcement of the OpenID Connect 1.0
// 'claims' request parameter.
type ClaimsParameterEnforcementProvider interface {
	// GetEnforceClaimsParameter returns true if the requirements the 'claims' request parameter places on the
	// authorization server are enforced.
	GetEnforceClaimsParameter(ctx context.Context) (enforce bool)
}

// RFC9470StepUpAuthenticationProvider returns the provider for configuring the advertisement of OAuth 2.0 Step Up
// Authentication Challenge Protocol support in the OAuth 2.0 Authorization Server Metadata.
//
// See: https://datatracker.ietf.org/doc/html/rfc9470#section-7
type RFC9470StepUpAuthenticationProvider interface {
	// GetRFC9470StepUpAuthenticationEnabled returns true if the 'acr_values' and 'max_age' authorization request
	// parameters are honoured for requests which do not grant the 'openid' scope.
	GetRFC9470StepUpAuthenticationEnabled(ctx context.Context) (enabled bool)
}

// AllowPublicClientsWithoutPKCEProvider returns the provider for configuring whether public clients and native
// application clients may perform the authorize code flow without PKCE.
type AllowPublicClientsWithoutPKCEProvider interface {
	// GetAllowPublicClientsWithoutPKCE returns true if public clients, and clients with the 'native' 'application_type',
	// may perform the authorize code flow without PKCE, which does not meet RFC 9700 or RFC 8252.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1 and https://www.rfc-editor.org/rfc/rfc8252#section-8.1
	GetAllowPublicClientsWithoutPKCE(ctx context.Context) (allow bool)
}

// EnablePKCEPlainChallengeMethodProvider returns the provider for configuring the enable PKCE plain challenge method.
type EnablePKCEPlainChallengeMethodProvider interface {
	// GetEnablePKCEPlainChallengeMethod returns the enable PKCE plain challenge method.
	GetEnablePKCEPlainChallengeMethod(ctx context.Context) (enable bool)
}

// GrantTypeJWTBearerCanSkipClientAuthProvider returns the provider for configuring the grant type JWT bearer can skip client auth.
type GrantTypeJWTBearerCanSkipClientAuthProvider interface {
	// GetGrantTypeJWTBearerCanSkipClientAuth returns the grant type JWT bearer can skip client auth.
	GetGrantTypeJWTBearerCanSkipClientAuth(ctx context.Context) (permitted bool)
}

// GrantTypeJWTBearerIDOptionalProvider returns the provider for configuring the grant type JWT bearer ID optional.
type GrantTypeJWTBearerIDOptionalProvider interface {
	// GetGrantTypeJWTBearerIDOptional returns the grant type JWT bearer ID optional.
	GetGrantTypeJWTBearerIDOptional(ctx context.Context) (optional bool)
}

// GrantTypeJWTBearerIssuedDateOptionalProvider returns the provider for configuring the grant type JWT bearer issued date optional.
type GrantTypeJWTBearerIssuedDateOptionalProvider interface {
	// GetGrantTypeJWTBearerIssuedDateOptional returns the grant type JWT bearer issued date optional.
	GetGrantTypeJWTBearerIssuedDateOptional(ctx context.Context) (optional bool)
}

// GetJWTMaxDurationProvider returns the provider for configuring the JWT max duration.
type GetJWTMaxDurationProvider interface {
	// GetJWTMaxDuration returns the JWT max duration.
	GetJWTMaxDuration(ctx context.Context) (max time.Duration)
}

// JWTClockSkewProvider returns the provider for configuring the clock skew permitted when validating a JWT.
type JWTClockSkewProvider interface {
	// GetJWTClockSkew returns how far into the future an 'iat' or 'nbf' claim may be in a JWT received from a client,
	// such as a client assertion, a request object, or an RFC 7523 authorization grant.
	GetJWTClockSkew(ctx context.Context) (skew time.Duration)
}

// TokenEntropyProvider returns the provider for configuring the token entropy.
type TokenEntropyProvider interface {
	// GetTokenEntropy returns the token entropy.
	GetTokenEntropy(ctx context.Context) (entropy int)
}

// GlobalSecretProvider returns the provider for configuring the global secret.
type GlobalSecretProvider interface {
	// GetGlobalSecret returns the global secret.
	GetGlobalSecret(ctx context.Context) (secret []byte, err error)
}

// RotatedGlobalSecretsProvider returns the provider for configuring the rotated global secrets.
type RotatedGlobalSecretsProvider interface {
	// GetRotatedGlobalSecrets returns the rotated global secrets.
	GetRotatedGlobalSecrets(ctx context.Context) (secrets [][]byte, err error)
}

// HMACHashingProvider returns the provider for configuring the hash function.
type HMACHashingProvider interface {
	// GetHMACHasher returns the hash function.
	GetHMACHasher(ctx context.Context) func() (hasher hash.Hash)
}

// SendDebugMessagesToClientsProvider returns the provider for configuring the send debug messages to clients.
type SendDebugMessagesToClientsProvider interface {
	// GetSendDebugMessagesToClients returns the send debug messages to clients.
	GetSendDebugMessagesToClients(ctx context.Context) (send bool)
}

// ClientAuthenticationRealmProvider returns the provider for configuring the realm of the 'Basic' challenge sent with a
// 401 invalid_client response, per RFC 6749 Section 5.2 and RFC 7617 Section 2.
type ClientAuthenticationRealmProvider interface {
	// GetClientAuthenticationRealm returns the realm of the 'Basic' client authentication challenge.
	GetClientAuthenticationRealm(ctx context.Context) (realm string)
}

// RevokeRefreshTokensExplicitlyProvider returns the provider for configuring the Refresh Token Explicit Revocation policy.
type RevokeRefreshTokensExplicitlyProvider interface {
	// GetRevokeRefreshTokensExplicit returns true if a refresh token should only be revoked explicitly.
	GetRevokeRefreshTokensExplicit(ctx context.Context) (explicit bool)

	// GetEnforceRevokeFlowRevokeRefreshTokensExplicitClient returns true if a
	// RevokeFlowRevokeRefreshTokensExplicitClient returning false should be enforced.
	GetEnforceRevokeFlowRevokeRefreshTokensExplicitClient(ctx context.Context) (explicit bool)
}

// JWKSFetcherStrategyProvider returns the provider for configuring the JWKS fetcher strategy.
type JWKSFetcherStrategyProvider interface {
	// GetJWKSFetcherStrategy returns the JWKS fetcher strategy.
	GetJWKSFetcherStrategy(ctx context.Context) (strategy jwt.JWKSFetcherStrategy)
}

// HTTPClientProvider returns the provider for configuring the HTTP client.
type HTTPClientProvider interface {
	// GetHTTPClient returns the HTTP client provider.
	GetHTTPClient(ctx context.Context) (client *retryablehttp.Client)
}

// ClientAuthenticationStrategyProvider returns the provider for configuring the client authentication strategy.
type ClientAuthenticationStrategyProvider interface {
	// GetClientAuthenticationStrategy returns the client authentication strategy.
	GetClientAuthenticationStrategy(ctx context.Context) (strategy ClientAuthenticationStrategy)
}

// ResponseModeHandlerProvider returns the provider for configuring the response mode handlers.
type ResponseModeHandlerProvider interface {
	// GetResponseModeHandlers returns the response mode handlers in order of execution.
	GetResponseModeHandlers(ctx context.Context) (handlers ResponseModeHandlers)
}

// ResponseModeParameterHandlerProvider returns the providers for configuring additional parameters in the response
// mode phase of an Authorization Request which may not be possible to determine until the final response mode is known.
type ResponseModeParameterHandlerProvider interface {
	// GetResponseModeParameterHandlers returns the ResponseModeParameterHandler's to process.
	GetResponseModeParameterHandlers(ctx context.Context) (handlers ResponseModeParameterHandlers)
}

// MessageCatalogProvider returns the provider for configuring the message catalog.
type MessageCatalogProvider interface {
	// GetMessageCatalog returns the message catalog.
	GetMessageCatalog(ctx context.Context) (catalog i18n.MessageCatalog)
}

// FormPostHTMLTemplateProvider returns the provider for configuring the form post HTML template.
type FormPostHTMLTemplateProvider interface {
	// GetFormPostHTMLTemplate returns the form post HTML template.
	GetFormPostHTMLTemplate(ctx context.Context) (tmpl *template.Template)
}

// FormPostResponseProvider provides a writer interface for writing the form post responses.
type FormPostResponseProvider interface {
	// GetFormPostResponseWriter returns a FormPostResponseWriter which should be utilized for writing the
	// form post response type.
	GetFormPostResponseWriter(ctx context.Context) FormPostResponseWriter
}

// AllowedJWTAssertionAudiencesProvider provides the audience rules for RFC 7523 JWT authorization grants and JWT client
// authentication assertions.
type AllowedJWTAssertionAudiencesProvider interface {
	// GetAllowedJWTAssertionAudiences returns the audiences accepted for an RFC 7523 JWT authorization grant in
	// addition to the issuer identifier and the token endpoint URL. They are accepted for a JWT client authentication
	// assertion only when GetDisableClientAssertionIssuerAudience returns true.
	//
	// See: https://www.rfc-editor.org/rfc/rfc10070#section-4
	GetAllowedJWTAssertionAudiences(ctx context.Context) (audiences []string)

	// GetDisableClientAssertionIssuerAudience returns true when a JWT client authentication assertion is not required
	// to carry the issuer identifier as the sole value of its 'aud' claim. The authorization grant is unaffected.
	//
	// See: https://www.rfc-editor.org/rfc/rfc10070#section-4
	// See: https://www.rfc-editor.org/rfc/rfc10070#section-5
	GetDisableClientAssertionIssuerAudience(ctx context.Context) (disable bool)
}

// ClientAssertionClientSecretEncryptionDisabledProvider returns the provider for turning off client assertions that
// are encrypted with a key derived from the client secret.
type ClientAssertionClientSecretEncryptionDisabledProvider interface {
	// GetClientAssertionClientSecretEncryptionDisabled returns true when a client assertion encrypted with a key derived
	// from the client secret per OpenID Connect Core 1.0 Section 10.2 must be rejected.
	//
	// Such an assertion identifies its client with the 'iss' and 'sub' claims per RFC 7523 Section 3, which are only
	// readable after decryption. When this returns false the client is resolved from the 'client_id' parameter, which
	// RFC 7521 Section 4.2 permits alongside the assertion, and the claims must identify that same client. An assertion
	// of this kind without the 'client_id' parameter is always rejected.
	GetClientAssertionClientSecretEncryptionDisabled(ctx context.Context) (disabled bool)
}

// AllowedIntrospectionAudiencesProvider is a provider used in contexts where the permitted audiences for an Access
// Token used to authenticate a request to the introspection endpoint is required to validate a request.
type AllowedIntrospectionAudiencesProvider interface {
	// GetAllowedIntrospectionAudiences returns the permitted audience list for introspection authentication. The
	// Access Token must carry at least one of them. An empty list does not disable the check: the configured
	// introspection endpoint URL is expected instead, then the URL the request was made to. See BearerAuthorization
	// for the full fallback chain.
	GetAllowedIntrospectionAudiences(ctx context.Context) (audiences []string)
}

// AllowedIntrospectionScopesProvider is a provider used in contexts where the required scopes for an Access Token
// used to authenticate a request to the introspection endpoint is required to validate a request.
type AllowedIntrospectionScopesProvider interface {
	// GetAllowedIntrospectionScopes returns the scopes an Access Token may carry to authenticate a request to the
	// introspection endpoint. The token must carry at least one of them. Defaults to consts.ScopeIntrospection.
	GetAllowedIntrospectionScopes(ctx context.Context) (scopes []string)
}

// AuthorizeEndpointHandlersProvider returns the provider for configuring the authorize endpoint handlers.
type AuthorizeEndpointHandlersProvider interface {
	// GetAuthorizeEndpointHandlers returns the authorize endpoint handlers.
	GetAuthorizeEndpointHandlers(ctx context.Context) (handlers AuthorizeEndpointHandlers)
}

// TokenEndpointHandlersProvider returns the provider for configuring the token endpoint handlers.
type TokenEndpointHandlersProvider interface {
	// GetTokenEndpointHandlers returns the token endpoint handlers.
	GetTokenEndpointHandlers(ctx context.Context) (handlers TokenEndpointHandlers)
}

// AuthorizeEndpointBindingHandlersProvider returns the provider for configuring the authorize endpoint binding handlers.
type AuthorizeEndpointBindingHandlersProvider interface {
	// GetAuthorizeEndpointBindingHandlers returns the authorize endpoint binding handlers.
	GetAuthorizeEndpointBindingHandlers(ctx context.Context) (handlers AuthorizeEndpointBindingHandlers)
}

// TokenEndpointBindingHandlersProvider returns the provider for configuring the token endpoint binding handlers.
type TokenEndpointBindingHandlersProvider interface {
	// GetTokenEndpointBindingHandlers returns the token endpoint binding handlers.
	GetTokenEndpointBindingHandlers(ctx context.Context) (handlers TokenEndpointBindingHandlers)
}

// RFC8628DeviceAuthorizeEndpointBindingHandlersProvider returns the provider for configuring the device authorization
// endpoint binding handlers.
type RFC8628DeviceAuthorizeEndpointBindingHandlersProvider interface {
	// GetRFC8628DeviceAuthorizeEndpointBindingHandlers returns the device authorization endpoint binding handlers.
	GetRFC8628DeviceAuthorizeEndpointBindingHandlers(ctx context.Context) (handlers RFC8628DeviceAuthorizeEndpointBindingHandlers)
}

// TokenIntrospectionHandlersProvider returns the provider for configuring the token introspection handlers.
type TokenIntrospectionHandlersProvider interface {
	// GetTokenIntrospectionHandlers returns the token introspection handlers.
	GetTokenIntrospectionHandlers(ctx context.Context) (handlers TokenIntrospectionHandlers)
}

// RevocationHandlersProvider returns the provider for configuring the revocation handlers.
type RevocationHandlersProvider interface {
	// GetRevocationHandlers returns the revocation handlers.
	GetRevocationHandlers(ctx context.Context) (handlers RevocationHandlers)
}

// PushedAuthorizeRequestHandlersProvider returns the provider for configuring the PAR handlers.
type PushedAuthorizeRequestHandlersProvider interface {
	// GetPushedAuthorizeEndpointHandlers returns the handlers.
	GetPushedAuthorizeEndpointHandlers(ctx context.Context) (handlers PushedAuthorizeEndpointHandlers)
}

// RFC8628DeviceAuthorizeConfigProvider returns the provider for configuring the device authorization response.
//
// See: https://www.rfc-editor.org/rfc/rfc8628#section-3.2
type RFC8628DeviceAuthorizeConfigProvider interface {
	// GetRFC8628CodeLifespan returns the device and user code lifespan.
	GetRFC8628CodeLifespan(ctx context.Context) (lifespan time.Duration)

	// GetRFC8628UserVerificationURL returns the end-user verification URL returned to the device as the
	// 'verification_uri' where the user enters their user code to authorize the device.
	GetRFC8628UserVerificationURL(ctx context.Context) (url string)

	// GetRFC8628TokenPollingInterval returns the minimum interval the device should wait between polling the token
	// endpoint, returned to the device as the 'interval' value.
	GetRFC8628TokenPollingInterval(ctx context.Context) (interval time.Duration)
}

// RFC7591ClientRegistrationTokenSecretProvider returns the provider for configuring the secret client registration
// tokens are signed and verified with.
type RFC7591ClientRegistrationTokenSecretProvider interface {
	// GetRFC7591ClientRegistrationGlobalSecret returns the secret used to sign client registration tokens. It is
	// deliberately separate from the global secret: a client management token never expires and RFC 7592 provides no
	// way to re-issue one, so signing it with the global secret would mean routine rotation of that secret
	// permanently locked every registered client out of its own registration.
	GetRFC7591ClientRegistrationGlobalSecret(ctx context.Context) (secret []byte, err error)

	// GetRFC7591ClientRegistrationRotatedGlobalSecrets returns the rotated client registration token secrets, which
	// remain valid for verification but are not used for signing.
	GetRFC7591ClientRegistrationRotatedGlobalSecrets(ctx context.Context) (secrets [][]byte, err error)
}

// RFC7591ClientRegistrationConfigProvider is the configuration provider for RFC 7591, RFC 7592, and OpenID Connect
// Dynamic Client Registration 1.0.
// RFC7591ClientRegistrationGrantTypesProvider returns the provider for the grant types a client may register for.
type RFC7591ClientRegistrationGrantTypesProvider interface {
	// GetRFC7591ClientRegistrationGrantTypes returns the grant types a client may register for. A registered grant
	// type outside this set is rejected with 'invalid_client_metadata'.
	GetRFC7591ClientRegistrationGrantTypes(ctx context.Context) (grantTypes []string)
}

// RFC7591AllowNativeImplicitGrantProvider returns the provider for configuring whether a client with the 'native'
// 'application_type' may register the 'implicit' grant type.
type RFC7591AllowNativeImplicitGrantProvider interface {
	// GetRFC7591AllowNativeImplicitGrant returns true if client registration accepts the 'implicit' grant type for a
	// client with the 'native' 'application_type', which RFC 8252 does not recommend.
	//
	// See: https://www.rfc-editor.org/rfc/rfc8252#section-8.2
	GetRFC7591AllowNativeImplicitGrant(ctx context.Context) (allow bool)
}

type RFC7591ClientRegistrationConfigProvider interface {
	RFC7591ClientRegistrationTokenSecretProvider
	RFC7591ClientRegistrationGrantTypesProvider
	RFC7591AllowNativeImplicitGrantProvider

	// GetRFC7591ClientRegistrationEndpointURL returns the absolute URL of the client registration endpoint. It is
	// used to build 'registration_client_uri' values and to audience initial access tokens.
	GetRFC7591ClientRegistrationEndpointURL(ctx context.Context) (endpoint string)

	// GetRFC7591ClientSecretLifespan returns the lifespan used to derive 'client_secret_expires_at'. A zero
	// duration indicates the secret does not expire.
	GetRFC7591ClientSecretLifespan(ctx context.Context) (lifespan time.Duration)

	// GetRFC7591ClientRegistrationStrategy returns the strategy used to construct and patch clients.
	GetRFC7591ClientRegistrationStrategy(ctx context.Context) (strategy ClientRegistrationStrategy)

	// GetRFC7591ClientRegistrationMetadataStrategy returns the strategy used to filter client metadata before it
	// reaches the client registration strategy and before it is returned to the client. A nil strategy leaves the
	// handlers to apply their default.
	GetRFC7591ClientRegistrationMetadataStrategy(ctx context.Context) (strategy ClientRegistrationMetadataStrategy)

	// GetRFC7591ClientRegistrationEndpointAuthStrategy returns the strategy used to authenticate requests at the
	// client registration and client configuration endpoints.
	GetRFC7591ClientRegistrationEndpointAuthStrategy(ctx context.Context) (strategy ClientRegistrationEndpointAuthStrategy)

	// GetRFC7591ClientRegistrationValidators returns the validators run in order against submitted metadata.
	GetRFC7591ClientRegistrationValidators(ctx context.Context) (validators []ClientRegistrationValidator)

	// GetRFC7591ClientRegistrationEndpointAudiences returns the audiences a client creation token may carry to be
	// accepted at the client registration endpoint. The token must carry at least one of them. An empty value means
	// the configured registration endpoint URL is expected, falling back to the URL the request was made to. A
	// deployment authorises a client to obtain such a token by adding one of these values to that client's
	// registered audience.
	GetRFC7591ClientRegistrationEndpointAudiences(ctx context.Context) (audiences []string)

	// GetRFC7591ClientRegistrationScopes returns the scopes a client creation token may carry to be accepted at the
	// client registration endpoint, defaulting to consts.ScopeClientRegistration. The token must carry at least one
	// of them. They are a second authorization dimension alongside the audience: the audience says a token is for
	// this endpoint, the scope says its holder may register clients. None of these scopes is ever grantable to a
	// registered client - see CheckGrantableScopes.
	GetRFC7591ClientRegistrationScopes(ctx context.Context) (scopes []string)
}

// RFC7591TrustedIssuer is an issuer trusted to sign JWTs presented at the client registration endpoint, with the
// location of its JSON Web Key Set: either a JWT client creation token (RFC 7591 Section 3), with or without a
// registration policy claim, or a software statement (RFC 7591 Section 2.3), depending on the list it appears in. A
// creation token issuer is only consulted when the registration endpoint has a JWT strategy available. Only keys of
// the set carrying an 'alg' and a 'use' of 'sig' are used to verify a JWT.
type RFC7591TrustedIssuer struct {
	// Issuer is the issuer identifier, compared against the iss claim of the token.
	Issuer string

	// JSONWebKeysURI is the URI of the issuer's JSON Web Key Set. Each signing key must carry 'alg' and 'use' of 'sig'.
	// When empty, a creation token issuer's set is located through the 'jwks_uri' of its OpenID Connect Discovery 1.0
	// metadata; a software statement issuer is skipped.
	JSONWebKeysURI string
}

// RFC7591ClientRegistrationPolicyProvider is the configuration provider for the registration policy that constrains
// the client metadata an authenticated registrant may register.
type RFC7591ClientRegistrationPolicyProvider interface {
	// GetRFC7591ClientRegistrationPolicyClaim returns the name of the claim, on the registration access token, that
	// carries the registration policy. It defaults to the issuer suffixed with
	// ':authelia:oauth2:dynamic-client-registration:policy'.
	GetRFC7591ClientRegistrationPolicyClaim(ctx context.Context) (claim string)

	// GetRFC7591ClientRegistrationStatelessAccessTokens returns true if a JWT client creation token issued by this
	// server is accepted without consulting access token storage, in which case it cannot be revoked before it expires.
	// A token whose registration policy sets 'max_registrations' is always resolved from storage.
	GetRFC7591ClientRegistrationStatelessAccessTokens(ctx context.Context) (enabled bool)

	// GetRFC7591ClientRegistrationTrustedIssuers returns the issuers, other than this server, trusted to issue JWT
	// client creation tokens, with or without a registration policy claim. They are only consulted when a JWT strategy
	// is available, and their tokens are only accepted at the client registration endpoint.
	GetRFC7591ClientRegistrationTrustedIssuers(ctx context.Context) (issuers []RFC7591TrustedIssuer)

	// GetRFC7591ClientRegistrationPatternIssuers returns the trusted issuers whose registration policies may hold
	// 'pattern' rules. A policy from this server may always hold them.
	GetRFC7591ClientRegistrationPatternIssuers(ctx context.Context) (issuers []string)

	// GetRFC7591SoftwareStatementIssuers returns the issuers whose software statements (RFC 7591 Section 2.3) are
	// approved. A registration or update request carrying a software statement from any other issuer is rejected, so
	// an empty list rejects every software statement.
	GetRFC7591SoftwareStatementIssuers(ctx context.Context) (issuers []RFC7591TrustedIssuer)

	RFC7591SoftwareStatementJWTValidationProvider
}

// RFC7591SoftwareStatementJWTValidationProvider is the configuration provider for how strictly a software statement
// (RFC 7591 Section 2.3) is told apart from other JWTs signed by the same issuer, which RFC 8725 Sections 2.8 and 3.12
// require of a deployment where such confusion is possible. RFC 7591 registers no JWT type for software statements;
// issuers are encouraged to use the explicit type 'software-statement+jwt' (RFC 8725 Section 3.11) and deployments to
// allow only that type once their issuers do.
type RFC7591SoftwareStatementJWTValidationProvider interface {
	// GetRFC7591SoftwareStatementJWTValidationHeaderAllowEmptyType returns true if a software statement without a 'typ'
	// header is accepted. A missing 'typ' is read as 'JWT', so it is only accepted when 'JWT' is an allowed type.
	GetRFC7591SoftwareStatementJWTValidationHeaderAllowEmptyType(ctx context.Context) (allow bool)

	// GetRFC7591SoftwareStatementJWTValidationHeaderAllowTypes returns the 'typ' header values a software statement may
	// carry, compared case-insensitively and also accepted with the 'application/' prefix. When empty it defaults to
	// 'software-statement+jwt' alone, so a generic 'JWT' such as an ID token is not mistaken for a software statement.
	GetRFC7591SoftwareStatementJWTValidationHeaderAllowTypes(ctx context.Context) (types []string)

	// GetRFC7591SoftwareStatementRequireSoftwareID returns true if a software statement must carry a non-empty
	// 'software_id' claim, which RFC 7591 Section 2.3 recommends but does not require. A JWT of another kind from the
	// same issuer, such as an ID Token, typically lacks one.
	GetRFC7591SoftwareStatementRequireSoftwareID(ctx context.Context) (require bool)
}

// RFC7591ClientRegistrationEndpointHandlersProvider returns the provider for configuring the client registration
// endpoint handlers.
type RFC7591ClientRegistrationEndpointHandlersProvider interface {
	// GetRFC7591ClientRegistrationEndpointHandlers returns the handlers.
	GetRFC7591ClientRegistrationEndpointHandlers(ctx context.Context) (handlers RFC7591ClientRegistrationEndpointHandlers)
}

// RFC7592ClientConfigurationEndpointHandlersProvider returns the provider for configuring the client configuration
// endpoint handlers.
type RFC7592ClientConfigurationEndpointHandlersProvider interface {
	// GetRFC7592ClientConfigurationEndpointHandlers returns the handlers.
	GetRFC7592ClientConfigurationEndpointHandlers(ctx context.Context) (handlers RFC7592ClientConfigurationEndpointHandlers)
}

// RFC8628DeviceAuthorizeEndpointHandlersProvider returns the provider for setting up the Device authorization handlers.
type RFC8628DeviceAuthorizeEndpointHandlersProvider interface {
	// GetRFC8628DeviceAuthorizeEndpointHandlers returns the handlers.
	GetRFC8628DeviceAuthorizeEndpointHandlers(ctx context.Context) (handlers RFC8628DeviceAuthorizeEndpointHandlers)
}

// RFC8628UserAuthorizeEndpointHandlersProvider returns the provider for setting up the Device grant user interaction handlers.
type RFC8628UserAuthorizeEndpointHandlersProvider interface {
	// GetRFC8628UserAuthorizeEndpointHandlers returns the handlers.
	GetRFC8628UserAuthorizeEndpointHandlers(ctx context.Context) (handlers RFC8628UserAuthorizeEndpointHandlers)
}

// RFC8693ConfigProvider is the configuration provider for RFC8693 Token Exchange.
type RFC8693ConfigProvider interface {
	// GetRFC8693TokenTypes returns the supported token types for Token Exchange keyed by their token type identifier
	// (i.e. the 'subject_token_type', 'actor_token_type', and 'requested_token_type' URN values).
	GetRFC8693TokenTypes(ctx context.Context) (types map[string]RFC8693TokenType)

	// GetRFC8693MaxActorChainDepth returns the maximum number of actors, including nested 'act' claims, a token issued by
	// Token Exchange may record.
	GetRFC8693MaxActorChainDepth(ctx context.Context) (depth int)

	// GetDefaultRFC8693RequestedTokenType returns the token type identifier used as the 'requested_token_type' when the
	// Token Exchange request does not explicitly specify one.
	GetDefaultRFC8693RequestedTokenType(ctx context.Context) (tokenType string)

	// GetScopeStrategy returns the scope strategy used to validate scopes during Token Exchange.
	GetScopeStrategy(ctx context.Context) (strategy ScopeStrategy)

	// GetAudienceStrategy returns the audience strategy used to validate audiences during Token Exchange.
	GetAudienceStrategy(ctx context.Context) (strategy AudienceStrategy)

	// GetResourceStrategy returns the RFC 8707 resource indicator strategy used during Token Exchange.
	GetResourceStrategy(ctx context.Context) (strategy ResourceStrategy)
}

// IDJAGConfigProvider is the configuration provider for the Identity Assertion JWT Authorization Grant.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06
type IDJAGConfigProvider interface {
	// GetIDJAGLifespan returns the lifespan of an issued grant. Defaults to 5 minutes.
	GetIDJAGLifespan(ctx context.Context) (lifespan time.Duration)

	// GetIDJAGSingleUse returns true when a grant may only be redeemed once. Section 4.4.4 permits a client to redeem
	// the same grant until it expires, so this defaults to false.
	GetIDJAGSingleUse(ctx context.Context) (single bool)

	// GetIDJAGAccessTokenAllowance returns how long an access token issued for a grant may outlive the grant. RFC 7521
	// Section 4.1 has it not exceed the validity period of the grant by a significant period, so this defaults to
	// zero, which expires the access token no later than the grant. A negative value removes the limit.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc7521#section-4.1
	GetIDJAGAccessTokenAllowance(ctx context.Context) (allowance time.Duration)
}

// IDJAGResourceOptionalProvider is optionally implemented by the configuration of an IdP Authorization Server issuing
// Identity Assertion JWT Authorization Grants.
type IDJAGResourceOptionalProvider interface {
	// GetIDJAGResourceOptional returns true when a client may omit the 'resource' parameter even though its
	// relationship lists resources, which issues a grant not restricted to a protected resource. A configuration which
	// does not implement this interface is treated as returning false, which answers invalid_target. A client
	// implementing IDJAGResourceOptionalClient can also waive it.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-4.3.3
	GetIDJAGResourceOptional(ctx context.Context) (optional bool)
}

// UseLegacyErrorFormatProvider returns the provider for configuring whether to use the legacy error format.
//
// Deprecated: Do not use this flag anymore.
type UseLegacyErrorFormatProvider interface {
	// GetUseLegacyErrorFormat returns whether to use the legacy error format.
	//
	// Deprecated: Do not use this flag anymore.
	GetUseLegacyErrorFormat(ctx context.Context) (use bool)
}

// PushedAuthorizeRequestConfigProvider is the configuration provider for pushed
// authorization requests.
type PushedAuthorizeRequestConfigProvider interface {
	// GetPushedAuthorizeRequestURIPrefix is the request URI prefix. This is
	// usually 'urn:ietf:params:oauth:request_uri:'.
	GetPushedAuthorizeRequestURIPrefix(ctx context.Context) (prefix string)

	// GetPushedAuthorizeContextLifespan is the lifespan of the short-lived PAR context.
	GetPushedAuthorizeContextLifespan(ctx context.Context) (lifespan time.Duration)

	// GetRequirePushedAuthorizationRequests indicates if the use of Pushed Authorization Requests is gobally required.
	// In this mode, a client cannot pass authorize parameters at the 'authorize' endpoint. The 'authorize' endpoint
	// must contain the PAR request_uri.
	GetRequirePushedAuthorizationRequests(ctx context.Context) (enforce bool)

	// GetRequireRedirectURIPushedAuthorizationRequests indicates if the 'redirect_uri' parameter is required in
	// Pushed Authorization Requests, even when the client has a single registered redirect URI which would otherwise
	// be used as the default.
	//
	// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.2
	GetRequireRedirectURIPushedAuthorizationRequests(ctx context.Context) (require bool)

	// GetDisablePushedAuthorizationRequestClientRefetch indicates if the client stored with a Pushed Authorization
	// Request is used as is when its 'request_uri' is redeemed at the 'authorize' endpoint, instead of fetching the
	// current client registration and validating the pushed request against it as RFC 9126 Section 7.4 recommends.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc9126#section-7.4
	GetDisablePushedAuthorizationRequestClientRefetch(ctx context.Context) (disable bool)
}

// JWTSecuredAuthorizationRequestConfigProvider is the configuration provider for JWT-Secured Authorization
// Requests (JAR).
//
// See: https://www.rfc-editor.org/rfc/rfc9101#section-9.2
type JWTSecuredAuthorizationRequestConfigProvider interface {
	// GetRequireSignedRequestObject is equivalent to the 'require_signed_request_object' authorization server metadata
	// value which indicates if the use of JWT-Secured Authorization Requests is globally required. In this mode a
	// client cannot pass authorization parameters via the OAuth 2.0 request syntax alone; the request must be
	// protected as a signed Request Object provided by either the 'request' or 'request_uri' parameter.
	GetRequireSignedRequestObject(ctx context.Context) (require bool)

	// GetRequireSignedRequestObjectSkipPushedAuthorizationRequests indicates if the requirement enforced by
	// GetRequireSignedRequestObject, or by the client metadata value of the same name, is skipped for requests made
	// directly to the Pushed Authorization Request endpoint. A Pushed Authorization Request is submitted via an
	// authenticated back-channel request which provides similar integrity guarantees to a Request Object, so some
	// deployments may consider it a sufficient substitute. This does not affect requests made to the authorization
	// endpoint.
	GetRequireSignedRequestObjectSkipPushedAuthorizationRequests(ctx context.Context) (skip bool)

	// GetRequireRequestObjectAudienceAndLifetime indicates if a Request Object must contain the 'aud', 'nbf' and 'exp'
	// claims, with an 'nbf' claim no more than GetRequestObjectMaximumLifetime in the past and an 'exp' claim no more
	// than GetRequestObjectMaximumLifetime after it. RFC 9101 requires none of these claims.
	//
	// See: https://openid.net/specs/fapi-message-signing-2_0-final.html#section-5.3.1
	GetRequireRequestObjectAudienceAndLifetime(ctx context.Context) (require bool)

	// GetRequestObjectMaximumLifetime returns the bound applied to a Request Object's 'nbf' and 'exp' claims when
	// GetRequireRequestObjectAudienceAndLifetime is enabled. A zero or negative value disables the bound.
	//
	// See: https://openid.net/specs/fapi-message-signing-2_0-final.html#section-5.3.1
	GetRequestObjectMaximumLifetime(ctx context.Context) (lifetime time.Duration)
}

// AuthorizeErrorFieldResponseStrategyProvider returns the provider for the strategy used to write authorization
// endpoint errors that cannot be delivered via a response_mode handler.
type AuthorizeErrorFieldResponseStrategyProvider interface {
	// GetAuthorizeErrorFieldResponseStrategy returns the AuthorizeErrorFieldResponseStrategy used to write authorization
	// endpoint errors directly to the response writer when no response_mode handler matches, such as when the user
	// cannot be safely redirected back to the client.
	GetAuthorizeErrorFieldResponseStrategy(ctx context.Context) (strategy AuthorizeErrorFieldResponseStrategy)
}

// TokenEndpointClientAuthStrategyProvider returns the provider for the client authentication strategy used at the token
// endpoint.
type TokenEndpointClientAuthStrategyProvider interface {
	// GetTokenEndpointClientAuthStrategy returns the EndpointClientAuthStrategy used to authenticate clients at the
	// token endpoint. This endpoint permits public clients to authenticate using the 'none' method.
	GetTokenEndpointClientAuthStrategy(ctx context.Context) (strategy EndpointClientAuthStrategy)
}

// IntrospectionEndpointClientAuthStrategyProvider returns the provider for the client authentication strategy used at
// the introspection endpoint.
type IntrospectionEndpointClientAuthStrategyProvider interface {
	// GetIntrospectionEndpointClientAuthStrategy returns the EndpointClientAuthStrategy used to authenticate clients at
	// the introspection endpoint. This endpoint does not permit public clients to authenticate using the 'none' method.
	GetIntrospectionEndpointClientAuthStrategy(ctx context.Context) (strategy EndpointClientAuthStrategy)
}

// IntrospectionEndpointClientAuthDisabledProvider returns the provider for turning off client authentication at the
// introspection endpoint.
type IntrospectionEndpointClientAuthDisabledProvider interface {
	// GetIntrospectionEndpointClientAuthDisabled returns true when the introspection endpoint must not accept client
	// authentication, leaving an Access Token presented as a bearer credential the only way to authorize a call. It is
	// off by default.
	//
	// See: https://www.rfc-editor.org/rfc/rfc7662#section-2.1
	GetIntrospectionEndpointClientAuthDisabled(ctx context.Context) (disabled bool)
}

// TokenRequestRedirectURIOptionalProvider is optionally implemented by the configuration to permit the OAuth 2.1
// authorization code token request, which omits the 'redirect_uri' parameter. When true, a token request may omit
// it if the authorization code was issued with a verified PKCE 'code_challenge' and without the 'openid' scope; a
// 'redirect_uri' that is sent must still be identical to the one from the authorization request. A configuration which
// does not implement this interface is treated as returning false, which enforces RFC 6749 Section 4.1.3. A client
// implementing TokenRequestRedirectURIOptionalClient overrides this value.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-17#section-10.2
type TokenRequestRedirectURIOptionalProvider interface {
	// GetTokenRequestRedirectURIOptional returns true if an authorization code token request protected by PKCE may
	// omit the 'redirect_uri' parameter.
	GetTokenRequestRedirectURIOptional(ctx context.Context) (optional bool)
}

// IntrospectionTokenTypeEnabledProvider returns the provider for including 'token_type' in introspection responses.
type IntrospectionTokenTypeEnabledProvider interface {
	// GetIntrospectionTokenTypeEnabled returns true if the introspection response for an active access token includes
	// the OPTIONAL 'token_type' member, the type of the token as defined in RFC 6749 Section 5.1. A DPoP-bound access
	// token is reported as 'DPoP' as RFC 9449 Section 6.2 requires. A refresh token has no such type, so the member
	// is omitted for it. An IntrospectionTokenTypeClient calling the endpoint overrides this value.
	//
	// See: https://www.rfc-editor.org/rfc/rfc7662#section-2.2
	GetIntrospectionTokenTypeEnabled(ctx context.Context) (enabled bool)
}

// RevocationEndpointClientAuthStrategyProvider returns the provider for the client authentication strategy used at the
// revocation endpoint.
type RevocationEndpointClientAuthStrategyProvider interface {
	// GetRevocationEndpointClientAuthStrategy returns the EndpointClientAuthStrategy used to authenticate clients at the
	// revocation endpoint. This endpoint permits public clients to authenticate using the 'none' method.
	GetRevocationEndpointClientAuthStrategy(ctx context.Context) (strategy EndpointClientAuthStrategy)
}

// DPoPStrictRefreshTokenBindingProvider returns the provider for configuring the RFC 9449 refresh token binding of
// confidential clients.
type DPoPStrictRefreshTokenBindingProvider interface {
	// GetDPoPStrictRefreshTokenBinding returns true if a confidential client's DPoP bound refresh token may only be
	// redeemed with a proof for the key it is bound to. When false the grant is re-bound to the key of the presented
	// proof, as RFC 9449 Section 5 does not bind the refresh tokens of confidential clients to the proof key.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9449#section-5
	GetDPoPStrictRefreshTokenBinding(ctx context.Context) (strict bool)
}

// SSFConfigProvider is the configuration provider for the OpenID Shared Signals Framework transmitter.
type SSFConfigProvider interface {
	// GetSSFConfig returns the Shared Signals Framework configuration. Has no default and may be nil. The provider
	// applies SSFConfig.WithDefaults to the result.
	GetSSFConfig(ctx context.Context) (config *SSFConfig)
}

// DPoPConfigProvider is the configuration provider for RFC 9449 DPoP.
type DPoPConfigProvider interface {
	// GetDPoPEnabled returns true if DPoP handling is enabled.
	GetDPoPEnabled(ctx context.Context) (enabled bool)

	// GetDPoPEnforce returns true if DPoP is required for all clients regardless of client metadata.
	GetDPoPEnforce(ctx context.Context) (enforce bool)

	// GetDPoPAllowedJWSAlgorithms returns the permitted asymmetric DPoP proof signing algorithms.
	GetDPoPAllowedJWSAlgorithms(ctx context.Context) (algs []string)

	// GetDPoPClockSkew returns the tolerance allowed for disagreement between this server's clock and the client's
	// when judging a DPoP proof's 'iat' claim. It widens the acceptance window at both ends and is not itself a
	// lifespan; see GetDPoPProofLifespan for that.
	GetDPoPClockSkew(ctx context.Context) (skew time.Duration)

	// GetDPoPProofLifespan returns how long a DPoP proof remains valid after the 'iat' it was minted with.
	//
	// Together with GetDPoPClockSkew this fixes the acceptance window: a proof is accepted from one clock skew
	// before its 'iat' until one lifespan plus one clock skew after it.
	GetDPoPProofLifespan(ctx context.Context) (lifespan time.Duration)

	// GetDPoPNonceRequired returns true if a server nonce is required in DPoP proofs.
	GetDPoPNonceRequired(ctx context.Context) (required bool)

	// GetDPoPNonceLifespan returns the lifespan of issued DPoP server nonces.
	GetDPoPNonceLifespan(ctx context.Context) (lifespan time.Duration)

	// GetDPoPNonceStateless returns true if DPoP server nonces carry the time at the server and are authenticated with
	// a key derived from the global secret rather than stored.
	GetDPoPNonceStateless(ctx context.Context) (stateless bool)

	// GetDPoPStrategy returns the configured DPoP strategy, or nil when DPoP is not wired.
	GetDPoPStrategy(ctx context.Context) (strategy DPoPStrategy)
}

// ResponseEncryptionTarget identifies a response that may be encrypted as a JWE.
type ResponseEncryptionTarget string

const (
	// ResponseEncryptionTargetIDToken is the ID Token.
	//
	// See: https://openid.net/specs/openid-connect-core-1_0.html#IDTokenEncryption
	ResponseEncryptionTargetIDToken ResponseEncryptionTarget = "id_token"

	// ResponseEncryptionTargetUserInfo is the UserInfo response.
	//
	// See: https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
	ResponseEncryptionTargetUserInfo ResponseEncryptionTarget = "userinfo"

	// ResponseEncryptionTargetAuthorization is the JWT-secured authorization response.
	//
	// See: https://openid.net/specs/oauth-v2-jarm.html#section-2.3
	ResponseEncryptionTargetAuthorization ResponseEncryptionTarget = "authorization"

	// ResponseEncryptionTargetIntrospection is the JWT introspection response.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9701#section-5
	ResponseEncryptionTargetIntrospection ResponseEncryptionTarget = "introspection"

	// ResponseEncryptionTargetAccessToken is a JWT access token.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9068#section-2.1
	ResponseEncryptionTargetAccessToken ResponseEncryptionTarget = "access_token"
)

// ClientAssertionAlgorithmsProvider is the configuration provider for the algorithms accepted on client assertions.
type ClientAssertionAlgorithmsProvider interface {
	// GetClientAssertionSigningAlgValues returns the JWS algorithms accepted for a client assertion.
	//
	// See: https://www.rfc-editor.org/rfc/rfc8414#section-2
	GetClientAssertionSigningAlgValues(ctx context.Context) (algs []string)

	// GetClientAssertionEncryptionAlgValues returns the JWE 'alg' values accepted for an encrypted client assertion.
	//
	// See: https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
	GetClientAssertionEncryptionAlgValues(ctx context.Context) (algs []string)

	// GetClientAssertionEncryptionEncValues returns the JWE 'enc' values accepted for an encrypted client assertion.
	//
	// See: https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
	GetClientAssertionEncryptionEncValues(ctx context.Context) (encs []string)
}

// RequestObjectAlgorithmsProvider is the configuration provider for the algorithms accepted on request objects.
type RequestObjectAlgorithmsProvider interface {
	// GetRequestObjectSigningAlgValues returns the JWS algorithms accepted for a request object.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9101#section-10.2
	GetRequestObjectSigningAlgValues(ctx context.Context) (algs []string)

	// GetRequestObjectEncryptionAlgValues returns the JWE 'alg' values accepted for an encrypted request object.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9101#section-10.2
	GetRequestObjectEncryptionAlgValues(ctx context.Context) (algs []string)

	// GetRequestObjectEncryptionEncValues returns the JWE 'enc' values accepted for an encrypted request object.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9101#section-10.2
	GetRequestObjectEncryptionEncValues(ctx context.Context) (encs []string)
}

// GrantAssertionAlgorithmsProvider is the configuration provider for the signing algorithms accepted on assertions
// presented as grants or as trust anchors.
type GrantAssertionAlgorithmsProvider interface {
	// GetRFC7523AssertionSigningAlgValues returns the JWS algorithms accepted for a JWT bearer grant assertion.
	//
	// See: https://www.rfc-editor.org/rfc/rfc7523#section-3
	GetRFC7523AssertionSigningAlgValues(ctx context.Context) (algs []string)

	// GetIDJAGRedeemSigningAlgValues returns the JWS algorithms accepted for an Identity Assertion JWT Authorization
	// Grant presented for redemption. 'none' and the HMAC algorithms are never accepted, whether listed or not, as the
	// keys of the issuer are public.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06
	GetIDJAGRedeemSigningAlgValues(ctx context.Context) (algs []string)

	// GetRFC7591TrustedIssuerSigningAlgValues returns the JWS algorithms accepted for a software statement and an
	// initial access token from a trusted issuer. 'none' and the HMAC algorithms are never accepted, whether listed or
	// not, as the keys of a trusted issuer are public.
	//
	// See: https://www.rfc-editor.org/rfc/rfc7591#section-2.3
	GetRFC7591TrustedIssuerSigningAlgValues(ctx context.Context) (algs []string)
}

// ResponseEncryptionAlgorithmsProvider is the configuration provider for the algorithms a response may be encrypted
// with.
type ResponseEncryptionAlgorithmsProvider interface {
	// GetResponseEncryptionAlgValues returns the JWE 'alg' values supported for the given response.
	//
	// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
	GetResponseEncryptionAlgValues(ctx context.Context, target ResponseEncryptionTarget) (algs []string)

	// GetResponseEncryptionEncValues returns the JWE 'enc' values supported for the given response.
	//
	// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
	GetResponseEncryptionEncValues(ctx context.Context, target ResponseEncryptionTarget) (encs []string)
}

// MTLSStrictRefreshTokenBindingProvider returns the provider for configuring the RFC 8705 refresh token binding of
// confidential clients.
type MTLSStrictRefreshTokenBindingProvider interface {
	// GetMTLSStrictRefreshTokenBinding returns true if a confidential client's certificate-bound refresh token may only
	// be redeemed with the certificate it is bound to. When false the grant is re-bound to the presented certificate,
	// as RFC 8705 Section 4 binds the refresh tokens of public clients only, and those of confidential clients are
	// sender-constrained by the client authentication RFC 6749 Section 6 requires, which RFC 8705 Section 7.1 notes
	// for the mutual-TLS client authentication methods.
	//
	// See: https://www.rfc-editor.org/rfc/rfc8705#section-4
	// See: https://www.rfc-editor.org/rfc/rfc8705#section-7.1
	// See: https://www.rfc-editor.org/rfc/rfc6749#section-6
	GetMTLSStrictRefreshTokenBinding(ctx context.Context) (strict bool)
}

// SignedResponseAlgValuesProvider returns the provider for restricting the JWS algorithms which sign JWT Secured
// Authorization Response Mode responses and RFC 9701 introspection responses, such as to the asymmetric algorithms
// which provide the non-repudiation FAPI 2.0 Message Signing Section 5.2 is for.
//
// See: https://openid.net/specs/fapi-message-signing-2_0-final.html#section-5.2
type SignedResponseAlgValuesProvider interface {
	// GetAuthorizationSignedResponseAlgValues returns the JWS algorithms which may sign a JWT Secured Authorization
	// Response Mode response, or nil for every algorithm the JARM strategy and the client secret support.
	GetAuthorizationSignedResponseAlgValues(ctx context.Context) (algs []string)

	// GetIntrospectionSignedResponseAlgValues returns the JWS algorithms which may sign an RFC 9701 introspection
	// response, or nil for every algorithm the introspection JWT response strategy and the client secret support.
	GetIntrospectionSignedResponseAlgValues(ctx context.Context) (algs []string)
}

// IntrospectionPermissionProvider returns the provider for requiring a client to be permitted to call the introspection
// endpoint.
//
// See: https://datatracker.ietf.org/doc/html/rfc7662#section-4
// See: https://openid.net/specs/fapi-message-signing-2_0-final.html#section-6.2
type IntrospectionPermissionProvider interface {
	// GetEnforceIntrospectionPermission returns true if only a client implementing IntrospectionClient whose
	// GetIntrospectionPermitted returns true may call the introspection endpoint.
	GetEnforceIntrospectionPermission(ctx context.Context) (enforce bool)
}

// EnforceSenderConstrainedAccessTokensProvider returns the provider for requiring every access token to be
// sender-constrained by either RFC 9449 DPoP or RFC 8705 Mutual-TLS.
//
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.1
type EnforceSenderConstrainedAccessTokensProvider interface {
	// GetEnforceSenderConstrainedAccessTokens returns true if every token request must bind its tokens to a DPoP
	// proof or a mutual-TLS client certificate, whichever the client presents.
	GetEnforceSenderConstrainedAccessTokens(ctx context.Context) (enforce bool)
}

// MTLSConfigProvider is the configuration provider for RFC 8705 Mutual-TLS.
type MTLSConfigProvider interface {
	// GetMTLSEnabled returns true if RFC 8705 handling is enabled.
	GetMTLSEnabled(ctx context.Context) (enabled bool)

	// GetMTLSEnforce returns true if certificate-bound access tokens are required for all clients regardless of
	// client metadata.
	GetMTLSEnforce(ctx context.Context) (enforce bool)

	// GetMTLSClientCertificateHeader returns the name of the header carrying the client certificate forwarded by a
	// trusted TLS terminating proxy, or an empty string to never read one.
	GetMTLSClientCertificateHeader(ctx context.Context) (header string)
}

// ConfirmationConfigProvider is the configuration ApplyConfirmation consults to decide whether a given RFC 7800
// confirmation method may be asserted in a token or an introspection response.
type ConfirmationConfigProvider interface {
	// GetDPoPEnabled returns true if DPoP handling is enabled.
	GetDPoPEnabled(ctx context.Context) (enabled bool)

	// GetMTLSEnabled returns true if RFC 8705 handling is enabled.
	GetMTLSEnabled(ctx context.Context) (enabled bool)
}

// IDTokenConfirmationConfigProvider is the configuration ApplyIDTokenConfirmation consults to decide whether the OpenID
// Connect Key Binding 1.0 confirmation may be asserted in an ID Token. Both getters are required, see
// confirmationMethod.enabled.
type IDTokenConfirmationConfigProvider interface {
	// GetOIDCKeyBindingEnabled returns true if OpenID Connect Key Binding 1.0 handling is enabled.
	GetOIDCKeyBindingEnabled(ctx context.Context) (enabled bool)

	// GetDPoPEnabled returns true if DPoP handling is enabled.
	GetDPoPEnabled(ctx context.Context) (enabled bool)
}

// OIDCKeyBindingConfigProvider is the configuration provider for OpenID Connect Key Binding 1.0.
type OIDCKeyBindingConfigProvider interface {
	// GetOIDCKeyBindingEnabled returns true if OpenID Connect Key Binding 1.0 handling is enabled.
	GetOIDCKeyBindingEnabled(ctx context.Context) (enabled bool)
}

// DiscoveryInformationProvider is the configuration provider for the informational authorization server and OpenID
// Provider metadata. Nil and empty values are omitted from the metadata.
type DiscoveryInformationProvider interface {
	// GetScopesSupported returns the configured 'scopes_supported' values, which are extended with the derived scopes.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
	GetScopesSupported(ctx context.Context) (scopes []string)

	// GetClaimsSupported returns the configured 'claims_supported' values, which are extended with the protocol claims
	// when OpenID Connect is registered.
	//
	// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
	GetClaimsSupported(ctx context.Context) (claims []string)

	// GetACRValuesSupported returns the 'acr_values_supported' values.
	//
	// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
	GetACRValuesSupported(ctx context.Context) (values []string)

	// GetDisplayValuesSupported returns the 'display_values_supported' values.
	//
	// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
	GetDisplayValuesSupported(ctx context.Context) (values []string)

	// GetClaimTypesSupported returns the 'claim_types_supported' values.
	//
	// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
	GetClaimTypesSupported(ctx context.Context) (types []string)

	// GetSubjectTypesSupported returns the 'subject_types_supported' values, which defaults to 'public'.
	//
	// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
	GetSubjectTypesSupported(ctx context.Context) (types []string)

	// GetUILocalesSupported returns the 'ui_locales_supported' values.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
	GetUILocalesSupported(ctx context.Context) (locales []string)

	// GetClaimsLocalesSupported returns the 'claims_locales_supported' values.
	//
	// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
	GetClaimsLocalesSupported(ctx context.Context) (locales []string)

	// GetServiceDocumentation returns the 'service_documentation' URL.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
	GetServiceDocumentation(ctx context.Context) (value string)

	// GetOPPolicyURI returns the 'op_policy_uri' URL.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
	GetOPPolicyURI(ctx context.Context) (value string)

	// GetOPTOSURI returns the 'op_tos_uri' URL.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
	GetOPTOSURI(ctx context.Context) (value string)
}

// ClientAuthMethodsProvider is the configuration provider for the client authentication methods accepted at the token,
// revocation and introspection endpoints. A nil list is not configured.
type ClientAuthMethodsProvider interface {
	// GetTokenEndpointAuthMethods returns the client authentication methods accepted at the token endpoint, narrowing
	// the methods supported by the ClientAuthenticationStrategy.
	//
	// See: https://www.rfc-editor.org/rfc/rfc8414#section-2
	GetTokenEndpointAuthMethods(ctx context.Context) (methods []string)

	// GetRevocationEndpointAuthMethods returns the client authentication methods accepted at the revocation endpoint.
	//
	// See: https://www.rfc-editor.org/rfc/rfc8414#section-2
	GetRevocationEndpointAuthMethods(ctx context.Context) (methods []string)

	// GetIntrospectionEndpointAuthMethods returns the client authentication methods accepted at the introspection
	// endpoint.
	//
	// See: https://www.rfc-editor.org/rfc/rfc8414#section-2
	GetIntrospectionEndpointAuthMethods(ctx context.Context) (methods []string)

	// GetRevocationEndpointAuthSigningAlgValues returns the JWS algorithms accepted for a client assertion at the
	// revocation endpoint, replacing the client assertion algorithms when set.
	//
	// See: https://www.rfc-editor.org/rfc/rfc8414#section-2
	GetRevocationEndpointAuthSigningAlgValues(ctx context.Context) (algs []string)

	// GetIntrospectionEndpointAuthSigningAlgValues returns the JWS algorithms accepted for a client assertion at the
	// introspection endpoint, replacing the client assertion algorithms when set.
	//
	// See: https://www.rfc-editor.org/rfc/rfc8414#section-2
	GetIntrospectionEndpointAuthSigningAlgValues(ctx context.Context) (algs []string)
}

// DiscoveryMetadataHook is called last when the OAuth 2.0 Authorization Server Metadata or the OpenID Provider Metadata
// is built, and may adjust the document before it is signed. The adjusted document must keep the configured 'issuer'
// and every required member, otherwise building it fails.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-3.3
type DiscoveryMetadataHook interface {
	// HandleDiscoveryMetadata adjusts the metadata. When the OAuth 2.0 Authorization Server Metadata is built the hook
	// receives a temporary wrapper of which only the embedded OAuth2AuthorizationServerMetadata is kept.
	HandleDiscoveryMetadata(ctx context.Context, metadata *OpenIDConnectProviderMetadata) (err error)
}

// DiscoveryMetadataHooksProvider is the configuration provider for the discovery metadata hooks.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
type DiscoveryMetadataHooksProvider interface {
	// GetDiscoveryMetadataHooks returns the hooks which run, in order, after the metadata is built.
	GetDiscoveryMetadataHooks(ctx context.Context) (hooks []DiscoveryMetadataHook)
}

// DiscoveryMetadataSigningStrategyProvider is the configuration provider for signed metadata.
type DiscoveryMetadataSigningStrategyProvider interface {
	// GetDiscoveryMetadataSigningStrategy returns the strategy which signs the metadata as the 'signed_metadata'
	// member. When nil the metadata is not signed.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2.1
	GetDiscoveryMetadataSigningStrategy(ctx context.Context) (strategy jwt.Strategy)
}
