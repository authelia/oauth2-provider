// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

// IDJAGIssuingHandler is optionally implemented by the handler which issues an Identity Assertion JWT Authorization
// Grant to report the JWS algorithms it can sign one with.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-7
type IDJAGIssuingHandler interface {
	// SigningAlgValuesSupported returns the JWS algorithms the handler can sign an ID-JAG with.
	SigningAlgValuesSupported(ctx context.Context) (algs []string)
}

// IdentityChainingHandler is optionally implemented by a token endpoint handler which issues a JWT authorization grant
// for an authorization server in another trust domain to report the 'requested_token_type' values which request one.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-chaining-17#section-3
type IdentityChainingHandler interface {
	// IdentityChainingRequestedTokenTypesSupported returns the token type identifiers which request a JWT authorization
	// grant.
	IdentityChainingRequestedTokenTypesSupported(ctx context.Context) (types []string)
}

// ErrDiscoveryOpenIDConnectNotRegistered is returned when the OpenID Provider Metadata is requested but no OpenID
// Connect handler is registered.
//
// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
var ErrDiscoveryOpenIDConnectNotRegistered = errors.New("the openid provider metadata requires an OpenID Connect handler to be registered")

type registrationTokenIntrospectorMarker interface {
	IsRegistrationTokenIntrospector()
}

type mutualTLSMarker interface {
	IsRFC8705MutualTLSHandler()
}

type dpopMarker interface {
	IsRFC9449DPoPHandler()
}

type idjagRedeemMarker interface {
	IsIDJAGRedeemHandler()
}

// NewOAuth2AuthorizationServerMetadata builds the OAuth 2.0 Authorization Server Metadata document from the registered
// handlers and the Configurator. An extension whose feature is disabled is omitted. It returns an error when the
// 'issuer' or 'response_types_supported' member is missing, when the 'authorization_endpoint' or 'token_endpoint'
// member is missing but a supported grant type requires it, or when a JWT client authentication method is listed
// without its signing algorithms.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
func (f *Fosite) NewOAuth2AuthorizationServerMetadata(ctx context.Context) (metadata *OAuth2AuthorizationServerMetadata, err error) {
	if metadata, err = f.newOAuth2AuthorizationServerMetadata(ctx, newDiscoveryCapabilities(ctx, f.Config)); err != nil {
		return nil, err
	}

	wrapper := &OpenIDConnectProviderMetadata{OAuth2AuthorizationServerMetadata: *metadata}

	if err = f.finalizeDiscoveryMetadata(ctx, wrapper, &wrapper.OAuth2AuthorizationServerMetadata, &wrapper.SignedMetadata); err != nil {
		return nil, err
	}

	return &wrapper.OAuth2AuthorizationServerMetadata, nil
}

func (f *Fosite) newOAuth2AuthorizationServerMetadata(ctx context.Context, capabilities *discoveryCapabilities) (metadata *OAuth2AuthorizationServerMetadata, err error) {
	config := f.Config

	issuer := config.GetIssuer(ctx)
	if issuer == "" {
		return nil, errors.New("the authorization server metadata requires an issuer")
	}

	urls := config.GetEndpointURLs(ctx)

	metadata = &OAuth2AuthorizationServerMetadata{
		Issuer:                            issuer,
		JWKSURI:                           urls.JWKS,
		ScopesSupported:                   supportedScopes(ctx, config, capabilities),
		ResponseTypesSupported:            capabilities.responseTypes,
		ResponseModesSupported:            SupportedResponseModes(ctx, config),
		GrantTypesSupported:               capabilities.grantTypes,
		TokenEndpointAuthMethodsSupported: SupportedTokenEndpointAuthMethods(ctx, config),
		ServiceDocumentation:              config.GetServiceDocumentation(ctx),
		UILocalesSupported:                config.GetUILocalesSupported(ctx),
		OPPolicyURI:                       config.GetOPPolicyURI(ctx),
		OPTOSURI:                          config.GetOPTOSURI(ctx),
		CodeChallengeMethodsSupported:     SupportedCodeChallengeMethods(ctx, config),
	}

	if len(config.GetAuthorizeEndpointHandlers(ctx)) != 0 {
		metadata.AuthorizationEndpoint = urls.Authorization
	}

	if len(config.GetTokenEndpointHandlers(ctx)) != 0 {
		metadata.TokenEndpoint = urls.Token
	}

	if len(config.GetRevocationHandlers(ctx)) != 0 {
		metadata.RevocationEndpoint = urls.Revocation
	}

	if err = validateOAuth2AuthorizationServerMetadataRequired(metadata); err != nil {
		return nil, err
	}

	if f.hasPublicTokenIntrospector(ctx) {
		metadata.IntrospectionEndpoint = urls.Introspection
	}

	if len(config.GetRFC7591ClientRegistrationEndpointHandlers(ctx)) != 0 {
		metadata.RegistrationEndpoint = config.GetRFC7591ClientRegistrationEndpointURL(ctx)
	}

	if err = validateConfiguredEndpointAuthMethods(ctx, config, metadata); err != nil {
		return nil, err
	}

	if slices.ContainsFunc(metadata.TokenEndpointAuthMethodsSupported, isJWTClientAuthMethod) {
		metadata.TokenEndpointAuthSigningAlgValuesSupported = withoutNone(config.GetClientAssertionSigningAlgValues(ctx))

		if len(metadata.TokenEndpointAuthSigningAlgValuesSupported) == 0 {
			return nil, errors.New("the authorization server metadata lists a JWT client authentication method in 'token_endpoint_auth_methods_supported' but no 'token_endpoint_auth_signing_alg_values_supported'")
		}
	}

	if metadata.RevocationEndpoint != "" {
		// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
		metadata.RevocationEndpointAuthMethodsSupported = SupportedEndpointAuthMethods(ctx, config, ClientAuthEndpointRevocation)

		if metadata.RevocationEndpointAuthSigningAlgValuesSupported, err = endpointAuthSigningAlgValues(ctx, config, ClientAuthEndpointRevocation, consts.DiscoveryRevocationEndpointAuthMethodsSupported, consts.DiscoveryRevocationEndpointAuthSigningAlgValuesSupported); err != nil {
			return nil, err
		}
	}

	if metadata.IntrospectionEndpoint != "" {
		metadata.IntrospectionEndpointAuthMethodsSupported = config.GetIntrospectionEndpointAuthMethods(ctx)

		if metadata.IntrospectionEndpointAuthSigningAlgValuesSupported, err = endpointAuthSigningAlgValues(ctx, config, ClientAuthEndpointIntrospection, consts.DiscoveryIntrospectionEndpointAuthMethodsSupported, consts.DiscoveryIntrospectionEndpointAuthSigningAlgValuesSupported); err != nil {
			return nil, err
		}
	}

	metadata.RFC8628DeviceAuthorizationMetadata = f.rfc8628Metadata(ctx, urls)
	metadata.RFC8705MutualTLSMetadata = f.rfc8705Metadata(ctx, urls)
	metadata.RFC9101JWTSecuredAuthorizationRequestMetadata = f.rfc9101Metadata(ctx)
	metadata.RFC9126PushedAuthorizationRequestMetadata = f.rfc9126Metadata(ctx, urls)
	metadata.RFC9207AuthorizationServerIssuerIdentificationMetadata = f.rfc9207Metadata(ctx)
	metadata.RFC9396RichAuthorizationRequestsMetadata = f.rfc9396Metadata(ctx)
	metadata.RFC9449DPoPMetadata = f.rfc9449Metadata(ctx)
	metadata.RFC9701JWTIntrospectionResponseMetadata = f.rfc9701Metadata(ctx)
	metadata.OpenIDConnectJARMMetadata = f.jarmMetadata(ctx)
	metadata.DraftClientIDMetadataDocumentMetadata = f.cimdMetadata(ctx)
	metadata.DraftIdentityChainingMetadata = f.identityChainingMetadata(ctx, capabilities.grantTypes)
	metadata.DraftIDJAGMetadata = f.idjagMetadata(ctx)

	return metadata, nil
}

// NewOpenIDConnectProviderMetadata builds the OpenID Provider Metadata document from the OAuth 2.0 Authorization Server
// Metadata, the registered handlers and the Configurator. An extension whose feature is disabled is omitted. In
// addition to the errors of NewOAuth2AuthorizationServerMetadata, it returns an error when no OpenID Connect handler is
// registered, or when the 'jwks_uri' or 'id_token_signing_alg_values_supported' member is missing.
//
// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
func (f *Fosite) NewOpenIDConnectProviderMetadata(ctx context.Context) (metadata *OpenIDConnectProviderMetadata, err error) {
	if metadata, err = f.newOpenIDConnectProviderMetadata(ctx); err != nil {
		return nil, err
	}

	if err = f.finalizeDiscoveryMetadata(ctx, metadata, metadata, &metadata.SignedMetadata); err != nil {
		return nil, err
	}

	return metadata, nil
}

func (f *Fosite) newOpenIDConnectProviderMetadata(ctx context.Context) (metadata *OpenIDConnectProviderMetadata, err error) {
	config := f.Config

	capabilities := newDiscoveryCapabilities(ctx, config)

	if !capabilities.openIDConnect {
		return nil, ErrDiscoveryOpenIDConnectNotRegistered
	}

	var base *OAuth2AuthorizationServerMetadata

	if base, err = f.newOAuth2AuthorizationServerMetadata(ctx, capabilities); err != nil {
		return nil, err
	}

	if base.JWKSURI == "" {
		return nil, errors.New("the openid provider metadata requires a 'jwks_uri'")
	}

	algs := SupportedIDTokenSignedResponseAlgValues(ctx, config)
	if len(algs) == 0 {
		return nil, errors.New("the openid provider metadata requires 'id_token_signing_alg_values_supported' but the id token issuer has no signing keys")
	}

	if !slices.Contains(algs, string(jose.RS256)) {
		return nil, errors.New("the openid provider metadata requires 'id_token_signing_alg_values_supported' to include 'RS256' but the id token issuer has no 'RS256' signing key")
	}

	subjectTypes := config.GetSubjectTypesSupported(ctx)
	if len(subjectTypes) == 0 {
		return nil, errors.New("the openid provider metadata requires 'subject_types_supported' but none are configured")
	}

	urls := config.GetEndpointURLs(ctx)

	metadata = &OpenIDConnectProviderMetadata{
		OAuth2AuthorizationServerMetadata:    *base,
		UserinfoEndpoint:                     urls.UserInfo,
		ACRValuesSupported:                   config.GetACRValuesSupported(ctx),
		SubjectTypesSupported:                subjectTypes,
		IDTokenSigningAlgValuesSupported:     algs,
		IDTokenEncryptionAlgValuesSupported:  config.GetResponseEncryptionAlgValues(ctx, ResponseEncryptionTargetIDToken),
		IDTokenEncryptionEncValuesSupported:  config.GetResponseEncryptionEncValues(ctx, ResponseEncryptionTargetIDToken),
		UserinfoSigningAlgValuesSupported:    SupportedUserinfoSignedResponseAlgValues(ctx, config),
		UserinfoEncryptionAlgValuesSupported: config.GetResponseEncryptionAlgValues(ctx, ResponseEncryptionTargetUserInfo),
		UserinfoEncryptionEncValuesSupported: config.GetResponseEncryptionEncValues(ctx, ResponseEncryptionTargetUserInfo),
		DisplayValuesSupported:               config.GetDisplayValuesSupported(ctx),
		ClaimTypesSupported:                  config.GetClaimTypesSupported(ctx),
		ClaimsSupported:                      supportedClaims(ctx, config, capabilities.openIDConnect),
		ClaimsLocalesSupported:               config.GetClaimsLocalesSupported(ctx),
		ClaimsParameterSupported:             isClaimsParameterEnforced(ctx, config),
		RequestParameterSupported:            true,
		RequestURIParameterSupported:         new(true),
		RequireRequestURIRegistration:        true,
	}

	metadata.OpenIDConnectRPInitiatedLogoutMetadata = rpInitiatedLogoutMetadata(urls)
	metadata.OpenIDConnectBackChannelLogoutMetadata = f.backChannelLogoutMetadata(ctx)
	metadata.OpenIDConnectPromptCreateMetadata = f.promptCreateMetadata(ctx)

	return metadata, nil
}

func (f *Fosite) finalizeDiscoveryMetadata(ctx context.Context, metadata *OpenIDConnectProviderMetadata, document any, signed *string) (err error) {
	for _, hook := range f.Config.GetDiscoveryMetadataHooks(ctx) {
		if err = hook.HandleDiscoveryMetadata(ctx, metadata); err != nil {
			return fmt.Errorf("the discovery metadata hook failed: %w", err)
		}
	}

	strategy := f.Config.GetDiscoveryMetadataSigningStrategy(ctx)
	if strategy == nil {
		return nil
	}

	*signed = ""

	var raw []byte

	if raw, err = json.Marshal(document); err != nil {
		return fmt.Errorf("unable to marshal the discovery metadata for signing: %w", err)
	}

	claims := jwt.MapClaims{}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()

	if err = decoder.Decode(&claims); err != nil {
		return fmt.Errorf("unable to prepare the discovery metadata for signing: %w", err)
	}

	delete(claims, consts.DiscoverySignedMetadata)

	claims[consts.ClaimIssuer] = metadata.Issuer

	algs := strategy.SigningAlgValues(ctx)

	var alg string

	switch {
	case len(algs) == 0:
		return errors.New("unable to sign the discovery metadata: the signing strategy has no signing algorithms")
	case slices.Contains(algs, string(jose.RS256)):
		alg = string(jose.RS256)
	default:
		alg = slices.Sorted(slices.Values(algs))[0]
	}

	if *signed, _, err = strategy.Encode(ctx, claims, jwt.WithIssuerSigningAlg(alg)); err != nil {
		return fmt.Errorf("unable to sign the discovery metadata: %w", err)
	}

	return nil
}

func rpInitiatedLogoutMetadata(urls EndpointURLs) *OpenIDConnectRPInitiatedLogoutMetadata {
	if urls.EndSession == "" {
		return nil
	}

	return &OpenIDConnectRPInitiatedLogoutMetadata{
		EndSessionEndpoint: urls.EndSession,
	}
}

func (f *Fosite) backChannelLogoutMetadata(ctx context.Context) *OpenIDConnectBackChannelLogoutMetadata {
	if f.Config.GetBackChannelLogoutTokenStrategy(ctx) == nil {
		return nil
	}

	return &OpenIDConnectBackChannelLogoutMetadata{
		BackChannelLogoutSupported:        true,
		BackChannelLogoutSessionSupported: true,
	}
}

func (f *Fosite) promptCreateMetadata(ctx context.Context) *OpenIDConnectPromptCreateMetadata {
	prompts := sortedUnique(SupportedPromptValues(ctx, f.Config))
	if len(prompts) == 0 {
		return nil
	}

	return &OpenIDConnectPromptCreateMetadata{
		PromptValuesSupported: prompts,
	}
}

func (f *Fosite) hasPublicTokenIntrospector(ctx context.Context) bool {
	for _, h := range f.Config.GetTokenIntrospectionHandlers(ctx) {
		if _, ok := h.(registrationTokenIntrospectorMarker); !ok {
			return true
		}
	}

	return false
}

func (f *Fosite) rfc8628Metadata(ctx context.Context, urls EndpointURLs) *RFC8628DeviceAuthorizationMetadata {
	if urls.DeviceAuthorization == "" || len(f.Config.GetRFC8628DeviceAuthorizeEndpointHandlers(ctx)) == 0 {
		return nil
	}

	return &RFC8628DeviceAuthorizationMetadata{
		DeviceAuthorizationEndpoint: urls.DeviceAuthorization,
	}
}

// rfc8705Metadata advertises certificate-bound access tokens when the RFC 8705 handler is registered, and the mutual
// TLS endpoint aliases whenever mutual TLS is enabled, as they apply to mutual TLS client authentication as well as to
// certificate-bound tokens.
//
// See: https://datatracker.ietf.org/doc/html/rfc8705#section-5
func (f *Fosite) rfc8705Metadata(ctx context.Context, urls EndpointURLs) *RFC8705MutualTLSMetadata {
	if !f.Config.GetMTLSEnabled(ctx) {
		return nil
	}

	metadata := &RFC8705MutualTLSMetadata{
		TLSClientCertificateBoundAccessTokens: hasMarker[mutualTLSMarker](ctx, f.Config),
	}

	if urls.MutualTLSAliases != (RFC8705MutualTLSEndpointAliases{}) {
		aliases := urls.MutualTLSAliases

		metadata.MutualTLSEndpointAliases = &aliases
	}

	if !metadata.TLSClientCertificateBoundAccessTokens && metadata.MutualTLSEndpointAliases == nil {
		return nil
	}

	return metadata
}

func (f *Fosite) rfc9101Metadata(ctx context.Context) *RFC9101JWTSecuredAuthorizationRequestMetadata {
	return &RFC9101JWTSecuredAuthorizationRequestMetadata{
		RequestObjectSigningAlgValuesSupported:    SupportedRequestObjectSigningAlgValues(ctx, f.Config),
		RequestObjectEncryptionAlgValuesSupported: f.Config.GetRequestObjectEncryptionAlgValues(ctx),
		RequestObjectEncryptionEncValuesSupported: f.Config.GetRequestObjectEncryptionEncValues(ctx),
		RequireSignedRequestObject:                f.Config.GetRequireSignedRequestObject(ctx),
	}
}

func (f *Fosite) rfc9126Metadata(ctx context.Context, urls EndpointURLs) *RFC9126PushedAuthorizationRequestMetadata {
	if urls.PushedAuthorizationRequest == "" || len(f.Config.GetPushedAuthorizeEndpointHandlers(ctx)) == 0 {
		return nil
	}

	return &RFC9126PushedAuthorizationRequestMetadata{
		PushedAuthorizationRequestEndpoint: urls.PushedAuthorizationRequest,
		RequirePushedAuthorizationRequests: f.Config.GetRequirePushedAuthorizationRequests(ctx),
	}
}

func (f *Fosite) rfc9207Metadata(ctx context.Context) *RFC9207AuthorizationServerIssuerIdentificationMetadata {
	provider, ok := f.Config.(ResponseModeParameterHandlerProvider)
	// See: https://datatracker.ietf.org/doc/html/rfc9207#section-2
	if !ok || !f.Config.GetAuthorizationServerIdentificationEnabled(ctx) || f.Config.GetIssuer(ctx) == "" {
		return nil
	}

	for _, h := range provider.GetResponseModeParameterHandlers(ctx) {
		if _, ok := h.(*RFC9207ResponseModeParameterHandler); ok {
			return &RFC9207AuthorizationServerIssuerIdentificationMetadata{
				AuthorizationResponseISSParameterSupported: true,
			}
		}
	}

	return nil
}

func (f *Fosite) rfc9396Metadata(ctx context.Context) *RFC9396RichAuthorizationRequestsMetadata {
	handlers := f.Config.GetAuthorizationDetailsTypeHandlers(ctx)
	if len(handlers) == 0 {
		return nil
	}

	if !slices.ContainsFunc(f.Config.GetTokenEndpointHandlers(ctx), func(h TokenEndpointHandler) bool {
		_, ok := h.(AuthorizationDetailsTokenEndpointHandler)

		return ok
	}) {
		return nil
	}

	types := make([]string, 0, len(handlers))

	for t := range handlers {
		types = append(types, t)
	}

	return &RFC9396RichAuthorizationRequestsMetadata{
		AuthorizationDetailsTypesSupported: sortedUnique(types),
	}
}

func (f *Fosite) rfc9449Metadata(ctx context.Context) *RFC9449DPoPMetadata {
	if !f.Config.GetDPoPEnabled(ctx) || !hasMarker[dpopMarker](ctx, f.Config) {
		return nil
	}

	return &RFC9449DPoPMetadata{
		DPoPSigningAlgValuesSupported: f.Config.GetDPoPAllowedJWSAlgorithms(ctx),
	}
}

func (f *Fosite) rfc9701Metadata(ctx context.Context) *RFC9701JWTIntrospectionResponseMetadata {
	strategy := f.Config.GetIntrospectionJWTResponseStrategy(ctx)
	if strategy == nil {
		return nil
	}

	return &RFC9701JWTIntrospectionResponseMetadata{
		IntrospectionSigningAlgValuesSupported:    SupportedIntrospectionSignedResponseAlgValues(ctx, f.Config),
		IntrospectionEncryptionAlgValuesSupported: f.Config.GetResponseEncryptionAlgValues(ctx, ResponseEncryptionTargetIntrospection),
		IntrospectionEncryptionEncValuesSupported: f.Config.GetResponseEncryptionEncValues(ctx, ResponseEncryptionTargetIntrospection),
	}
}

func (f *Fosite) jarmMetadata(ctx context.Context) *OpenIDConnectJARMMetadata {
	strategy := f.Config.GetJWTSecuredAuthorizeResponseModeStrategy(ctx)
	if strategy == nil {
		return nil
	}

	return &OpenIDConnectJARMMetadata{
		AuthorizationSigningAlgValuesSupported:    SupportedAuthorizationSignedResponseAlgValues(ctx, f.Config),
		AuthorizationEncryptionAlgValuesSupported: f.Config.GetResponseEncryptionAlgValues(ctx, ResponseEncryptionTargetAuthorization),
		AuthorizationEncryptionEncValuesSupported: f.Config.GetResponseEncryptionEncValues(ctx, ResponseEncryptionTargetAuthorization),
	}
}

// cimdMetadata advertises Client ID Metadata Document support only when GetClient resolves one: a resolver is
// configured and the RFC 9207 'iss' parameter the authorization response must include is sent.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-7
func (f *Fosite) cimdMetadata(ctx context.Context) *DraftClientIDMetadataDocumentMetadata {
	provider, ok := f.Config.(ClientIDMetadataDocumentConfigProvider)
	if !ok || provider.GetClientIDMetadataDocumentResolver(ctx) == nil || getAuthorizationServerIdentificationIssuer(ctx, f.Config) == "" {
		return nil
	}

	return &DraftClientIDMetadataDocumentMetadata{
		ClientIDMetadataDocumentSupported: true,
	}
}

func (f *Fosite) identityChainingMetadata(ctx context.Context, grantTypes []string) *DraftIdentityChainingMetadata {
	if !slices.Contains(grantTypes, consts.GrantTypeOAuthTokenExchange) {
		return nil
	}

	var types []string

	for _, h := range f.Config.GetTokenEndpointHandlers(ctx) {
		if handler, ok := h.(IdentityChainingHandler); ok {
			types = append(types, handler.IdentityChainingRequestedTokenTypesSupported(ctx)...)
		}
	}

	if types = sortedUnique(types); len(types) == 0 {
		return nil
	}

	return &DraftIdentityChainingMetadata{
		IdentityChainingRequestedTokenTypesSupported: types,
	}
}

func (f *Fosite) idjagMetadata(ctx context.Context) *DraftIDJAGMetadata {
	metadata := &DraftIDJAGMetadata{}

	if hasMarker[idjagRedeemMarker](ctx, f.Config) {
		metadata.AuthorizationGrantProfilesSupported = []string{consts.GrantProfileIDJAG}
	}

	issuing := false

	for _, h := range f.Config.GetTokenEndpointHandlers(ctx) {
		if issuer, ok := h.(IDJAGIssuingHandler); ok {
			issuing = true

			metadata.IDJAGSigningAlgValuesSupported = append(metadata.IDJAGSigningAlgValuesSupported, issuer.SigningAlgValuesSupported(ctx)...)
		}
	}

	if !issuing && metadata.AuthorizationGrantProfilesSupported == nil {
		return nil
	}

	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-7.1
	if metadata.IDJAGSigningAlgValuesSupported = sortedUnique(metadata.IDJAGSigningAlgValuesSupported); !slices.Contains(metadata.IDJAGSigningAlgValuesSupported, string(jose.RS256)) {
		metadata.IDJAGSigningAlgValuesSupported = nil
	}

	return metadata
}

// validateOAuth2AuthorizationServerMetadataRequired rejects metadata missing a member RFC 8414 Section 2 requires:
// 'response_types_supported' always, 'authorization_endpoint' unless no supported grant type uses the authorization
// endpoint, and 'token_endpoint' unless only the implicit grant type is supported.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
func validateOAuth2AuthorizationServerMetadataRequired(metadata *OAuth2AuthorizationServerMetadata) (err error) {
	if len(metadata.ResponseTypesSupported) == 0 {
		return errors.New("the authorization server metadata requires 'response_types_supported' but no handler supports a response type")
	}

	if metadata.AuthorizationEndpoint == "" && slices.ContainsFunc(metadata.GrantTypesSupported, func(grantType string) bool {
		return grantType == consts.GrantTypeAuthorizationCode || grantType == consts.GrantTypeImplicit
	}) {
		return errors.New("the authorization server metadata requires an 'authorization_endpoint' as a supported grant type uses the authorization endpoint")
	}

	if metadata.TokenEndpoint == "" && slices.ContainsFunc(metadata.GrantTypesSupported, func(grantType string) bool {
		return grantType != consts.GrantTypeImplicit
	}) {
		return errors.New("the authorization server metadata requires a 'token_endpoint' as a grant type other than 'implicit' is supported")
	}

	return nil
}

// isClaimsParameterEnforced reports whether the authorization server meets the requirements OpenID Connect Core 1.0
// places on an OP which supports the 'claims' parameter: a requested 'sub' value and an Essential 'acr' value are
// enforced. Only then is 'claims_parameter_supported' advertised.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequestValidation
// See: https://openid.net/specs/openid-connect-core-1_0.html#acrSemantics
func isClaimsParameterEnforced(ctx context.Context, config Configurator) bool {
	provider, ok := config.(ClaimsParameterEnforcementProvider)

	return ok && provider.GetEnforceClaimsParameter(ctx)
}

func hasMarker[T any](ctx context.Context, config Configurator) bool {
	return anyHandler(ctx, config, func(h any) bool {
		_, ok := h.(T)

		return ok
	})
}

// endpointAuthSigningAlgValues returns the signing algorithms advertised for the revocation or introspection endpoint:
// the configured algorithms, and when the endpoint accepts a JWT client authentication method the algorithms it
// accepts, which must not be empty.
func endpointAuthSigningAlgValues(ctx context.Context, config Configurator, endpoint ClientAuthEndpoint, methodsName, algsName string) (algs []string, err error) {
	if !slices.ContainsFunc(SupportedEndpointAuthMethods(ctx, config, endpoint), isJWTClientAuthMethod) {
		return withoutNone(configuredEndpointAuthSigningAlgValues(ctx, config, endpoint)), nil
	}

	if algs = withoutNone(SupportedEndpointAuthSigningAlgValues(ctx, config, endpoint)); len(algs) == 0 {
		return nil, fmt.Errorf("the authorization server metadata lists a JWT client authentication method in '%s' but no '%s'", methodsName, algsName)
	}

	return algs, nil
}

// validateConfiguredEndpointAuthMethods rejects a configured client authentication method of an advertised endpoint
// which the ClientAuthenticationStrategy cannot authenticate a client with, as advertising it would invite clients to
// register a method no request can succeed with.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
func validateConfiguredEndpointAuthMethods(ctx context.Context, config Configurator, metadata *OAuth2AuthorizationServerMetadata) (err error) {
	for _, endpoint := range []struct {
		endpoint   ClientAuthEndpoint
		member     string
		advertised bool
	}{
		{ClientAuthEndpointToken, consts.DiscoveryTokenEndpointAuthMethodsSupported, true},
		{ClientAuthEndpointRevocation, consts.DiscoveryRevocationEndpointAuthMethodsSupported, metadata.RevocationEndpoint != ""},
		{ClientAuthEndpointIntrospection, consts.DiscoveryIntrospectionEndpointAuthMethodsSupported, metadata.IntrospectionEndpoint != ""},
	} {
		if !endpoint.advertised {
			continue
		}

		if methods := unsupportedEndpointAuthMethods(ctx, config, endpoint.endpoint); len(methods) != 0 {
			return fmt.Errorf("the authorization server metadata lists the client authentication methods '%s' in '%s' but the client authentication strategy does not support them", strings.Join(methods, "', '"), endpoint.member)
		}
	}

	return nil
}

func isJWTClientAuthMethod(method string) bool {
	return method == consts.ClientAuthMethodPrivateKeyJWT || method == consts.ClientAuthMethodClientSecretJWT
}

func withoutNone(algs []string) (out []string) {
	for _, alg := range algs {
		if alg != consts.JSONWebTokenAlgNone {
			out = append(out, alg)
		}
	}

	return out
}

func clientSecretSigningAlgValues(algs []string) []string {
	return append(slices.Clone(algs), consts.JSONWebTokenAlgHMACSHA256, consts.JSONWebTokenAlgHMACSHA384, consts.JSONWebTokenAlgHMACSHA512)
}
