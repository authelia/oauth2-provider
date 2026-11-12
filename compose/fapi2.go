// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/handler/par"
	"authelia.com/provider/oauth2/handler/pkce"
	"authelia.com/provider/oauth2/handler/rfc7523"
	"authelia.com/provider/oauth2/handler/rfc8705"
	"authelia.com/provider/oauth2/handler/rfc9449"
)

const (
	fapi2SectionGeneral               = "5.3.2.1"
	fapi2SectionAuthorizationEndpoint = "5.3.2.2"
	fapi2SectionCryptography          = "5.4.1"

	fapi2MaximumAuthorizeCodeLifespan = oauth2.FAPI2SecurityProfileMaximumAuthorizeCodeLifespan
	fapi2MaximumPushedAuthorizeLife   = 10 * time.Minute
	fapi2MinimumClockSkew             = 10 * time.Second
	fapi2MaximumClockSkew             = time.Minute
)

// ApplyFAPI2SecurityProfile sets the options of config which the FAPI 2.0 Security Profile requires of an authorization
// server: pushed authorization requests with a redirect URI, PKCE with S256, the RFC 9207 'iss' parameter, the issuer
// as the sole client assertion audience, no refresh token rotation, sender-constrained access tokens, an authorization
// code lifetime of at most 60 seconds, a clock skew allowance between 10 and 60 seconds, and only the permitted client
// authentication methods and JWS algorithms. A value already within the profile is kept.
//
// It does not set Issuer, enable DPoP or mTLS, or register handlers, so ValidateFAPI2SecurityProfile must still be
// called once the provider is composed. An unset introspection endpoint list, which accepts every supported method, and
// one holding only access token types are kept, so an unset one must be set when an introspection handler is
// registered.
//
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2
func ApplyFAPI2SecurityProfile(config *oauth2.Config) {
	config.RequirePushedAuthorizationRequests = true
	config.RequireRedirectURIPushedAuthorizationRequests = true
	config.EnforcePKCE = true
	config.EnablePKCEPlainChallengeMethod = false
	config.DisableAuthorizationServerIdentification = false
	config.DisableClientAssertionIssuerAudience = false
	config.DisableRefreshTokenRotation = true
	config.EnforceSenderConstrainedAccessTokens = true

	if config.AuthorizeCodeLifespan <= 0 || config.AuthorizeCodeLifespan > fapi2MaximumAuthorizeCodeLifespan {
		config.AuthorizeCodeLifespan = fapi2MaximumAuthorizeCodeLifespan
	}

	if config.PushedAuthorizeContextLifespan >= fapi2MaximumPushedAuthorizeLife {
		config.PushedAuthorizeContextLifespan = 0
	}

	if config.JWTClockSkew != 0 && (config.JWTClockSkew < fapi2MinimumClockSkew || config.JWTClockSkew > fapi2MaximumClockSkew) {
		config.JWTClockSkew = 0
	}

	if config.DPoPClockSkew != 0 && (config.DPoPClockSkew < fapi2MinimumClockSkew || config.DPoPClockSkew > fapi2MaximumClockSkew) {
		config.DPoPClockSkew = 0
	}

	config.TokenEndpointAuthMethods = fapi2Permitted(config.TokenEndpointAuthMethods, oauth2.FAPI2SecurityProfileClientAuthMethods)
	config.RevocationEndpointAuthMethods = fapi2Permitted(config.RevocationEndpointAuthMethods, oauth2.FAPI2SecurityProfileClientAuthMethods)
	config.ClientAssertionSigningAlgValues = fapi2Permitted(config.ClientAssertionSigningAlgValues, oauth2.FAPI2SecurityProfileSigningAlgValues)
	config.RequestObjectSigningAlgValues = fapi2Permitted(config.RequestObjectSigningAlgValues, oauth2.FAPI2SecurityProfileSigningAlgValues)
	config.DPoPAllowedJWSAlgorithms = fapi2Permitted(config.DPoPAllowedJWSAlgorithms, oauth2.FAPI2SecurityProfileSigningAlgValues)
	config.RFC7523AssertionSigningAlgValues = fapi2Permitted(config.RFC7523AssertionSigningAlgValues, oauth2.FAPI2SecurityProfileSigningAlgValues)
	config.IntrospectionEndpointAuthMethods = fapi2PermittedIntrospectionAuthMethods(config.IntrospectionEndpointAuthMethods)

	if len(config.RevocationEndpointAuthSigningAlgValues) != 0 {
		config.RevocationEndpointAuthSigningAlgValues = fapi2Permitted(config.RevocationEndpointAuthSigningAlgValues, oauth2.FAPI2SecurityProfileSigningAlgValues)
	}

	if len(config.IntrospectionEndpointAuthSigningAlgValues) != 0 {
		config.IntrospectionEndpointAuthSigningAlgValues = fapi2Permitted(config.IntrospectionEndpointAuthSigningAlgValues, oauth2.FAPI2SecurityProfileSigningAlgValues)
	}
}

// ValidateFAPI2SecurityProfile returns an error joining every way the configuration and the handlers registered with it
// fail the authorization server requirements of the FAPI 2.0 Security Profile which the configuration determines, or
// nil when it meets them. Call it once the provider is composed. Of the authorize endpoint handlers it recognizes only
// those of this library serving the implicit, hybrid and 'none' response types, not a custom handler serving another
// response type. It does not check the clients, which must be confidential and register the 'code' response type, or
// the keys which sign the JWTs the server issues, which must use PS256, ES256 or EdDSA.
//
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2
func ValidateFAPI2SecurityProfile(ctx context.Context, config oauth2.Configurator) (err error) {
	v := &fapi2Violations{}

	v.general(ctx, config)
	v.senderConstrained(ctx, config)
	v.authorizationEndpoint(ctx, config)
	v.cryptography(ctx, config)

	return errors.Join(v.errs...)
}

type fapi2Violations struct {
	errs []error
}

func (v *fapi2Violations) fail(section, format string, args ...any) {
	v.errs = append(v.errs, fmt.Errorf("FAPI 2.0 Security Profile Section %s: %s", section, fmt.Sprintf(format, args...)))
}

func (v *fapi2Violations) general(ctx context.Context, config oauth2.Configurator) {
	for _, h := range config.GetTokenEndpointHandlers(ctx) {
		if _, ok := h.(*hoauth2.ResourceOwnerPasswordCredentialsGrantHandler); ok { //nolint:staticcheck
			v.fail(fapi2SectionGeneral, "the resource owner password credentials grant handler must not be registered")
		}
	}

	for _, e := range []oauth2.ClientAuthEndpoint{oauth2.ClientAuthEndpointToken, oauth2.ClientAuthEndpointRevocation} {
		if methods := oauth2.SupportedEndpointAuthMethods(ctx, config, e); !fapi2Subset(methods, oauth2.FAPI2SecurityProfileClientAuthMethods) {
			v.fail(fapi2SectionGeneral, "the %s endpoint accepts the client authentication methods '%s', but only '%s' are permitted", e, strings.Join(methods, "', '"), strings.Join(oauth2.FAPI2SecurityProfileClientAuthMethods, "', '"))
		}
	}

	if len(config.GetTokenIntrospectionHandlers(ctx)) != 0 {
		methods := slices.DeleteFunc(oauth2.SupportedEndpointAuthMethods(ctx, config, oauth2.ClientAuthEndpointIntrospection), oauth2.IsAccessTokenTypeAuthMethod)

		if slices.ContainsFunc(methods, func(method string) bool {
			return !slices.Contains(oauth2.FAPI2SecurityProfileClientAuthMethods, method)
		}) {
			v.fail(fapi2SectionGeneral, "the %s endpoint accepts the client authentication methods '%s', but only '%s' are permitted", oauth2.ClientAuthEndpointIntrospection, strings.Join(methods, "', '"), strings.Join(oauth2.FAPI2SecurityProfileClientAuthMethods, "', '"))
		}
	}

	if p, ok := config.(oauth2.AllowedJWTAssertionAudiencesProvider); !ok || p.GetDisableClientAssertionIssuerAudience(ctx) {
		v.fail(fapi2SectionGeneral, "the issuer must be the sole client assertion audience, but DisableClientAssertionIssuerAudience is set")
	}

	if !config.GetDisableRefreshTokenRotation(ctx) {
		v.fail(fapi2SectionGeneral, "refresh tokens must not be rotated, but DisableRefreshTokenRotation is not set")
	}

	if lifespan := config.GetAuthorizeCodeLifespan(ctx); lifespan > fapi2MaximumAuthorizeCodeLifespan {
		v.fail(fapi2SectionGeneral, "the authorization code lifetime must be at most %s, but is %s", fapi2MaximumAuthorizeCodeLifespan, lifespan)
	}

	if p, ok := config.(oauth2.JWTClockSkewProvider); !ok {
		v.fail(fapi2SectionGeneral, "JWTs with an 'iat' or 'nbf' up to %s in the future must be accepted, but the configuration has no JWT clock skew", fapi2MinimumClockSkew)
	} else if skew := p.GetJWTClockSkew(ctx); skew < fapi2MinimumClockSkew || skew > fapi2MaximumClockSkew {
		v.fail(fapi2SectionGeneral, "the JWT clock skew must be between %s and %s, but is %s", fapi2MinimumClockSkew, fapi2MaximumClockSkew, skew)
	}
}

func (v *fapi2Violations) senderConstrained(ctx context.Context, config oauth2.Configurator) {
	if p, ok := config.(oauth2.EnforceSenderConstrainedAccessTokensProvider); !ok || !p.GetEnforceSenderConstrainedAccessTokens(ctx) {
		v.fail(fapi2SectionGeneral, "only sender-constrained access tokens may be issued, but EnforceSenderConstrainedAccessTokens is not set")
	}

	dpop, mtls := config.GetDPoPEnabled(ctx), config.GetMTLSEnabled(ctx)

	if !dpop && !mtls {
		v.fail(fapi2SectionGeneral, "access tokens must be sender-constrained by DPoP or mTLS, but neither is enabled")
	}

	if mtls && !fapi2Registered[*rfc8705.Handler](config.GetTokenEndpointBindingHandlers(ctx)) {
		v.fail(fapi2SectionGeneral, "mTLS is enabled, but the mTLS certificate-bound access token handler is not registered")
	}

	if !dpop {
		return
	}

	if !fapi2Registered[*rfc9449.Handler](config.GetTokenEndpointBindingHandlers(ctx)) {
		v.fail(fapi2SectionGeneral, "DPoP is enabled, but the DPoP token endpoint handler is not registered")
	}

	if p, ok := config.(oauth2.AuthorizeEndpointBindingHandlersProvider); !ok || !fapi2Registered[*rfc9449.AuthorizeHandler](p.GetAuthorizeEndpointBindingHandlers(ctx)) {
		v.fail(fapi2SectionGeneral, "DPoP is enabled, but the DPoP authorization code binding handler is not registered")
	}

	if skew := config.GetDPoPClockSkew(ctx); skew < fapi2MinimumClockSkew || skew > fapi2MaximumClockSkew {
		v.fail(fapi2SectionGeneral, "the DPoP clock skew must be between %s and %s, but is %s", fapi2MinimumClockSkew, fapi2MaximumClockSkew, skew)
	}

	if algs := config.GetDPoPAllowedJWSAlgorithms(ctx); !fapi2Subset(algs, oauth2.FAPI2SecurityProfileSigningAlgValues) {
		v.fail(fapi2SectionCryptography, "the DPoP proof algorithms '%s' include one not permitted", strings.Join(algs, "', '"))
	}
}

func (v *fapi2Violations) authorizationEndpoint(ctx context.Context, config oauth2.Configurator) {
	for _, h := range config.GetAuthorizeEndpointHandlers(ctx) {
		switch h.(type) {
		case *hoauth2.AuthorizeImplicitGrantTypeHandler, *openid.OpenIDConnectImplicitHandler, *openid.OpenIDConnectHybridHandler, *hoauth2.NoneResponseTypeHandler:
			v.fail(fapi2SectionAuthorizationEndpoint, "the response type must be 'code', but the '%T' authorize endpoint handler is registered", h)
		}
	}

	if !fapi2Registered[*par.PushedAuthorizeHandler](config.GetPushedAuthorizeEndpointHandlers(ctx)) {
		v.fail(fapi2SectionAuthorizationEndpoint, "pushed authorization requests must be supported, but the pushed authorization request handler is not registered")
	}

	if !config.GetRequirePushedAuthorizationRequests(ctx) {
		v.fail(fapi2SectionAuthorizationEndpoint, "authorization requests must be pushed, but RequirePushedAuthorizationRequests is not set")
	}

	if !config.GetRequireRedirectURIPushedAuthorizationRequests(ctx) {
		v.fail(fapi2SectionAuthorizationEndpoint, "pushed authorization requests must carry 'redirect_uri', but RequireRedirectURIPushedAuthorizationRequests is not set")
	}

	if lifespan := config.GetPushedAuthorizeContextLifespan(ctx); lifespan >= fapi2MaximumPushedAuthorizeLife {
		v.fail(fapi2SectionAuthorizationEndpoint, "the pushed authorization request 'expires_in' must be less than %s, but is %s", fapi2MaximumPushedAuthorizeLife, lifespan)
	}

	if !fapi2Registered[*pkce.Handler](config.GetAuthorizeEndpointHandlers(ctx)) {
		v.fail(fapi2SectionAuthorizationEndpoint, "PKCE is required, but the PKCE handler is not registered")
	}

	if !config.GetEnforcePKCE(ctx) {
		v.fail(fapi2SectionAuthorizationEndpoint, "PKCE is required, but EnforcePKCE is not set")
	}

	if config.GetEnablePKCEPlainChallengeMethod(ctx) {
		v.fail(fapi2SectionAuthorizationEndpoint, "PKCE must use S256, but EnablePKCEPlainChallengeMethod is set")
	}

	if config.GetIssuer(ctx) == "" {
		v.fail(fapi2SectionAuthorizationEndpoint, "the 'iss' authorization response parameter must be returned, but Issuer is not set")
	}

	if !config.GetAuthorizationServerIdentificationEnabled(ctx) {
		v.fail(fapi2SectionAuthorizationEndpoint, "the 'iss' authorization response parameter must be returned, but DisableAuthorizationServerIdentification is set")
	}

	if p, ok := config.(oauth2.ResponseModeParameterHandlerProvider); !ok || !fapi2Registered[*oauth2.RFC9207ResponseModeParameterHandler](p.GetResponseModeParameterHandlers(ctx)) {
		v.fail(fapi2SectionAuthorizationEndpoint, "the 'iss' authorization response parameter must be returned, but the RFC 9207 response mode parameter handler is not registered")
	}
}

func (v *fapi2Violations) cryptography(ctx context.Context, config oauth2.Configurator) {
	if algs := config.GetClientAssertionSigningAlgValues(ctx); !fapi2Subset(algs, oauth2.FAPI2SecurityProfileSigningAlgValues) {
		v.fail(fapi2SectionCryptography, "the client assertion algorithms '%s' include one not permitted", strings.Join(algs, "', '"))
	}

	if algs := oauth2.SupportedEndpointAuthSigningAlgValues(ctx, config, oauth2.ClientAuthEndpointRevocation); !fapi2Subset(algs, oauth2.FAPI2SecurityProfileSigningAlgValues) {
		v.fail(fapi2SectionCryptography, "the revocation endpoint client assertion algorithms '%s' include one not permitted", strings.Join(algs, "', '"))
	}

	if algs := config.GetRequestObjectSigningAlgValues(ctx); !fapi2Subset(algs, oauth2.FAPI2SecurityProfileSigningAlgValues) {
		v.fail(fapi2SectionCryptography, "the request object algorithms '%s' include one not permitted", strings.Join(algs, "', '"))
	}

	if len(config.GetTokenIntrospectionHandlers(ctx)) != 0 {
		if algs := oauth2.SupportedEndpointAuthSigningAlgValues(ctx, config, oauth2.ClientAuthEndpointIntrospection); !fapi2Subset(algs, oauth2.FAPI2SecurityProfileSigningAlgValues) {
			v.fail(fapi2SectionCryptography, "the introspection endpoint client assertion algorithms '%s' include one not permitted", strings.Join(algs, "', '"))
		}
	}

	if !fapi2Registered[*rfc7523.Handler](config.GetTokenEndpointHandlers(ctx)) {
		return
	}

	if p, ok := config.(oauth2.GrantAssertionAlgorithmsProvider); !ok {
		v.fail(fapi2SectionCryptography, "the JWT bearer grant handler is registered, but the configuration has no JWT bearer grant assertion algorithms")
	} else if algs := p.GetRFC7523AssertionSigningAlgValues(ctx); !fapi2Subset(algs, oauth2.FAPI2SecurityProfileSigningAlgValues) {
		v.fail(fapi2SectionCryptography, "the JWT bearer grant assertion algorithms '%s' include one not permitted", strings.Join(algs, "', '"))
	}
}

func fapi2PermittedIntrospectionAuthMethods(methods []string) []string {
	clients := slices.DeleteFunc(slices.Clone(methods), oauth2.IsAccessTokenTypeAuthMethod)
	if len(clients) == 0 {
		return methods
	}

	tokens := slices.DeleteFunc(slices.Clone(methods), func(method string) bool { return !oauth2.IsAccessTokenTypeAuthMethod(method) })

	return append(fapi2Permitted(clients, oauth2.FAPI2SecurityProfileClientAuthMethods), tokens...)
}

func fapi2Permitted(values, permitted []string) []string {
	var kept []string

	for _, value := range values {
		if slices.Contains(permitted, value) {
			kept = append(kept, value)
		}
	}

	if len(kept) == 0 {
		return slices.Clone(permitted)
	}

	return kept
}

func fapi2Subset(values, permitted []string) bool {
	if len(values) == 0 {
		return false
	}

	for _, value := range values {
		if !slices.Contains(permitted, value) {
			return false
		}
	}

	return true
}

func fapi2Registered[T any, S ~[]E, E any](handlers S) bool {
	for _, h := range handlers {
		if _, ok := any(h).(T); ok {
			return true
		}
	}

	return false
}
