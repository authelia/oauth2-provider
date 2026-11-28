// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/ciba"
	"authelia.com/provider/oauth2/handler/idjag"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/handler/par"
	"authelia.com/provider/oauth2/handler/pkce"
	"authelia.com/provider/oauth2/handler/rfc7523"
	"authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/handler/rfc8705"
	"authelia.com/provider/oauth2/handler/rfc9449"
	"authelia.com/provider/oauth2/internal/slicesx"
)

const (
	fapi2SectionGeneral               = "5.3.2.1"
	fapi2SectionAuthorizationEndpoint = "5.3.2.2"
	fapi2SectionResourceServer        = "5.3.4"
	fapi2SectionCryptography          = "5.4.1"

	fapi2MaximumAuthorizeCodeLifespan = oauth2.FAPI2SecurityProfileMaximumAuthorizeCodeLifespan
	fapi2MaximumPushedAuthorizeLife   = 10 * time.Minute
	fapi2MinimumClockSkew             = oauth2.FAPI2SecurityProfileMinimumClockSkew
	fapi2MaximumClockSkew             = oauth2.FAPI2SecurityProfileMaximumClockSkew
	fapi2MaximumNonceLength           = 64
)

// ApplyFAPI2SecurityProfile sets the options of config which the FAPI 2.0 Security Profile requires of an authorization
// server: pushed authorization requests with a redirect URI, PKCE with S256, the RFC 9207 'iss' parameter, the issuer
// as the sole client assertion audience and a string, no refresh token rotation, sender-constrained access tokens which
// are refused when presented unbound or in the URI query, client authentication for the JWT bearer grant, an
// authorization code lifetime of at most 60 seconds, a clock skew allowance between 10 and 60 seconds, a 'nonce'
// minimum length of at most 64 characters, and only the permitted client authentication methods and JWS algorithms for
// the JWTs received. It also sets FAPI2SecurityProfile, so the discovery metadata lists only the permitted JWS
// algorithms. A value already within the profile is kept.
//
// It does not set Issuer, enable DPoP or mTLS, register handlers, or choose the keys which sign the JWTs the server
// issues, so ValidateFAPI2SecurityProfile must still be called once the provider is composed. An unset introspection endpoint list, which accepts every supported method, and
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
	config.RequireStringClientAssertionAudience = true
	config.DisableRefreshTokenRotation = true
	config.EnforceSenderConstrainedAccessTokens = true
	config.GrantTypeJWTBearerCanSkipClientAuth = false
	config.AccessTokenURIQueryParameterEnabled = false
	config.FAPI2SecurityProfile = true

	applyFAPI2SecurityProfileLimits(config)

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

	if len(config.CIBARequestSigningAlgValues) != 0 {
		config.CIBARequestSigningAlgValues = fapi2Permitted(config.CIBARequestSigningAlgValues, oauth2.FAPI2SecurityProfileSigningAlgValues)
	}

	if len(config.IDJAGRedeemSigningAlgValues) == 0 {
		config.IDJAGRedeemSigningAlgValues = slices.Clone(oauth2.FAPI2SecurityProfileSigningAlgValues)
	} else {
		config.IDJAGRedeemSigningAlgValues = fapi2Permitted(config.IDJAGRedeemSigningAlgValues, oauth2.FAPI2SecurityProfileSigningAlgValues)
	}

	if len(config.RFC7591TrustedIssuerSigningAlgValues) == 0 {
		config.RFC7591TrustedIssuerSigningAlgValues = slices.Clone(oauth2.FAPI2SecurityProfileSigningAlgValues)
	} else {
		config.RFC7591TrustedIssuerSigningAlgValues = fapi2Permitted(config.RFC7591TrustedIssuerSigningAlgValues, oauth2.FAPI2SecurityProfileSigningAlgValues)
	}

	if len(config.AuthorizationSignedResponseAlgValues) != 0 {
		config.AuthorizationSignedResponseAlgValues = fapi2Permitted(config.AuthorizationSignedResponseAlgValues, oauth2.FAPI2SecurityProfileSigningAlgValues)
	}

	if len(config.IntrospectionSignedResponseAlgValues) != 0 {
		config.IntrospectionSignedResponseAlgValues = fapi2Permitted(config.IntrospectionSignedResponseAlgValues, oauth2.FAPI2SecurityProfileSigningAlgValues)
	}

	if len(config.IntrospectionEndpointAuthSigningAlgValues) != 0 {
		config.IntrospectionEndpointAuthSigningAlgValues = fapi2Permitted(config.IntrospectionEndpointAuthSigningAlgValues, oauth2.FAPI2SecurityProfileSigningAlgValues)
	}
}

func applyFAPI2SecurityProfileLimits(config *oauth2.Config) {
	if config.AuthorizeCodeLifespan <= 0 || config.AuthorizeCodeLifespan > fapi2MaximumAuthorizeCodeLifespan {
		config.AuthorizeCodeLifespan = fapi2MaximumAuthorizeCodeLifespan
	}

	if config.PushedAuthorizeContextLifespan >= fapi2MaximumPushedAuthorizeLife {
		config.PushedAuthorizeContextLifespan = 0
	}

	if config.MinParameterEntropy > fapi2MaximumNonceLength {
		config.MinParameterEntropy = 0
	}

	if config.JWTClockSkew != 0 && (config.JWTClockSkew < fapi2MinimumClockSkew || config.JWTClockSkew > fapi2MaximumClockSkew) {
		config.JWTClockSkew = 0
	}

	if config.DPoPClockSkew != 0 && (config.DPoPClockSkew < fapi2MinimumClockSkew || config.DPoPClockSkew > fapi2MaximumClockSkew) {
		config.DPoPClockSkew = 0
	}
}

// ValidateFAPI2SecurityProfile returns an error joining every way the configuration and the handlers registered with it
// fail the authorization server requirements of the FAPI 2.0 Security Profile which the configuration determines, or
// nil when it meets them. Call it once the provider is composed. Of the authorize endpoint handlers it recognizes only
// those of this library serving the implicit, hybrid and 'none' response types, not a custom handler serving another
// response type. The signing algorithms of the JWTs the server issues are checked for the JWT strategy, the JARM,
// introspection response and Logout Token strategies of the configuration, and each of strategies, such as the strategy
// passed to Compose, which is not visible through the configuration. Each must report only permitted algorithms
// through a SigningAlgValues method, and one reporting none, such as a custom strategy without the method, is not
// checked. A CommonStrategy is checked through each strategy it is composed of. It does not check the clients, which must be
// confidential, register the 'code' response type, and register only PS256, ES256 or EdDSA for the JWTs issued to them.
// The signing algorithm of an Identity Assertion JWT Authorization Grant relationship is held by the storage and not
// checked, though under FAPI2SecurityProfile a grant is never signed with one the profile does not permit.
//
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2
func ValidateFAPI2SecurityProfile(ctx context.Context, config oauth2.Configurator, strategies ...any) (err error) {
	v := &fapi2Violations{}

	v.general(ctx, config)
	v.senderConstrained(ctx, config)
	v.authorizationEndpoint(ctx, config)
	v.nonce(ctx, config)
	v.resourceServer(ctx, config)
	v.cryptography(ctx, config)
	v.responseSigning(ctx, config)
	v.extensionSigning(ctx, config)
	v.grantSigning(ctx, config)

	for _, signer := range fapi2Signers(ctx, config, strategies) {
		if algs := signer.algs(ctx); len(algs) != 0 && !fapi2Subset(algs, oauth2.FAPI2SecurityProfileSigningAlgValues) {
			v.fail(fapi2SectionCryptography, "the %s signing algorithms '%s' include one not permitted", signer.name, strings.Join(algs, "', '"))
		}
	}

	return errors.Join(v.errs...)
}

type fapi2Signer struct {
	name     string
	strategy any
}

// algs returns the signing algorithms the strategy reports, or nil when it reports none, including when it is a nil
// pointer or wraps a nil jwt.Strategy.
func (s fapi2Signer) algs(ctx context.Context) (algs []string) {
	strategy, ok := s.strategy.(interface {
		SigningAlgValues(ctx context.Context) []string
	})
	if !ok {
		return nil
	}

	if value := reflect.ValueOf(strategy); value.Kind() == reflect.Pointer && value.IsNil() {
		return nil
	}

	defer func() {
		if recover() != nil {
			algs = nil
		}
	}()

	return strategy.SigningAlgValues(ctx)
}

// fapi2Signers returns the strategies the authorization server signs JWTs with which are visible to a check: those of
// the configuration and the given strategies, with a CommonStrategy, or a pointer to one, replaced by those it is
// composed of.
func fapi2Signers(ctx context.Context, config oauth2.Configurator, strategies []any) (signers []fapi2Signer) {
	signers = append(signers, fapi2Signer{name: "issuer", strategy: config.GetJWTStrategy(ctx)})

	if p, ok := config.(oauth2.JWTSecuredAuthorizeResponseModeStrategyProvider); ok {
		signers = append(signers, fapi2Signer{name: "JARM", strategy: p.GetJWTSecuredAuthorizeResponseModeStrategy(ctx)})
	}

	if p, ok := config.(oauth2.IntrospectionJWTResponseStrategyProvider); ok {
		signers = append(signers, fapi2Signer{name: "introspection response", strategy: p.GetIntrospectionJWTResponseStrategy(ctx)})
	}

	if p, ok := config.(oauth2.BackChannelLogoutTokenStrategyProvider); ok {
		signers = append(signers, fapi2Signer{name: "Logout Token", strategy: p.GetBackChannelLogoutTokenStrategy(ctx)})
	}

	for i, strategy := range strategies {
		name := fmt.Sprintf("strategy %d", i+1)

		var common *CommonStrategy

		switch value := strategy.(type) {
		case *CommonStrategy:
			common = value
		case CommonStrategy:
			common = &value
		}

		if common != nil {
			signers = append(signers,
				fapi2Signer{name: name + " core", strategy: common.CoreStrategy},
				fapi2Signer{name: name + " OpenID Connect", strategy: common.OpenIDConnectTokenStrategy},
				fapi2Signer{name: name + " JWT", strategy: common.Strategy},
			)

			continue
		}

		signers = append(signers, fapi2Signer{name: name, strategy: strategy})
	}

	return signers
}

type fapi2Violations struct {
	document string
	errs     []error
}

func (v *fapi2Violations) fail(section, format string, args ...any) {
	document := v.document
	if document == "" {
		document = "FAPI 2.0 Security Profile"
	}

	v.errs = append(v.errs, fmt.Errorf("%s Section %s: %s", document, section, fmt.Sprintf(format, args...)))
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

	v.clientAssertionAudience(ctx, config)
	v.jwtBearerClientAuthentication(ctx, config)

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

func (v *fapi2Violations) clientAssertionAudience(ctx context.Context, config oauth2.Configurator) {
	if p, ok := config.(oauth2.AllowedJWTAssertionAudiencesProvider); !ok || p.GetDisableClientAssertionIssuerAudience(ctx) {
		v.fail(fapi2SectionGeneral, "the issuer must be the sole client assertion audience, but DisableClientAssertionIssuerAudience is set")
	}

	if p, ok := config.(oauth2.RequireStringClientAssertionAudienceProvider); !ok || !p.GetRequireStringClientAssertionAudience(ctx) {
		v.fail(fapi2SectionGeneral, "the issuer must be the client assertion audience as a string, but RequireStringClientAssertionAudience is not set")
	}
}

func (v *fapi2Violations) jwtBearerClientAuthentication(ctx context.Context, config oauth2.Configurator) {
	if !fapi2Registered[*rfc7523.Handler](config.GetTokenEndpointHandlers(ctx)) {
		return
	}

	if p, ok := config.(oauth2.GrantTypeJWTBearerCanSkipClientAuthProvider); ok && p.GetGrantTypeJWTBearerCanSkipClientAuth(ctx) {
		v.fail(fapi2SectionGeneral, "clients must authenticate, but GrantTypeJWTBearerCanSkipClientAuth is set")
	}
}

func (v *fapi2Violations) resourceServer(ctx context.Context, config oauth2.Configurator) {
	if p, ok := config.(oauth2.AccessTokenURIQueryParameterEnabledProvider); ok && p.GetAccessTokenURIQueryParameterEnabled(ctx) {
		v.fail(fapi2SectionResourceServer, "access tokens in the URI query must not be accepted, but AccessTokenURIQueryParameterEnabled is set")
	}

	if stateless, stateful := fapi2Introspection(ctx, config); stateless != nil && !stateful {
		v.fail(fapi2SectionResourceServer, "the revocation status of access tokens must be verified, but the stateless JWT introspection handler is registered without a storage-backed one")
	}
}

func fapi2Introspection(ctx context.Context, config oauth2.Configurator) (stateless *hoauth2.StatelessJWTValidator, stateful bool) {
	for _, h := range config.GetTokenIntrospectionHandlers(ctx) {
		switch handler := h.(type) {
		case *hoauth2.StatelessJWTValidator:
			stateless = handler
		case *hoauth2.CoreValidator:
			stateful = true
		}
	}

	return stateless, stateful
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

func (v *fapi2Violations) nonce(ctx context.Context, config oauth2.Configurator) {
	if p, ok := config.(oauth2.MinParameterEntropyProvider); ok && p.GetMinParameterEntropy(ctx) > fapi2MaximumNonceLength {
		v.fail(fapi2SectionAuthorizationEndpoint, "'nonce' values of up to %d characters must be accepted, but MinParameterEntropy is %d", fapi2MaximumNonceLength, p.GetMinParameterEntropy(ctx))
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

	v.pkce(ctx, config, fapi2SectionAuthorizationEndpoint, "PKCE is required")

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
	if !oauth2.IsFAPI2SecurityProfile(ctx, config) {
		v.fail(fapi2SectionCryptography, "the discovery metadata must list only the permitted algorithms, but FAPI2SecurityProfile is not set")
	}

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

func (v *fapi2Violations) responseSigning(ctx context.Context, config oauth2.Configurator) {
	p, ok := config.(oauth2.SignedResponseAlgValuesProvider)
	if !ok {
		return
	}

	if algs := p.GetAuthorizationSignedResponseAlgValues(ctx); len(algs) != 0 && !fapi2Subset(algs, oauth2.FAPI2SecurityProfileSigningAlgValues) {
		v.fail(fapi2SectionCryptography, "the authorization response algorithms '%s' include one not permitted", strings.Join(algs, "', '"))
	}

	if algs := p.GetIntrospectionSignedResponseAlgValues(ctx); len(algs) != 0 && !fapi2Subset(algs, oauth2.FAPI2SecurityProfileSigningAlgValues) {
		v.fail(fapi2SectionCryptography, "the introspection response algorithms '%s' include one not permitted", strings.Join(algs, "', '"))
	}
}

func (v *fapi2Violations) extensionSigning(ctx context.Context, config oauth2.Configurator) {
	if p, ok := config.(oauth2.RFC7591ClientRegistrationPolicyProvider); ok && len(p.GetRFC7591ClientRegistrationTrustedIssuers(ctx)) != 0 {
		if algs := config.GetRFC7591TrustedIssuerSigningAlgValues(ctx); !fapi2Subset(algs, oauth2.FAPI2SecurityProfileSigningAlgValues) {
			v.fail(fapi2SectionCryptography, "the software statement and trusted issuer algorithms '%s' include one not permitted", strings.Join(algs, "', '"))
		}
	}

	for _, name := range slices.Sorted(maps.Keys(config.GetRFC8693TokenTypes(ctx))) {
		t, ok := config.GetRFC8693TokenTypes(ctx)[name].(*rfc8693.TxnTokenType)
		if !ok {
			continue
		}

		for _, domain := range slices.Sorted(maps.Keys(t.Domains)) {
			if t.Domains[domain] == nil {
				continue
			}

			if alg := fapi2SigningAlg(t.Domains[domain].SigningAlg); !slices.Contains(oauth2.FAPI2SecurityProfileSigningAlgValues, alg) {
				v.fail(fapi2SectionCryptography, "the transaction token type '%s' signs the tokens of the trust domain '%s' with '%s', which is not permitted", name, domain, alg)
			}
		}
	}

	p, ok := config.(oauth2.SSFConfigProvider)
	if !ok {
		return
	}

	ssf := p.GetSSFConfig(ctx)
	if ssf == nil {
		return
	}

	if ssf.EnforceCAEPInteroperabilityProfile {
		v.fail(fapi2SectionCryptography, "security event tokens must use a permitted algorithm, but EnforceCAEPInteroperabilityProfile requires RS256")
	}

	if s, ok := ssf.TokenStrategy.(*oauth2.DefaultSecurityEventTokenStrategy); ok {
		if alg := fapi2SigningAlg(s.SigningAlg); !slices.Contains(oauth2.FAPI2SecurityProfileSigningAlgValues, alg) {
			v.fail(fapi2SectionCryptography, "security event tokens are signed with '%s', which is not permitted", alg)
		}
	}
}

func (v *fapi2Violations) grantSigning(ctx context.Context, config oauth2.Configurator) {
	if fapi2Registered[*ciba.EndpointHandler](config.GetBackChannelAuthenticationEndpointHandlers(ctx)) {
		if algs := config.GetCIBARequestSigningAlgValues(ctx); !fapi2Subset(algs, oauth2.FAPI2SecurityProfileSigningAlgValues) {
			v.fail(fapi2SectionCryptography, "the CIBA signed authentication request algorithms '%s' include one not permitted", strings.Join(algs, "', '"))
		}
	}

	if p, ok := config.(oauth2.GrantAssertionAlgorithmsProvider); ok && fapi2Registered[*idjag.RedeemHandler](config.GetTokenEndpointHandlers(ctx)) {
		if algs := p.GetIDJAGRedeemSigningAlgValues(ctx); !fapi2Subset(algs, oauth2.FAPI2SecurityProfileSigningAlgValues) {
			v.fail(fapi2SectionCryptography, "the Identity Assertion JWT Authorization Grant redemption algorithms '%s' include one not permitted", strings.Join(algs, "', '"))
		}
	}

	for _, name := range slices.Sorted(maps.Keys(config.GetRFC8693TokenTypes(ctx))) {
		t, ok := config.GetRFC8693TokenTypes(ctx)[name].(*rfc8693.JWTType)
		if !ok || t.Issue == nil || !t.Issue.AuthorizationGrant {
			continue
		}

		if alg := fapi2SigningAlg(t.Issue.SigningAlg); !slices.Contains(oauth2.FAPI2SecurityProfileSigningAlgValues, alg) {
			v.fail(fapi2SectionCryptography, "the JWT authorization grant type '%s' is signed with '%s', which is not permitted", name, alg)
		}
	}
}

// See: https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1
func (v *fapi2Violations) pkce(ctx context.Context, config oauth2.Configurator, section, requirement string) {
	switch {
	case !fapi2Registered[*pkce.Handler](config.GetAuthorizeEndpointHandlers(ctx)):
		v.fail(section, "%s, but the PKCE handler is not registered", requirement)
	case !fapi2Registered[*pkce.Handler](config.GetTokenEndpointHandlers(ctx)):
		v.fail(section, "%s, but the PKCE handler is not registered with the token endpoint handlers, so no 'code_verifier' is verified", requirement)
	}
}

func fapi2SigningAlg(alg string) string {
	if alg == "" {
		return string(jose.RS256)
	}

	return alg
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
	return len(values) != 0 && slicesx.Subset(permitted, values)
}

func fapi2Registered[T any, S ~[]E, E any](handlers S) bool {
	for _, h := range handlers {
		if _, ok := any(h).(T); ok {
			return true
		}
	}

	return false
}
