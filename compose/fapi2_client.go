// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"
	"errors"
	"slices"
	"strings"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/par"
	"authelia.com/provider/oauth2/handler/pkce"
	"authelia.com/provider/oauth2/handler/rfc8705"
	"authelia.com/provider/oauth2/handler/rfc9449"
)

// ValidateFAPI2SecurityProfileClientSupport returns an error joining every way the configuration and the handlers
// registered with it cannot hold a client implementing oauth2.FAPI2SecurityProfileClient to the FAPI 2.0 Security
// Profile, or nil when they can. Call it once the provider is composed when such clients are registered and the
// authorization server as a whole is not held to the profile, which ValidateFAPI2SecurityProfile checks instead.
//
// A FAPI 2.0 client relies on the configuration for what it cannot enforce at each request: an issuer for the 'iss'
// authorization response parameter and the client assertion audience, the RFC 9207 response mode parameter handler, the
// authorization code grant, pushed authorization request and PKCE handlers, a sender-constraining method with its
// handlers, a permitted client authentication method at the token endpoint, and an issuer signing key of a permitted
// algorithm when the JWT strategy reports any. A custom ClientAuthenticationStrategy, DPoPStrategy,
// SecurityEventTokenStrategy or response mode handler is not checked, and must apply the rules of
// oauth2.FAPI2SecurityProfileClient itself. A JWT strategy reporting no signing algorithms is not checked, as
// ValidateFAPI2SecurityProfile does not check one either: an authorization server issuing only opaque tokens signs
// nothing, and the signer passed to Compose is not visible here. Each JWT issued to such a client is still refused
// unless signed with a permitted algorithm.
//
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2
func ValidateFAPI2SecurityProfileClientSupport(ctx context.Context, config oauth2.Configurator) (err error) {
	v := &fapi2Violations{}

	v.clientSupportAuthorization(ctx, config)
	v.clientSupportSenderConstrained(ctx, config)
	v.clientSupportCryptography(ctx, config)

	return errors.Join(v.errs...)
}

func (v *fapi2Violations) clientSupportAuthorization(ctx context.Context, config oauth2.Configurator) {
	if config.GetIssuer(ctx) == "" {
		v.fail(fapi2SectionAuthorizationEndpoint, "the 'iss' authorization response parameter must be returned, but Issuer is not set")
	}

	if p, ok := config.(oauth2.ResponseModeParameterHandlerProvider); !ok || !fapi2Registered[*oauth2.RFC9207ResponseModeParameterHandler](p.GetResponseModeParameterHandlers(ctx)) {
		v.fail(fapi2SectionAuthorizationEndpoint, "the 'iss' authorization response parameter must be returned, but the RFC 9207 response mode parameter handler is not registered")
	}

	if !fapi2Registered[*par.PushedAuthorizeHandler](config.GetPushedAuthorizeEndpointHandlers(ctx)) {
		v.fail(fapi2SectionAuthorizationEndpoint, "authorization requests must be pushed, but the pushed authorization request handler is not registered")
	}

	if !fapi2Registered[*hoauth2.AuthorizeExplicitGrantHandler](config.GetAuthorizeEndpointHandlers(ctx)) {
		v.fail(fapi2SectionAuthorizationEndpoint, "the response type must be 'code', but the authorization code grant handler is not registered")
	}

	if !fapi2Registered[*pkce.Handler](config.GetAuthorizeEndpointHandlers(ctx)) {
		v.fail(fapi2SectionAuthorizationEndpoint, "PKCE is required, but the PKCE handler is not registered")
	}

	if methods := oauth2.SupportedEndpointAuthMethods(ctx, config, oauth2.ClientAuthEndpointToken); !slices.ContainsFunc(methods, func(method string) bool {
		return slices.Contains(oauth2.FAPI2SecurityProfileClientAuthMethods, method)
	}) {
		v.fail(fapi2SectionGeneral, "the token endpoint accepts the client authentication methods '%s', none of which is permitted", strings.Join(methods, "', '"))
	}
}

func (v *fapi2Violations) clientSupportSenderConstrained(ctx context.Context, config oauth2.Configurator) {
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
}

func (v *fapi2Violations) clientSupportCryptography(ctx context.Context, config oauth2.Configurator) {
	strategy, ok := config.GetJWTStrategy(ctx).(interface {
		SigningAlgValues(ctx context.Context) []string
	})
	if !ok {
		return
	}

	if algs := strategy.SigningAlgValues(ctx); len(algs) != 0 && !slices.ContainsFunc(algs, func(alg string) bool {
		return slices.Contains(oauth2.FAPI2SecurityProfileSigningAlgValues, alg)
	}) {
		v.fail(fapi2SectionCryptography, "the issuer signing algorithms '%s' include none permitted", strings.Join(algs, "', '"))
	}
}
