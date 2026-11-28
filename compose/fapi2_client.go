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
	"authelia.com/provider/oauth2/handler/rfc8705"
	"authelia.com/provider/oauth2/handler/rfc9449"
	"authelia.com/provider/oauth2/internal/consts"
)

// ValidateFAPI2SecurityProfileClientSupport returns an error joining every way the configuration and the handlers
// registered with it cannot hold a client implementing oauth2.FAPI2SecurityProfileClient to the FAPI 2.0 Security
// Profile, or nil when they can. Call it once the provider is composed when such clients are registered and the
// authorization server as a whole is not held to the profile, which ValidateFAPI2SecurityProfile checks instead.
//
// A FAPI 2.0 client relies on the configuration for what it cannot enforce at each request: an issuer for the 'iss'
// authorization response parameter and the client assertion audience, the RFC 9207 response mode parameter handler, the
// authorization code grant, pushed authorization request and PKCE handlers, a sender-constraining method with its
// handlers, a permitted client authentication method at the token endpoint, an issuer signing key of a permitted
// algorithm for each signing strategy which reports any, and a storage-backed introspection handler behind a stateless JWT one,
// which must recognize such a client. A custom ClientAuthenticationStrategy, DPoPStrategy, SecurityEventTokenStrategy
// or response mode handler is not checked, and must apply the rules of oauth2.FAPI2SecurityProfileClient itself. A JWT
// strategy reporting no signing algorithms is not checked, as ValidateFAPI2SecurityProfile does not check one either:
// an authorization server issuing only opaque tokens signs nothing. The strategies are those ValidateFAPI2SecurityProfile
// checks, including each of strategies such as the one passed to Compose, and each must hold a key of a permitted
// algorithm. Each JWT issued to such a client is still refused unless signed with a permitted algorithm.
//
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2
func ValidateFAPI2SecurityProfileClientSupport(ctx context.Context, config oauth2.Configurator, strategies ...any) (err error) {
	v := &fapi2Violations{}

	v.clientSupportAuthorization(ctx, config)
	v.clientSupportSenderConstrained(ctx, config)
	v.clientSupportCryptography(ctx, config, strategies)
	v.clientSupportResourceServer(ctx, config)

	return errors.Join(v.errs...)
}

// ValidateFAPI2SecurityProfileClient returns an error joining every way the registration of the client cannot meet the
// FAPI 2.0 Security Profile, or nil when it can. Call it for each statically configured client held to the profile,
// such as one implementing oauth2.FAPI2SecurityProfileClient or every client of an authorization server held to it, as
// a request of such a client would otherwise be refused at each request. The client must be confidential, register
// only the 'code' response type, and not require a PKCE 'code_challenge_method' other than S256.
//
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.1
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.2
func ValidateFAPI2SecurityProfileClient(client oauth2.Client) (err error) {
	v := &fapi2Violations{}

	if client.IsPublic() {
		v.fail(fapi2SectionGeneral, "the client '%s' must be confidential, but it is public", client.GetID())
	}

	for _, responseType := range client.GetResponseTypes() {
		if !oauth2.Arguments(oauth2.RemoveEmpty(strings.Split(responseType, " "))).ExactOne(consts.ResponseTypeAuthorizationCodeFlow) {
			v.fail(fapi2SectionAuthorizationEndpoint, "the client '%s' must register only the 'code' response type, but it registers '%s'", client.GetID(), responseType)
		}
	}

	if pkce, ok := client.(oauth2.ProofKeyCodeExchangeClient); ok && pkce.GetEnforcePKCEChallengeMethod() && pkce.GetPKCEChallengeMethod() != consts.PKCEChallengeMethodSHA256 {
		v.fail(fapi2SectionAuthorizationEndpoint, "the client '%s' requires the PKCE code challenge method '%s', but only 'S256' is permitted, so no authorization request of it can succeed", client.GetID(), pkce.GetPKCEChallengeMethod())
	}

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

	v.pkce(ctx, config, fapi2SectionAuthorizationEndpoint, "PKCE is required")

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

func (v *fapi2Violations) clientSupportResourceServer(ctx context.Context, config oauth2.Configurator) {
	stateless, stateful := fapi2Introspection(ctx, config)

	switch {
	case stateless == nil:
		return
	case stateless.Clients == nil:
		v.fail(fapi2SectionResourceServer, "the revocation status of access tokens must be verified, but the stateless JWT introspection handler has no Clients to recognize a FAPI 2.0 client by")
	case !stateful:
		v.fail(fapi2SectionResourceServer, "the revocation status of access tokens must be verified, but the stateless JWT introspection handler is registered without a storage-backed one")
	}
}

func (v *fapi2Violations) clientSupportCryptography(ctx context.Context, config oauth2.Configurator, strategies []any) {
	for _, signer := range fapi2Signers(ctx, config, strategies) {
		if algs := signer.algs(ctx); len(algs) != 0 && !slices.ContainsFunc(algs, func(alg string) bool {
			return slices.Contains(oauth2.FAPI2SecurityProfileSigningAlgValues, alg)
		}) {
			v.fail(fapi2SectionCryptography, "the %s signing algorithms '%s' include none permitted", signer.name, strings.Join(algs, "', '"))
		}
	}
}
