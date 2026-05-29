// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/token/jwt"
)

// RFC 8693 (OAuth 2.0 Token Exchange) factory functions.
//
// The factories MUST be registered in the order declared by RFC8693TokenExchangeFactories. The order is required
// because of two cross-handler dependencies that are not encoded in the type system:
//
//  1. TokenExchangeGrantHandler.PopulateTokenEndpointResponse writes the RFC 8693 §4.1 'act' claim onto the session
//     via session.SetClaimActor. The token-type handlers' PopulateTokenEndpointResponse implementations issue the
//     token by serializing the session into a JWT or persisting the session for opaque introspection. The grant
//     handler MUST therefore run BEFORE any token-type handler in the PopulateTokenEndpointResponse phase, or the
//     'act' claim is computed too late to reach the issued token.
//
//  2. ActorTokenValidationHandler.HandleTokenEndpointRequest enforces the RFC 8693 §4.4 'may_act' authorization
//     constraint. It reads session.GetActorToken(), which is populated by the token-type handlers' own
//     HandleTokenEndpointRequest implementations when actor_token / actor_token_type match their token type. The
//     validation handler MUST therefore run AFTER the token-type handlers in the HandleTokenEndpointRequest phase
//     or the may_act check fires before there is anything to validate.
//
// Putting the two together produces the canonical order:
//
//	1. RFC8693TokenExchangeGrantFactory       (grant + act-claim writer; FIRST)
//	2. RFC8693AccessTokenTypeFactory          (token-type handlers; any order among themselves —
//	3. RFC8693RefreshTokenTypeFactory          they're mutually exclusive at issuance because each handler's
//	4. RFC8693IDTokenTypeFactory               CanHandleTokenEndpointRequest filters by requested_token_type)
//	5. RFC8693CustomJWTTypeFactory
//	6. RFC8693ActorTokenValidationFactory     (may_act validator; LAST)
//
// Skipping any of the type-handler factories is supported (e.g. an AS that does not accept JWT subject tokens may
// omit RFC8693CustomJWTTypeFactory) as long as the relative order of the remaining factories is preserved.

// RFC8693TokenExchangeGrantFactory creates the request-validation + act-claim writer for the OAuth 2.0 Token
// Exchange grant. It MUST be registered FIRST in the RFC 8693 chain so the act claim is set before any token-type
// handler issues a token.
func RFC8693TokenExchangeGrantFactory(config oauth2.Configurator, _ any, _ any) any {
	return &rfc8693.TokenExchangeGrantHandler{
		Config:           config.(oauth2.RFC8693ConfigProvider),
		ScopeStrategy:    config.GetScopeStrategy(context.Background()),
		AudienceStrategy: config.GetAudienceStrategy(context.Background()),
		ResourceStrategy: config.GetResourceStrategy(context.Background()),
	}
}

// RFC8693AccessTokenTypeFactory creates the handler that exchanges to an opaque OAuth 2.0 access token. Pulls
// AccessToken/RefreshToken lifespans from the configurator at construction time.
func RFC8693AccessTokenTypeFactory(config oauth2.Configurator, storage any, strategy any) any {
	ctx := context.Background()

	return &rfc8693.AccessTokenTypeHandler{
		Config:               config.(oauth2.RFC8693ConfigProvider),
		AccessTokenLifespan:  config.GetAccessTokenLifespan(ctx),
		RefreshTokenLifespan: config.GetRefreshTokenLifespan(ctx),
		RefreshTokenScopes:   config.GetRefreshTokenScopes(ctx),
		ScopeStrategy:        config.GetScopeStrategy(ctx),
		CoreStrategy:         strategy.(hoauth2.CoreStrategy),
		Storage:              storage.(rfc8693.Storage),
	}
}

// RFC8693RefreshTokenTypeFactory creates the handler that exchanges to a refresh token. Refuses to issue when the
// client is not registered for the refresh_token grant type or when the granted scopes do not include any of the
// configured RefreshTokenScopes (see RFC8693RefreshTokenTypeFactory's gating logic in
// handler/rfc8693/refresh_token_type_handler.go).
func RFC8693RefreshTokenTypeFactory(config oauth2.Configurator, storage any, strategy any) any {
	ctx := context.Background()

	return &rfc8693.RefreshTokenTypeHandler{
		Config:               config.(oauth2.RFC8693ConfigProvider),
		RefreshTokenLifespan: config.GetRefreshTokenLifespan(ctx),
		RefreshTokenScopes:   config.GetRefreshTokenScopes(ctx),
		ScopeStrategy:        config.GetScopeStrategy(ctx),
		CoreStrategy:         strategy.(hoauth2.CoreStrategy),
		Storage:              storage.(rfc8693.Storage),
	}
}

// RFC8693IDTokenTypeFactory creates the handler that exchanges to an OpenID Connect ID token. The ValidationStrategy
// is the new openid.DefaultIDTokenValidationStrategy wired to the same jwt.Strategy used for issuance, so a
// token signed by this AS can be decoded and verified end-to-end.
func RFC8693IDTokenTypeFactory(config oauth2.Configurator, storage any, strategy any) any {
	jwtStrategy := strategy.(jwt.Strategy)

	return &rfc8693.IDTokenTypeHandler{
		Config:             config,
		Strategy:           jwtStrategy,
		IssueStrategy:      strategy.(openid.OpenIDConnectTokenStrategy),
		ValidationStrategy: &openid.DefaultIDTokenValidationStrategy{Strategy: jwtStrategy},
		Storage:            storage.(rfc8693.Storage),
	}
}

// RFC8693CustomJWTTypeFactory creates the handler that exchanges to a JWT of an implementer-registered type.
// Custom JWT types are configured on oauth2.Config.RFC8693TokenTypes as *rfc8693.JWTType entries.
func RFC8693CustomJWTTypeFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &rfc8693.CustomJWTTypeHandler{
		Config:   config.(oauth2.RFC8693ConfigProvider),
		Strategy: strategy.(jwt.Strategy),
		Storage:  storage.(rfc8693.Storage),
	}
}

// RFC8693ActorTokenValidationFactory creates the handler that enforces the RFC 8693 §4.4 'may_act' authorization
// constraint on delegation requests. It MUST be registered LAST in the RFC 8693 chain so the token-type handlers
// have populated session.ActorToken before this handler reads it.
func RFC8693ActorTokenValidationFactory(_ oauth2.Configurator, _ any, _ any) any {
	return &rfc8693.ActorTokenValidationHandler{}
}

// RFC8693TokenExchangeFactories returns the RFC 8693 Token Exchange factories in their required registration order.
// Pass them as the trailing variadic arguments to Compose:
//
//	provider := compose.Compose(
//	    config,
//	    storage,
//	    strategy,
//	    // ... other factories ...
//	    compose.RFC8693TokenExchangeFactories()...,
//	)
//
// See the package-level documentation on the rfc8693 factories above for the rationale behind the ordering
// constraint.
func RFC8693TokenExchangeFactories() []Factory {
	return []Factory{
		RFC8693TokenExchangeGrantFactory,
		RFC8693AccessTokenTypeFactory,
		RFC8693RefreshTokenTypeFactory,
		RFC8693IDTokenTypeFactory,
		RFC8693CustomJWTTypeFactory,
		RFC8693ActorTokenValidationFactory,
	}
}
