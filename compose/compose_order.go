// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"errors"
	"fmt"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/oidckb"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/handler/pkce"
	"authelia.com/provider/oauth2/handler/rfc8628"
	"authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/handler/rfc9449"
)

// ErrHandlerOrder is wrapped by every error ValidateHandlerOrder returns.
var ErrHandlerOrder = errors.New("oauth2: handlers are registered in an order which does not work")

// ValidateHandlerOrder returns an error for every handler in config which is registered in an order it does not work
// in, each wrapping ErrHandlerOrder, or nil when there is none. Compose calls it and panics on an error, so a
// configuration built with Compose and the factories in this package is always checked. A configuration which sets
// the handler lists on oauth2.Config itself, or composes the factories in its own order, should call it once the
// handlers are registered.
//
// The rules are:
//
//   - Every openid.OpenIDConnectExplicitHandler must follow the hoauth2.AuthorizeExplicitGrantHandler, and every
//     pkce.Handler must follow the hoauth2.AuthorizeExplicitGrantHandler and the openid.OpenIDConnectHybridHandler, in
//     the authorize endpoint handlers. Each records a session keyed by the authorization code the handler it follows
//     issues, so registered first it finds no code and fails the request.
//   - Every pkce.Handler must follow the hoauth2.AuthorizeExplicitGrantHandler in the token endpoint handlers. The
//     PKCE request session is removed once the token request succeeds, so the authorization code must already be
//     invalidated; otherwise a request failing in between leaves the code redeemable without its PKCE binding.
//   - Every openid.OpenIDConnectExplicitHandler must follow the hoauth2.AuthorizeExplicitGrantHandler, every
//     openid.OpenIDConnectRefreshHandler must follow the hoauth2.RefreshTokenGrantHandler, and every
//     openid.OpenIDConnectDeviceAuthorizeHandler must follow the rfc8628.DeviceAuthorizeTokenEndpointHandler in the
//     token endpoint handlers. Each computes the ID Token 'at_hash' claim from the access token the OAuth 2.0 grant
//     handler adds to the response, so registered first it hashes an empty access token.
//   - Every oidckb.Handler must follow the rfc9449.Handler in the token endpoint binding handlers, as it consumes the
//     DPoP proof rfc9449.Handler publishes.
//   - Every oidckb.UserAuthorizeHandler must precede the rfc8628.UserAuthorizeHandler in the RFC 8628 user authorize
//     endpoint handlers, as it records the granted key binding onto the session rfc8628.UserAuthorizeHandler persists.
//   - When any RFC 8693 handler is registered in the token endpoint handlers, an rfc8693.TokenExchangeGrantHandler
//     must precede every RFC 8693 token type handler and an rfc8693.ActorTokenValidationHandler must follow every
//     one, the order RFC8693TokenExchangeFactories declares. The grant handler validates the request and writes the
//     RFC 8693 Section 4.1 'act' claim the token type handlers issue, and the validation handler enforces the RFC
//     8693 Section 4.4 'may_act' claim on the tokens they validate.
//
// Except for the RFC 8693 rule, a rule only applies when both handlers are registered.
func ValidateHandlerOrder(config *oauth2.Config) (err error) {
	return errors.Join(
		validateAuthorizeEndpointHandlerOrder(config),
		validateTokenEndpointHandlerOrder(config),
		validateRFC8693HandlerOrder(config),
		validateTokenEndpointBindingHandlerOrder(config),
		validateRFC8628UserAuthorizeHandlerOrder(config),
	)
}

func validateAuthorizeEndpointHandlerOrder(config *oauth2.Config) (err error) {
	handlers := config.AuthorizeEndpointHandlers

	if handlerPrecedes[*openid.OpenIDConnectExplicitHandler, *hoauth2.AuthorizeExplicitGrantHandler](handlers) {
		err = errors.Join(err, fmt.Errorf("%w: the openid.OpenIDConnectExplicitHandler (OpenIDConnectExplicitFactory) must be registered after the hoauth2.AuthorizeExplicitGrantHandler (OAuth2AuthorizeExplicitFactory) in the authorize endpoint handlers, as it records the OpenID Connect session under the authorization code the hoauth2.AuthorizeExplicitGrantHandler issues", ErrHandlerOrder))
	}

	if handlerPrecedes[*pkce.Handler, *hoauth2.AuthorizeExplicitGrantHandler](handlers) {
		err = errors.Join(err, fmt.Errorf("%w: the pkce.Handler (OAuth2PKCEFactory) must be registered after the hoauth2.AuthorizeExplicitGrantHandler (OAuth2AuthorizeExplicitFactory) in the authorize endpoint handlers, as it records the PKCE request session under the authorization code the hoauth2.AuthorizeExplicitGrantHandler issues", ErrHandlerOrder))
	}

	if handlerPrecedes[*pkce.Handler, *openid.OpenIDConnectHybridHandler](handlers) {
		err = errors.Join(err, fmt.Errorf("%w: the pkce.Handler (OAuth2PKCEFactory) must be registered after the openid.OpenIDConnectHybridHandler (OpenIDConnectHybridFactory) in the authorize endpoint handlers, as it records the PKCE request session under the authorization code the openid.OpenIDConnectHybridHandler issues", ErrHandlerOrder))
	}

	return err
}

func validateTokenEndpointHandlerOrder(config *oauth2.Config) (err error) {
	handlers := config.TokenEndpointHandlers

	if handlerPrecedes[*pkce.Handler, *hoauth2.AuthorizeExplicitGrantHandler](handlers) {
		err = errors.Join(err, fmt.Errorf("%w: the pkce.Handler (OAuth2PKCEFactory) must be registered after the hoauth2.AuthorizeExplicitGrantHandler (OAuth2AuthorizeExplicitFactory), as it removes the PKCE request session which must outlive the authorization code", ErrHandlerOrder))
	}

	if handlerPrecedes[*openid.OpenIDConnectExplicitHandler, *hoauth2.AuthorizeExplicitGrantHandler](handlers) {
		err = errors.Join(err, fmt.Errorf("%w: the openid.OpenIDConnectExplicitHandler (OpenIDConnectExplicitFactory) must be registered after the hoauth2.AuthorizeExplicitGrantHandler (OAuth2AuthorizeExplicitFactory), as it computes the ID Token 'at_hash' claim from the access token the hoauth2.AuthorizeExplicitGrantHandler issues", ErrHandlerOrder))
	}

	if handlerPrecedes[*openid.OpenIDConnectRefreshHandler, *hoauth2.RefreshTokenGrantHandler](handlers) {
		err = errors.Join(err, fmt.Errorf("%w: the openid.OpenIDConnectRefreshHandler (OpenIDConnectRefreshFactory) must be registered after the hoauth2.RefreshTokenGrantHandler (OAuth2RefreshTokenGrantFactory), as it computes the ID Token 'at_hash' claim from the access token the hoauth2.RefreshTokenGrantHandler issues", ErrHandlerOrder))
	}

	if handlerPrecedes[*openid.OpenIDConnectDeviceAuthorizeHandler, *rfc8628.DeviceAuthorizeTokenEndpointHandler](handlers) {
		err = errors.Join(err, fmt.Errorf("%w: the openid.OpenIDConnectDeviceAuthorizeHandler (OpenIDConnectDeviceAuthorizeFactory) must be registered after the rfc8628.DeviceAuthorizeTokenEndpointHandler (RFC8628DeviceAuthorizeTokenFactory), as it computes the ID Token 'at_hash' claim from the access token the rfc8628.DeviceAuthorizeTokenEndpointHandler issues", ErrHandlerOrder))
	}

	return err
}

func handlerPrecedes[Dependent, Dependency, Handler any](handlers []Handler) bool {
	var dependency, unordered bool

	for _, handler := range handlers {
		if _, ok := any(handler).(Dependency); ok {
			dependency = true
		} else if _, ok = any(handler).(Dependent); ok && !dependency {
			unordered = true
		}
	}

	return unordered && dependency
}

func validateRFC8693HandlerOrder(config *oauth2.Config) (err error) {
	var grant, typed, validator, grantUnordered, validatorUnordered bool

	for _, handler := range config.TokenEndpointHandlers {
		switch handler.(type) {
		case *rfc8693.TokenExchangeGrantHandler:
			grant = true

			if typed {
				grantUnordered = true
			}
		case *rfc8693.AccessTokenTypeHandler, *rfc8693.RefreshTokenTypeHandler, *rfc8693.IDTokenTypeHandler, *rfc8693.CustomJWTTypeHandler:
			typed = true

			if validator {
				validatorUnordered = true
			}
		case *rfc8693.ActorTokenValidationHandler:
			validator = true
		}
	}

	if !grant && !typed && !validator {
		return nil
	}

	switch {
	case !grant:
		err = errors.Join(err, fmt.Errorf("%w: the rfc8693.TokenExchangeGrantHandler (RFC8693TokenExchangeGrantFactory) must be registered with the other RFC 8693 handlers, as it validates the token exchange request and writes the 'act' claim", ErrHandlerOrder))
	case grantUnordered:
		err = errors.Join(err, fmt.Errorf("%w: the rfc8693.TokenExchangeGrantHandler (RFC8693TokenExchangeGrantFactory) must be registered before every RFC 8693 token type handler, as it writes the 'act' claim onto the session they issue the token from", ErrHandlerOrder))
	}

	switch {
	case !validator:
		err = errors.Join(err, fmt.Errorf("%w: the rfc8693.ActorTokenValidationHandler (RFC8693ActorTokenValidationFactory) must be registered with the other RFC 8693 handlers, as it requires a validated subject token and enforces the 'may_act' claim", ErrHandlerOrder))
	case validatorUnordered:
		err = errors.Join(err, fmt.Errorf("%w: the rfc8693.ActorTokenValidationHandler (RFC8693ActorTokenValidationFactory) must be registered after every RFC 8693 token type handler, as it enforces the 'may_act' claim on the tokens they validate", ErrHandlerOrder))
	}

	return err
}

// validateTokenEndpointBindingHandlerOrder returns an error when both key binding token endpoint binding handlers are
// registered and oidckb.Handler precedes rfc9449.Handler.
//
// oidckb.Handler performs no proof validation of its own; it consumes the proof rfc9449.Handler publishes once every
// RFC 9449 Section 5 check has passed. Registered first it would find nothing published, so a grant that asked to be
// key bound would fail with a server error on every token request.
//
// rfc9449.Handler alone is a legitimate configuration. oidckb.Handler alone is legitimate only when some other
// handler publishes a validated proof via oauth2.PublishDPoPProof; with no publisher registered at all, every grant
// whose authentication request carried 'dpop_jkt' fails with a server error at the token endpoint.
func validateTokenEndpointBindingHandlerOrder(config *oauth2.Config) (err error) {
	var dpop, unordered bool

	// Every oidckb.Handler must be preceded by an rfc9449.Handler, so the list is walked in order rather than
	// reduced to one index per type: a list carrying more than one of either would report only the last of each,
	// and a misordered earlier pair would go unseen. Config.TokenEndpointBindingHandlers is exported and can be
	// assigned directly, so the Append deduplication cannot be relied on here.
	for _, handler := range config.TokenEndpointBindingHandlers {
		switch handler.(type) {
		case *rfc9449.Handler:
			dpop = true
		case *oidckb.Handler:
			if !dpop {
				unordered = true
			}
		}
	}

	// An oidckb.Handler with no rfc9449.Handler registered at all is the custom publisher configuration described
	// above, not an ordering fault.
	if !unordered || !dpop {
		return nil
	}

	return fmt.Errorf("%w: the rfc9449.Handler (DPoPTokenFactory) must be registered before the oidckb.Handler (OpenIDConnectKeyBindingFactory), as it consumes the DPoP proof the rfc9449.Handler publishes", ErrHandlerOrder)
}

// validateRFC8628UserAuthorizeHandlerOrder returns an error when oidckb.UserAuthorizeHandler is registered after
// rfc8628.UserAuthorizeHandler.
//
// Both populate the user authorization response in registration order. rfc8628.UserAuthorizeHandler persists the
// device code session, and oidckb.UserAuthorizeHandler records onto that session that the 'bound_key' scope was
// granted; consent decides that here, so it cannot be recorded any earlier. Registered second it would mutate a
// session already written, and every store that serializes on write would drop the marker, leaving the device flow to
// issue an ID Token with no 'cnf' claim and no error anywhere to say why.
func validateRFC8628UserAuthorizeHandlerOrder(config *oauth2.Config) (err error) {
	var device, unordered bool

	// Walked in order for the reason validateTokenEndpointBindingHandlerOrder is: no oidckb.UserAuthorizeHandler may
	// follow an rfc8628.UserAuthorizeHandler, which one index per type cannot express for a list carrying more
	// than one of either.
	for _, handler := range config.RFC8628UserAuthorizeEndpointHandlers {
		switch handler.(type) {
		case *rfc8628.UserAuthorizeHandler:
			device = true
		case *oidckb.UserAuthorizeHandler:
			if device {
				unordered = true
			}
		}
	}

	if !unordered {
		return nil
	}

	return fmt.Errorf("%w: the oidckb.UserAuthorizeHandler (OpenIDConnectKeyBindingUserAuthorizeFactory) must be registered before the rfc8628.UserAuthorizeHandler (RFC8628UserAuthorizeFactory), as it records the granted key binding onto the device code session the rfc8628.UserAuthorizeHandler persists", ErrHandlerOrder)
}
