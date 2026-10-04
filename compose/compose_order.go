// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"errors"
	"fmt"
	"slices"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/idjag"
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
//   - Every oidckb.Handler and every idjag.RedeemHandler must follow the rfc9449.Handler in the token endpoint binding
//     handlers, as each consumes the DPoP proof rfc9449.Handler publishes.
//   - Every idjag.RedeemHandler registered in the token endpoint handlers must also be registered in the token
//     endpoint binding handlers, as it enforces the grant's 'cnf' claim there.
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
		validateIDJAGRedeemHandlerBinding(config),
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
		case *rfc8693.AccessTokenTypeHandler, *rfc8693.RefreshTokenTypeHandler, *rfc8693.IDTokenTypeHandler, *rfc8693.CustomJWTTypeHandler, *idjag.IssueHandler:
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

// validateTokenEndpointBindingHandlerOrder returns an error when an oidckb.Handler or idjag.RedeemHandler precedes the
// rfc9449.Handler in the token endpoint binding handlers, as each consumes the validated proof it publishes.
//
// Either consumer without any rfc9449.Handler is not an error: another handler may publish the proof via
// oauth2.PublishDPoPProof.
func validateTokenEndpointBindingHandlerOrder(config *oauth2.Config) (err error) {
	var dpop, keyBindingUnordered, idjagUnordered bool

	// Walked in order as Config.TokenEndpointBindingHandlers is exported and may hold more than one handler of each
	// type.
	for _, handler := range config.TokenEndpointBindingHandlers {
		switch handler.(type) {
		case *rfc9449.Handler:
			dpop = true
		case *oidckb.Handler:
			if !dpop {
				keyBindingUnordered = true
			}
		case *idjag.RedeemHandler:
			if !dpop {
				idjagUnordered = true
			}
		}
	}

	// A consumer with no rfc9449.Handler registered at all is the custom publisher configuration described above, not
	// an ordering fault.
	if !dpop {
		return nil
	}

	if keyBindingUnordered {
		err = errors.Join(err, fmt.Errorf("%w: the rfc9449.Handler (DPoPTokenFactory) must be registered before the oidckb.Handler (OpenIDConnectKeyBindingFactory), as it consumes the DPoP proof the rfc9449.Handler publishes", ErrHandlerOrder))
	}

	if idjagUnordered {
		err = errors.Join(err, fmt.Errorf("%w: the rfc9449.Handler (DPoPTokenFactory) must be registered before the idjag.RedeemHandler (IDJAGRedeemFactory), as it enforces the ID-JAG 'cnf' claim against the DPoP proof the rfc9449.Handler publishes", ErrHandlerOrder))
	}

	return err
}

func validateIDJAGRedeemHandlerBinding(config *oauth2.Config) (err error) {
	isRedeem := func(handler oauth2.TokenEndpointBindingHandler) bool {
		_, ok := handler.(*idjag.RedeemHandler)

		return ok
	}

	for _, handler := range config.TokenEndpointHandlers {
		if _, ok := handler.(*idjag.RedeemHandler); ok && !slices.ContainsFunc(config.TokenEndpointBindingHandlers, isRedeem) {
			return fmt.Errorf("%w: the idjag.RedeemHandler (IDJAGRedeemFactory) must also be registered in the token endpoint binding handlers, as it enforces the ID-JAG 'cnf' claim there", ErrHandlerOrder)
		}
	}

	return nil
}

// validateRFC8628UserAuthorizeHandlerOrder returns an error when oidckb.UserAuthorizeHandler is registered after
// rfc8628.UserAuthorizeHandler, which persists the device code session the 'bound_key' grant must be recorded onto.
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
