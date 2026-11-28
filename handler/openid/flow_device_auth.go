// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"crypto/rand"
	"errors"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// OpenIDConnectDeviceAuthorizeHandler issues ID Tokens for the RFC 8628 device authorization grant. As a
// oauth2.RFC8628DeviceAuthorizeRequestValidator it checks the OpenID Connect 1.0 parameters of the device authorization
// request in any registration order. As a
// oauth2.RFC8628UserAuthorizeEndpointHandler it must be registered before rfc8628.UserAuthorizeHandler, so an approval
// it rejects is not recorded. As a oauth2.TokenEndpointHandler it must be registered after
// rfc8628.DeviceAuthorizeTokenEndpointHandler, so the granted scopes are set on the token request.
//
// See: https://datatracker.ietf.org/doc/html/rfc8628#section-3.3
type OpenIDConnectDeviceAuthorizeHandler struct {
	OpenIDConnectRequestStorage   OpenIDConnectRequestStorage
	OpenIDConnectRequestValidator *OpenIDConnectRequestValidator
	hoauth2.CodeTokenEndpointHandler

	Config interface {
		oauth2.IDTokenLifespanProvider
	}

	*IDTokenHandleHelper
}

// HandleRFC8628UserAuthorizeEndpointRequest always returns oauth2.ErrUnknownRequest as this handler only acts when the
// user authorization response is populated.
func (c *OpenIDConnectDeviceAuthorizeHandler) HandleRFC8628UserAuthorizeEndpointRequest(_ context.Context, _ oauth2.DeviceAuthorizeRequester) (err error) {
	return errorsx.WithStack(oauth2.ErrUnknownRequest)
}

// PopulateRFC8628UserAuthorizeEndpointResponse persists the OpenID Connect 1.0 session under the device code signature
// when the request is approved, the 'openid' scope was granted and the client is registered for the device code grant
// type, and otherwise does nothing. An approval whose session does not meet the 'max_age', 'prompt' and 'id_token_hint'
// parameters of the device authorization request, the 'default_max_age' or the 'require_auth_time' of the client is
// rejected with the error the authorization endpoint returns for it, such as oauth2.ErrLoginRequired, so the decision
// is not recorded and the user code can be approved again once the End-User has authenticated as required. A 'nonce'
// the client already used while the device code issued for it could still be redeemed is rejected. A session
// implementing ApprovalSession is given a new approval identifier, which the token endpoint requires the OpenID Connect
// 1.0 session to share with the session of the recorded decision.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthError
func (c *OpenIDConnectDeviceAuthorizeHandler) PopulateRFC8628UserAuthorizeEndpointResponse(ctx context.Context, req oauth2.DeviceAuthorizeRequester, _ oauth2.DeviceUserAuthorizeResponder) (err error) {
	if req.GetStatus() != oauth2.DeviceAuthorizeStatusApproved {
		return nil
	}

	if !req.GetGrantedScopes().Has(consts.ScopeOpenID) {
		return nil
	}

	if !req.GetClient().GetGrantTypes().Has(string(oauth2.GrantTypeDeviceCode)) {
		return nil
	}

	if len(req.GetDeviceCodeSignature()) == 0 {
		return errorsx.WithStack(oauth2.ErrMisconfiguration.WithDebug("The device code has not been issued yet, indicating a broken code configuration."))
	}

	if _, err = c.OpenIDConnectRequestValidator.ValidateSession(ctx, req); err != nil {
		return err
	}

	if err = setNonceUsed(ctx, c.OpenIDConnectRequestStorage, req, getSessionExpiresAt(req, oauth2.DeviceCode, c.Config.GetIDTokenLifespan(ctx))); err != nil {
		return err
	}

	if session, ok := req.GetSession().(ApprovalSession); ok {
		session.SetApprovalID(rand.Text())
	}

	if err = c.OpenIDConnectRequestStorage.CreateOpenIDConnectSession(ctx, req.GetDeviceCodeSignature(), req.Sanitize(oidcParameters)); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	return nil
}

// ValidateRFC8628DeviceAuthorizeRequest returns oauth2.ErrInvalidRequest for a malformed 'prompt', 'max_age' or
// 'id_token_hint' parameter of a device authorization request for the 'openid' scope, so no device code is issued for
// a request which could never be approved.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
func (c *OpenIDConnectDeviceAuthorizeHandler) ValidateRFC8628DeviceAuthorizeRequest(ctx context.Context, request oauth2.DeviceAuthorizeRequester) (err error) {
	if !request.GetRequestedScopes().Has(consts.ScopeOpenID) {
		return nil
	}

	return c.OpenIDConnectRequestValidator.ValidateParameters(ctx, request)
}

// HandleTokenEndpointRequest always returns oauth2.ErrUnknownRequest as this handler only acts when the token response
// is populated.
func (c *OpenIDConnectDeviceAuthorizeHandler) HandleTokenEndpointRequest(_ context.Context, _ oauth2.AccessRequester) (err error) {
	return errorsx.WithStack(oauth2.ErrUnknownRequest)
}

// PopulateTokenEndpointResponse issues an ID Token for a device code grant. It loads the OpenID Connect 1.0 session
// stored under the device code signature, deletes it, and adds the 'id_token' with an 'at_hash' claim to the response.
// When no such session exists it returns oauth2.ErrServerError if the 'openid' scope was granted, and otherwise
// oauth2.ErrUnknownRequest. It returns oauth2.ErrServerError when the session is not for the subject of the recorded
// decision, or when the session of the decision implements ApprovalSession and the session was stored by another
// approval.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
func (c *OpenIDConnectDeviceAuthorizeHandler) PopulateTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	var (
		signature string
		ar        oauth2.Requester
		session   Session
		ok        bool
	)

	if signature, err = c.DeviceCodeSignature(ctx, request.GetRequestForm().Get(consts.FormParameterDeviceCode)); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	// Read first, as the storage may hydrate the OpenID Connect 1.0 session into the session of the request.
	subject := getSessionSubject(request)
	approval, tracked := getSessionApprovalID(request.GetSession())

	if ar, err = c.OpenIDConnectRequestStorage.GetOpenIDConnectSession(ctx, signature, request); errors.Is(err, ErrNoSessionFound) {
		if request.GetGrantedScopes().Has(consts.ScopeOpenID) {
			return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebug("The 'openid' scope was granted but no OpenID Connect session exists for the device code, so no ID Token can be issued."))
		}

		return errorsx.WithStack(oauth2.ErrUnknownRequest.WithWrap(err).WithDebugError(err))
	} else if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	if !ar.GetGrantedScopes().Has(consts.ScopeOpenID) {
		return errorsx.WithStack(oauth2.ErrMisconfiguration.WithDebug("An OpenID Connect session was found but the openid scope is missing, probably due to a broken code configuration."))
	}

	if !request.GetClient().GetGrantTypes().Has(string(oauth2.GrantTypeDeviceCode)) {
		return errorsx.WithStack(oauth2.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use the authorization grant 'urn:ietf:params:oauth:grant-type:device_code'."))
	}

	if session, ok = ar.GetSession().(Session); !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to generate ID Token because the session must be of type 'openid.Session'."))
	}

	if session.GetSubject() != subject {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to generate ID Token because the OpenID Connect session is not for the subject the device code was approved by."))
	}

	if id, _ := getSessionApprovalID(session); tracked && id != approval {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to generate ID Token because the OpenID Connect session is not from the approval the device code decision was recorded for."))
	}

	claims := session.IDTokenClaims()

	if claims.Subject == "" {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to generate ID Token because subject is an empty string."))
	}

	if err = c.OpenIDConnectRequestStorage.DeleteOpenIDConnectSession(ctx, signature); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	claims.AccessTokenHash = c.GetAccessTokenHash(ctx, request, response)

	lifespan := oauth2.GetEffectiveLifespan(request.GetClient(), oauth2.GrantTypeDeviceCode, oauth2.IDToken, c.Config.GetIDTokenLifespan(ctx))

	return c.IssueExplicitIDToken(ctx, lifespan, ar, response)
}

// CanSkipClientAuth always returns false, client authentication is never skipped by this handler.
func (c *OpenIDConnectDeviceAuthorizeHandler) CanSkipClientAuth(_ context.Context, _ oauth2.AccessRequester) (skip bool) {
	return false
}

// CanHandleTokenEndpointRequest reports whether the 'grant_type' is exactly
// 'urn:ietf:params:oauth:grant-type:device_code'.
func (c *OpenIDConnectDeviceAuthorizeHandler) CanHandleTokenEndpointRequest(_ context.Context, request oauth2.AccessRequester) (handle bool) {
	return request.GetGrantTypes().ExactOne(string(oauth2.GrantTypeDeviceCode))
}

// GrantTypesSupported returns nil because the handler only augments another grant.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
func (c *OpenIDConnectDeviceAuthorizeHandler) GrantTypesSupported(ctx context.Context) (types []string) {
	return nil
}

// CodeChallengeMethodsSupported returns nil because the handler does not enforce PKCE.
//
// See: https://datatracker.ietf.org/doc/html/rfc7636#section-4.3
func (c *OpenIDConnectDeviceAuthorizeHandler) CodeChallengeMethodsSupported(ctx context.Context) (methods []string) {
	return nil
}

// RFC8693TokenTypesSupported returns nil because the handler does not issue RFC 8693 tokens.
//
// See: https://datatracker.ietf.org/doc/html/rfc8693#section-3
func (c *OpenIDConnectDeviceAuthorizeHandler) RFC8693TokenTypesSupported(ctx context.Context) (types []string) {
	return nil
}

var (
	_ oauth2.RFC8628UserAuthorizeEndpointHandler    = (*OpenIDConnectDeviceAuthorizeHandler)(nil)
	_ oauth2.RFC8628DeviceAuthorizeRequestValidator = (*OpenIDConnectDeviceAuthorizeHandler)(nil)
	_ oauth2.TokenEndpointHandler                   = (*OpenIDConnectDeviceAuthorizeHandler)(nil)
)
