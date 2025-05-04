package openid

import (
	"context"
	"errors"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

type OpenIDConnectDeviceAuthorizeHandler struct {
	OpenIDConnectRequestStorage   OpenIDConnectRequestStorage
	OpenIDConnectRequestValidator *OpenIDConnectRequestValidator
	hoauth2.CodeTokenEndpointHandler

	Config interface {
		oauth2.IDTokenLifespanProvider
	}

	*IDTokenHandleHelper
}

func (c *OpenIDConnectDeviceAuthorizeHandler) HandleRFC8628UserAuthorizeEndpointRequest(_ context.Context, _ oauth2.DeviceAuthorizeRequester) (err error) {
	return errorsx.WithStack(oauth2.ErrUnknownRequest)
}

func (c *OpenIDConnectDeviceAuthorizeHandler) PopulateRFC8628UserAuthorizeEndpointResponse(ctx context.Context, req oauth2.DeviceAuthorizeRequester, _ oauth2.DeviceUserAuthorizeResponder) (err error) {
	if !req.GetGrantedScopes().Has(consts.ScopeOpenID) {
		return nil
	}

	if !req.GetClient().GetGrantTypes().Has(string(oauth2.GrantTypeDeviceCode)) {
		return nil
	}

	if len(req.GetDeviceCodeSignature()) == 0 {
		return errorsx.WithStack(oauth2.ErrMisconfiguration.WithDebug("The device code has not been issued yet, indicating a broken code configuration."))
	}

	if err = c.OpenIDConnectRequestStorage.CreateOpenIDConnectSession(ctx, req.GetDeviceCodeSignature(), req.Sanitize(oidcParameters)); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	return nil
}

func (c *OpenIDConnectDeviceAuthorizeHandler) HandleTokenEndpointRequest(_ context.Context, _ oauth2.AccessRequester) (err error) {
	return errorsx.WithStack(oauth2.ErrUnknownRequest)
}

func (c *OpenIDConnectDeviceAuthorizeHandler) PopulateTokenEndpointResponse(ctx context.Context, requester oauth2.AccessRequester, responder oauth2.AccessResponder) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	var (
		signature string
		ar        oauth2.Requester
		session   Session
		ok        bool
	)

	if signature, err = c.DeviceCodeSignature(ctx, requester.GetRequestForm().Get(consts.FormParameterDeviceCode)); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	if ar, err = c.OpenIDConnectRequestStorage.GetOpenIDConnectSession(ctx, signature, requester); errors.Is(err, ErrNoSessionFound) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest.WithWrap(err).WithDebugError(err))
	} else if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	if !ar.GetGrantedScopes().Has(consts.ScopeOpenID) {
		return errorsx.WithStack(oauth2.ErrMisconfiguration.WithDebug("An OpenID Connect session was found but the openid scope is missing, probably due to a broken code configuration."))
	}

	if !requester.GetClient().GetGrantTypes().Has(string(oauth2.GrantTypeDeviceCode)) {
		return errorsx.WithStack(oauth2.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use the authorization grant 'urn:ietf:params:oauth:grant-type:device_code'."))
	}

	if session, ok = ar.GetSession().(Session); !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to generate id token because session must be of type 'openid.Session'."))
	}

	claims := session.IDTokenClaims()

	if claims.Subject == "" {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to generate id token because subject is an empty string."))
	}

	claims.AccessTokenHash = c.GetAccessTokenHash(ctx, requester, responder)

	lifespan := oauth2.GetEffectiveLifespan(requester.GetClient(), oauth2.GrantTypeDeviceCode, oauth2.IDToken, c.Config.GetIDTokenLifespan(ctx))

	return c.IssueExplicitIDToken(ctx, lifespan, ar, responder)
}

func (c *OpenIDConnectDeviceAuthorizeHandler) CanSkipClientAuth(_ context.Context, _ oauth2.AccessRequester) (skip bool) {
	return false
}

func (c *OpenIDConnectDeviceAuthorizeHandler) CanHandleTokenEndpointRequest(_ context.Context, requester oauth2.AccessRequester) (handle bool) {
	return requester.GetGrantTypes().ExactOne(string(oauth2.GrantTypeDeviceCode))
}

var (
	_ oauth2.RFC8628UserAuthorizeEndpointHandler = (*OpenIDConnectDeviceAuthorizeHandler)(nil)
	_ oauth2.TokenEndpointHandler                = (*OpenIDConnectDeviceAuthorizeHandler)(nil)
)
