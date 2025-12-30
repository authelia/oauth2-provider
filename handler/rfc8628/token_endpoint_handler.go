package rfc8628

import (
	"context"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// DeviceCodeTokenHandler is a response handler for the Device Code introduced in the Device Authorize Grant
// as defined in https://www.rfc-editor.org/rfc/rfc8628
type DeviceCodeTokenHandler struct {
	Storage  Storage
	Strategy CodeStrategy
	Config   interface {
		oauth2.RFC9628DeviceAuthorizeConfigProvider
		oauth2.ClockConfigProvider
	}
}

type DeviceAuthorizeTokenEndpointHandler struct {
	hoauth2.GenericCodeTokenEndpointHandler
}

func (c *DeviceCodeTokenHandler) ValidateGrantTypes(_ context.Context, requester oauth2.AccessRequester) (err error) {
	if !requester.GetClient().GetGrantTypes().Has(string(oauth2.GrantTypeDeviceCode)) {
		return errorsx.WithStack(oauth2.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant 'urn:ietf:params:oauth:grant-type:device_code'."))
	}

	return nil
}

func (c *DeviceCodeTokenHandler) ValidateCodeAndSession(ctx context.Context, _ oauth2.AccessRequester, authorizeRequest oauth2.Requester, code string) (err error) {
	return c.Strategy.ValidateRFC8628DeviceCode(ctx, authorizeRequest, code)
}

func (c *DeviceCodeTokenHandler) GetCodeAndSession(ctx context.Context, requester oauth2.AccessRequester) (code string, signature string, r oauth2.Requester, err error) {
	code = requester.GetRequestForm().Get(consts.FormParameterDeviceCode)

	if signature, err = c.Strategy.RFC8628DeviceCodeSignature(ctx, code); err != nil {
		return "", "", nil, errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	var deviceAuthReq oauth2.DeviceAuthorizeRequester

	if deviceAuthReq, err = c.Storage.GetDeviceCodeSession(ctx, signature, requester.GetSession()); err != nil {
		return "", "", nil, err
	}

	if deviceAuthReq.GetClient().GetID() != requester.GetClient().GetID() {
		return "", "", nil, errorsx.WithStack(oauth2.ErrInvalidGrant.
			WithHint("The OAuth 2.0 Client ID from this request does not match the one from the authorize request."))
	}

	// check last requested time
	requestedAt := requester.GetRequestedAt()
	last := deviceAuthReq.GetLastChecked()
	interval := c.Config.GetRFC8628TokenPollingInterval(ctx)

	if requestedAt.IsZero() {
		requestedAt = c.Config.GetClock(ctx).Now().UTC()
	}

	if last.Add(interval).After(requestedAt) {
		_ = c.UpdateLastChecked(ctx, requester, deviceAuthReq)
		return code, signature, deviceAuthReq, errorsx.WithStack(
			oauth2.ErrSlowDown.WithHintf(
				"The device made an attempt within [%d] seconds. This request will not be processed.",
				(int)(interval.Seconds()),
			),
		)
	}

	var userAuthReq oauth2.DeviceAuthorizeRequester

	if userAuthReq, err = c.Storage.GetDeviceCodeSessionByUserCode(ctx, deviceAuthReq.GetUserCodeSignature(), requester.GetSession()); err != nil {
		_ = c.UpdateLastChecked(ctx, requester, deviceAuthReq)

		return code, signature, deviceAuthReq, err
	}

	if userAuthReq.GetStatus() == oauth2.DeviceAuthorizeStatusNew {
		_ = c.UpdateLastChecked(ctx, requester, deviceAuthReq)

		return "", "", nil, errorsx.WithStack(oauth2.ErrAuthorizationPending.WithHintf("The user has not authorized the request."))
	}

	deviceAuthReq.Merge(userAuthReq)
	requester.SetSession(deviceAuthReq.GetSession())
	requester.SetID(deviceAuthReq.GetID())

	if userAuthReq.GetStatus() != oauth2.DeviceAuthorizeStatusApproved {
		return "", "", nil, errorsx.WithStack(oauth2.ErrAccessDenied.WithHintf("The user has denied the request."))
	}

	return code, signature, deviceAuthReq, err
}

func (c *DeviceCodeTokenHandler) UpdateLastChecked(ctx context.Context, requester oauth2.AccessRequester, authorizeRequest oauth2.Requester) (err error) {
	r, ok := authorizeRequest.(oauth2.DeviceAuthorizeRequester)
	if !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to perform device authorization because the authorizeRequest is not of the right type."))
	}

	lastChecked := requester.GetRequestedAt()
	if lastChecked.IsZero() {
		lastChecked = c.Config.GetClock(ctx).Now().UTC()
	}

	r.SetLastChecked(lastChecked)

	return c.Storage.UpdateDeviceCodeSession(ctx, r.GetDeviceCodeSignature(), r)
}

func (c *DeviceCodeTokenHandler) InvalidateSession(ctx context.Context, signature string, requester oauth2.Requester) (err error) {
	return c.Storage.InvalidateDeviceCodeSession(ctx, signature)
}

func (c *DeviceCodeTokenHandler) CanSkipClientAuth(_ context.Context, _ oauth2.AccessRequester) (skip bool) {
	return false
}

func (c *DeviceCodeTokenHandler) CanHandleTokenEndpointRequest(_ context.Context, requester oauth2.AccessRequester) (handle bool) {
	return requester.GetGrantTypes().ExactOne(string(oauth2.GrantTypeDeviceCode))
}

func (c *DeviceCodeTokenHandler) DeviceCodeSignature(ctx context.Context, code string) (signature string, err error) {
	return c.Strategy.RFC8628DeviceCodeSignature(ctx, code)
}

var (
	_ hoauth2.CodeTokenEndpointHandler = (*DeviceCodeTokenHandler)(nil)
	_ oauth2.TokenEndpointHandler      = (*DeviceAuthorizeTokenEndpointHandler)(nil)
)
