package rfc8628

import (
	"context"
	"time"

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
	}
}

type DeviceAuthorizeTokenEndpointHandler struct {
	hoauth2.GenericCodeTokenEndpointHandler
}

func (c *DeviceCodeTokenHandler) ValidateGrantTypes(_ context.Context, requester oauth2.AccessRequester) error {
	if !requester.GetClient().GetGrantTypes().Has(string(oauth2.GrantTypeDeviceCode)) {
		return errorsx.WithStack(oauth2.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant 'urn:ietf:params:oauth:grant-type:device_code'."))
	}

	return nil
}

func (c *DeviceCodeTokenHandler) ValidateCodeAndSession(ctx context.Context, _ oauth2.AccessRequester, authorizeRequest oauth2.Requester, code string) error {
	return c.Strategy.ValidateRFC8628DeviceCode(ctx, authorizeRequest, code)
}

func (c *DeviceCodeTokenHandler) GetCodeAndSession(ctx context.Context, requester oauth2.AccessRequester) (string, string, oauth2.Requester, error) {
	code := requester.GetRequestForm().Get(consts.FormParameterDeviceCode)
	signature, err := c.Strategy.RFC8628DeviceCodeSignature(ctx, code)
	if err != nil {
		return "", "", nil, errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	deviceAuthReq, err := c.Storage.GetDeviceCodeSession(ctx, signature, requester.GetSession())
	if err != nil {
		return "", "", nil, err
	}

	if deviceAuthReq.GetClient().GetID() != requester.GetClient().GetID() {
		return "", "", nil, errorsx.WithStack(oauth2.ErrInvalidGrant.
			WithHint("The OAuth 2.0 Client ID from this request does not match the one from the authorize request."))
	}

	// check last requested time
	lastReqTime := deviceAuthReq.GetLastChecked()
	requestedAt := requester.GetRequestedAt()
	if requestedAt.IsZero() {
		requestedAt = time.Now()
	}

	pollInterval := c.Config.GetRFC8628TokenPollingInterval(ctx)
	if lastReqTime.Add(pollInterval).After(requestedAt) {
		_ = c.UpdateLastChecked(ctx, requester, deviceAuthReq)
		return code, signature, deviceAuthReq, errorsx.WithStack(
			oauth2.ErrSlowDown.WithHintf(
				"The device made an attempt within [%d] seconds. This request will not be processed.",
				(int)(pollInterval.Seconds()),
			),
		)
	}

	// get the user code session
	userAuthReq, err := c.Storage.GetDeviceCodeSessionByUserCode(ctx, deviceAuthReq.GetUserCodeSignature(), requester.GetSession())
	if err != nil {
		_ = c.UpdateLastChecked(ctx, requester, deviceAuthReq)
		return code, signature, deviceAuthReq, err
	}

	if userAuthReq.GetStatus() == oauth2.DeviceAuthorizeStatusNew {
		_ = c.UpdateLastChecked(ctx, requester, deviceAuthReq)
		return "", "", nil, errorsx.WithStack(oauth2.ErrAuthorizationPending.WithHintf("The user has not authorized the request."))
	}

	// Update status and session into access request and device authorization request.
	deviceAuthReq.Merge(userAuthReq)
	requester.SetSession(deviceAuthReq.GetSession())
	requester.SetID(deviceAuthReq.GetID())

	if userAuthReq.GetStatus() != oauth2.DeviceAuthorizeStatusApproved {
		return "", "", nil, errorsx.WithStack(oauth2.ErrAccessDenied.WithHintf("The user has denied the request."))
	}

	return code, signature, deviceAuthReq, err
}

func (c *DeviceCodeTokenHandler) UpdateLastChecked(ctx context.Context, requester oauth2.AccessRequester, authorizeRequest oauth2.Requester) error {
	r, ok := authorizeRequest.(oauth2.DeviceAuthorizeRequester)
	if !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to perform device authorization because the authorizeRequest is not of the right type."))
	}

	lastChecked := requester.GetRequestedAt()
	if lastChecked.IsZero() {
		lastChecked = time.Now()
	}

	r.SetLastChecked(requester.GetRequestedAt())

	return c.Storage.UpdateDeviceCodeSession(ctx, r.GetDeviceCodeSignature(), r)
}

func (c *DeviceCodeTokenHandler) InvalidateSession(ctx context.Context, signature string, requester oauth2.Requester) error {
	return c.Storage.InvalidateDeviceCodeSession(ctx, signature)
}

func (c *DeviceCodeTokenHandler) CanSkipClientAuth(_ context.Context, _ oauth2.AccessRequester) bool {
	return false
}

func (c *DeviceCodeTokenHandler) CanHandleTokenEndpointRequest(_ context.Context, requester oauth2.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne(string(oauth2.GrantTypeDeviceCode))
}

func (c *DeviceCodeTokenHandler) DeviceCodeSignature(ctx context.Context, code string) (string, error) {
	return c.Strategy.RFC8628DeviceCodeSignature(ctx, code)
}

var (
	_ hoauth2.CodeTokenEndpointHandler = (*DeviceCodeTokenHandler)(nil)
	_ oauth2.TokenEndpointHandler      = (*DeviceAuthorizeTokenEndpointHandler)(nil)
)
