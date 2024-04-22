package rfc8628

import (
	"context"
	"net/url"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

type DeviceAuthorizeHandler struct {
	Storage  Storage
	Strategy CodeStrategy
	Config   interface {
		oauth2.RFC9628DeviceAuthorizeConfigProvider
	}
}

// HandleRFC8628DeviceAuthorizeEndpointRequest is a response handler for the Device Authorization Grant as
// defined in https://tools.ietf.org/html/rfc8628#section-3.1
func (d *DeviceAuthorizeHandler) HandleRFC8628DeviceAuthorizeEndpointRequest(ctx context.Context, dar oauth2.DeviceAuthorizeRequester, resp oauth2.DeviceAuthorizeResponder) error {
	session := dar.GetSession()

	deviceCode, deviceCodeSignature, err := d.Strategy.GenerateRFC8628DeviceCode(ctx)
	if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	userCode, userCodeSignature, err := d.Strategy.GenerateRFC8628UserCode(ctx)
	if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	dar.SetStatus(oauth2.DeviceAuthorizeStatusNew)

	dar.SetDeviceCodeSignature(deviceCodeSignature)
	dar.SetUserCodeSignature(userCodeSignature)

	expireAt := time.Now().UTC().Add(d.Config.GetRFC8628CodeLifespan(ctx)).Round(time.Second)
	session.SetExpiresAt(oauth2.DeviceCode, expireAt)
	session.SetExpiresAt(oauth2.UserCode, expireAt)

	if err = d.Storage.CreateDeviceCodeSession(ctx, deviceCodeSignature, dar); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	raw := d.Config.GetRFC8628UserVerificationURL(ctx)
	uri, err := url.ParseRequestURI(raw)
	if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithHint("Failed to parse the RFC8628 User Verification URL.").WithWrap(err).WithDebugError(err))
	}

	query := uri.Query()

	query.Set(consts.FormParameterUserCode, userCode)

	uri.RawQuery = query.Encode()

	resp.SetDeviceCode(deviceCode)
	resp.SetUserCode(userCode)
	resp.SetVerificationURI(raw)
	resp.SetVerificationURIComplete(uri.String())
	resp.SetExpiresIn(int64(time.Until(expireAt).Seconds()))
	resp.SetInterval(int(d.Config.GetRFC8628TokenPollingInterval(ctx).Seconds()))

	return nil
}

var (
	_ oauth2.RFC8628DeviceAuthorizeEndpointHandler = (*DeviceAuthorizeHandler)(nil)
)
