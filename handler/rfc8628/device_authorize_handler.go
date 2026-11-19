// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8628

import (
	"context"
	"errors"
	"net/url"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

// DeviceAuthorizeHandler implements the Device Authorization Grant Flow's relying party interactions as defined in
// RFC8638 Section 3.1 and Section 3.2.
//
// See: https://tools.ietf.org/html/rfc8628#section-3.1 and https://tools.ietf.org/html/rfc8628#section-3.2
type DeviceAuthorizeHandler struct {
	Storage  Storage
	Strategy CodeStrategy
	Config   interface {
		oauth2.RFC8628DeviceAuthorizeConfigProvider
	}
}

// HandleRFC8628DeviceAuthorizeEndpointRequest implements the Device Authorization Grant Flow's relying party
// Device Authorization Request and Device Authorization Response as defined in RFC8638 Section 3.1 and Section 3.2.
// The codes expire after the client's oauth2.DeviceCode lifespan for the grant, or the configured lifespan when the
// client has none greater than 0 seconds. The 'verification_uri_complete' member is included only when the
// configuration or the client enables it.
//
// See: https://tools.ietf.org/html/rfc8628#section-3.1 and https://tools.ietf.org/html/rfc8628#section-3.2
func (d *DeviceAuthorizeHandler) HandleRFC8628DeviceAuthorizeEndpointRequest(ctx context.Context, request oauth2.DeviceAuthorizeRequester, response oauth2.DeviceAuthorizeResponder) (err error) {
	session := request.GetSession()

	var deviceCode, deviceCodeSignature, userCode string

	if deviceCode, deviceCodeSignature, err = d.Strategy.GenerateRFC8628DeviceCode(ctx); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	request.SetStatus(oauth2.DeviceAuthorizeStatusNew)
	request.SetDeviceCodeSignature(deviceCodeSignature)

	lifespan := oauth2.GetEffectiveLifespan(request.GetClient(), oauth2.GrantTypeDeviceCode, oauth2.DeviceCode, d.Config.GetRFC8628CodeLifespan(ctx))
	if lifespan <= 0 {
		lifespan = d.Config.GetRFC8628CodeLifespan(ctx)
	}

	expireAt := time.Now().UTC().Add(lifespan).Truncate(jwt.TimePrecision)
	session.SetExpiresAt(oauth2.DeviceCode, expireAt)
	session.SetExpiresAt(oauth2.UserCode, expireAt)

	if userCode, err = d.createWithUniqueUserCode(ctx, deviceCodeSignature, request); err != nil {
		return err
	}

	raw := d.Config.GetRFC8628UserVerificationURL(ctx)

	var uri *url.URL

	if uri, err = url.ParseRequestURI(raw); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithHint("Failed to parse the RFC8628 User Verification URL.").WithWrap(err).WithDebugError(err))
	}

	response.SetDeviceCode(deviceCode)
	response.SetUserCode(userCode)
	response.SetVerificationURI(raw)

	// See: https://www.rfc-editor.org/rfc/rfc10027#section-6.1.14
	if d.isVerificationURICompleteEnabled(ctx, request.GetClient()) {
		query := uri.Query()

		query.Set(consts.FormParameterUserCode, userCode)

		uri.RawQuery = query.Encode()

		response.SetVerificationURIComplete(uri.String())
	}

	response.SetExpiresIn(int64(time.Until(expireAt).Seconds()))
	response.SetInterval(int(d.Config.GetRFC8628TokenPollingInterval(ctx).Seconds()))

	return nil
}

func (d *DeviceAuthorizeHandler) isVerificationURICompleteEnabled(ctx context.Context, client oauth2.Client) (enabled bool) {
	if config, ok := d.Config.(oauth2.RFC8628VerificationURICompleteProvider); ok {
		enabled = config.GetRFC8628VerificationURIComplete(ctx)
	}

	if c, ok := client.(oauth2.RFC8628VerificationURICompleteClient); ok {
		return c.GetRFC8628VerificationURIComplete(enabled)
	}

	return enabled
}

func (d *DeviceAuthorizeHandler) createWithUniqueUserCode(ctx context.Context, deviceCodeSignature string, request oauth2.DeviceAuthorizeRequester) (code string, err error) {
	var signature string

	for range userCodeGenerationAttempts {
		if code, signature, err = d.Strategy.GenerateRFC8628UserCode(ctx); err != nil {
			return "", errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
		}

		_, err = d.Storage.GetDeviceCodeSessionByUserCode(ctx, signature, request.GetSession().Clone())

		switch {
		case errors.Is(err, oauth2.ErrNotFound):
		case err == nil, errors.Is(err, oauth2.ErrInvalidatedDeviceCode):
			continue
		default:
			return "", errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
		}

		request.SetUserCodeSignature(signature)

		switch err = d.Storage.CreateDeviceCodeSession(ctx, deviceCodeSignature, request); {
		case err == nil:
			return code, nil
		case errors.Is(err, oauth2.ErrDuplicateUserCode):
			continue
		default:
			return "", errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
		}
	}

	return "", errorsx.WithStack(oauth2.ErrServerError.WithDebugf("Failed to generate a unique user code after %d attempts.", userCodeGenerationAttempts))
}

const userCodeGenerationAttempts = 3

var (
	_ oauth2.RFC8628DeviceAuthorizeEndpointHandler = (*DeviceAuthorizeHandler)(nil)
)
