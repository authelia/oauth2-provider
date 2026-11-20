// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8628

import (
	"context"
	"errors"
	"time"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

const slowDownIncrement = 5 * time.Second

// DeviceCodeTokenHandler is a response handler for the Device Code introduced in the Device Authorize Grant
// as defined in https://www.rfc-editor.org/rfc/rfc8628
type DeviceCodeTokenHandler struct {
	Storage  Storage
	Strategy CodeStrategy
	Config   interface {
		oauth2.RFC8628DeviceAuthorizeConfigProvider
	}
}

// DeviceAuthorizeTokenEndpointHandler is a generic code token endpoint handler for the device code grant.
type DeviceAuthorizeTokenEndpointHandler struct {
	hoauth2.GenericCodeTokenEndpointHandler
}

// ValidateGrantTypes returns an error unless the client is registered for the
// 'urn:ietf:params:oauth:grant-type:device_code' grant type.
func (c *DeviceCodeTokenHandler) ValidateGrantTypes(_ context.Context, request oauth2.AccessRequester) (err error) {
	if !request.GetClient().GetGrantTypes().Has(string(oauth2.GrantTypeDeviceCode)) {
		return errorsx.WithStack(oauth2.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant 'urn:ietf:params:oauth:grant-type:device_code'."))
	}

	return nil
}

// ValidateCodeAndSession validates the device code against the device authorization request with the configured
// strategy.
func (c *DeviceCodeTokenHandler) ValidateCodeAndSession(ctx context.Context, _ oauth2.AccessRequester, authorizeRequest oauth2.Requester, code string) (err error) {
	return c.Strategy.ValidateRFC8628DeviceCode(ctx, authorizeRequest, code)
}

// GetCodeAndSession loads the device authorization request for the 'device_code' parameter and decides the outcome of
// this poll. It returns 'expired_token' for an expired code, 'slow_down' when the device polls faster than the
// interval in force, which starts as the configured interval and grows by 5 seconds with each 'slow_down',
// 'invalid_grant' once the device code is invalidated for exceeding the configured limit of consecutive 'slow_down'
// responses, 'authorization_pending' while the user has not decided and 'access_denied' when the user has denied the
// request. Once approved, the user's session is merged into the request.
//
// See: https://datatracker.ietf.org/doc/html/rfc8628#section-3.5
//
//nolint:gocyclo
func (c *DeviceCodeTokenHandler) GetCodeAndSession(ctx context.Context, request oauth2.AccessRequester) (code string, signature string, r oauth2.Requester, err error) {
	code = request.GetRequestForm().Get(consts.FormParameterDeviceCode)

	if signature, err = c.Strategy.RFC8628DeviceCodeSignature(ctx, code); err != nil {
		return "", "", nil, errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	var deviceAuthReq oauth2.DeviceAuthorizeRequester

	if deviceAuthReq, err = c.Storage.GetDeviceCodeSession(ctx, signature, request.GetSession()); errors.Is(err, oauth2.ErrInvalidatedDeviceCode) {
		return code, signature, deviceAuthReq, err
	} else if err != nil {
		return "", "", nil, err
	}

	if deviceAuthReq.GetClient().GetID() != request.GetClient().GetID() {
		return "", "", nil, errorsx.WithStack(oauth2.ErrInvalidGrant.
			WithHint("The OAuth 2.0 Client ID from this request does not match the one from the authorize request."))
	}

	// RFC 8628 Section 3.5: once the device code has expired the device is told so with 'expired_token', whatever the
	// user has or has not decided.
	if verr := c.Strategy.ValidateRFC8628DeviceCode(ctx, deviceAuthReq, code); errors.Is(verr, oauth2.ErrDeviceExpiredToken) {
		return "", "", nil, verr
	}

	requestedAt := request.GetRequestedAt()
	last := deviceAuthReq.GetLastChecked()
	interval := c.Config.GetRFC8628TokenPollingInterval(ctx)

	polling, _ := deviceAuthReq.(oauth2.DeviceAuthorizePollingRequester)

	if polling != nil && polling.GetPollingInterval() > 0 {
		interval = polling.GetPollingInterval()
	}

	if requestedAt.IsZero() {
		requestedAt = time.Now()
	}

	// The client waits the interval between polls, not before the first, so a poll is only early when one was made
	// before it. The interval grows by 5 seconds for this and every later request.
	//
	// See: https://www.rfc-editor.org/rfc/rfc8628#section-3.2 and https://www.rfc-editor.org/rfc/rfc8628#section-3.5
	if last.Add(interval).After(requestedAt) {
		return code, signature, deviceAuthReq, c.slowDown(ctx, request, deviceAuthReq, interval)
	}

	if polling != nil {
		polling.SetSlowDownCount(0)
	}

	// The record of the user code is hydrated into a copy of the session, so the session of the request only carries
	// it once it is known to be the record for this device code.
	session := request.GetSession()
	if session != nil {
		session = session.Clone()
	}

	var userAuthReq oauth2.DeviceAuthorizeRequester

	if userAuthReq, err = c.Storage.GetDeviceCodeSessionByUserCode(ctx, deviceAuthReq.GetUserCodeSignature(), session); err != nil {
		_ = c.UpdateLastChecked(ctx, request, deviceAuthReq)

		return code, signature, deviceAuthReq, err
	}

	// RFC 8628 Section 3.2: the user code identifies one grant, so its record must be the one for this device code.
	if userAuthReq.GetDeviceCodeSignature() != signature {
		return "", "", nil, errorsx.WithStack(oauth2.ErrInvalidGrant.
			WithHint("The user code for this device code is associated with another device authorization request."))
	}

	if status := userAuthReq.GetStatus(); status == oauth2.DeviceAuthorizeStatusNew || status == oauth2.DeviceAuthorizeStatusClaimed {
		if err = c.UpdateLastChecked(ctx, request, deviceAuthReq); err != nil {
			return "", "", nil, errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
		}

		return "", "", nil, errorsx.WithStack(oauth2.ErrAuthorizationPending.WithHintf("The user has not authorized the request."))
	}

	deviceAuthReq.Merge(userAuthReq)
	request.SetSession(deviceAuthReq.GetSession())
	request.SetID(deviceAuthReq.GetID())

	if userAuthReq.GetStatus() != oauth2.DeviceAuthorizeStatusApproved {
		return "", "", nil, errorsx.WithStack(oauth2.ErrAccessDenied.WithHintf("The user has denied the request."))
	}

	return code, signature, deviceAuthReq, err
}

func (c *DeviceCodeTokenHandler) slowDown(ctx context.Context, request oauth2.AccessRequester, deviceAuthReq oauth2.DeviceAuthorizeRequester, interval time.Duration) (err error) {
	polling, _ := deviceAuthReq.(oauth2.DeviceAuthorizePollingRequester)

	count := 1

	if polling != nil {
		count = polling.GetSlowDownCount() + 1
	}

	if limit := c.slowDownLimit(ctx); limit > 0 && count > limit {
		if err = c.Storage.InvalidateDeviceCodeSession(ctx, deviceAuthReq.GetDeviceCodeSignature()); err != nil && !errors.Is(err, oauth2.ErrInvalidatedDeviceCode) {
			return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
		}

		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHintf("The device exceeded the limit of [%d] 'slow_down' responses and the device code is no longer valid.", limit))
	}

	if polling != nil {
		polling.SetPollingInterval(interval + slowDownIncrement)
		polling.SetSlowDownCount(count)
	}

	if err = c.UpdateLastChecked(ctx, request, deviceAuthReq); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	return errorsx.WithStack(oauth2.ErrSlowDown.WithHintf("The device made an attempt within [%d] seconds. This request will not be processed.", (int)(interval.Seconds())))
}

func (c *DeviceCodeTokenHandler) slowDownLimit(ctx context.Context) (limit int) {
	if config, ok := c.Config.(oauth2.RFC8628SlowDownLimitProvider); ok {
		return config.GetRFC8628SlowDownLimit(ctx)
	}

	return 0
}

// UpdateLastChecked records the time of this request on the device authorization request as the last time the device
// polled, and persists it with the rest of its polling state. Only the polling state is written when the Storage
// implements PollStorage.
func (c *DeviceCodeTokenHandler) UpdateLastChecked(ctx context.Context, request oauth2.AccessRequester, authorizeRequest oauth2.Requester) (err error) {
	r, ok := authorizeRequest.(oauth2.DeviceAuthorizeRequester)
	if !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to perform device authorization because the authorizeRequest is not of the right type."))
	}

	lastChecked := request.GetRequestedAt()
	if lastChecked.IsZero() {
		lastChecked = time.Now()
	}

	r.SetLastChecked(lastChecked)

	if storage, ok := c.Storage.(PollStorage); ok {
		return storage.UpdateDeviceCodeSessionPolling(ctx, r.GetDeviceCodeSignature(), r)
	}

	return c.Storage.UpdateDeviceCodeSession(ctx, r.GetDeviceCodeSignature(), r)
}

// InvalidateSession invalidates the device code session with the given signature.
func (c *DeviceCodeTokenHandler) InvalidateSession(ctx context.Context, signature string, request oauth2.Requester) (err error) {
	return c.Storage.InvalidateDeviceCodeSession(ctx, signature)
}

// CanSkipClientAuth always returns false, client authentication is never skipped by this handler.
func (c *DeviceCodeTokenHandler) CanSkipClientAuth(_ context.Context, _ oauth2.AccessRequester) (skip bool) {
	return false
}

// CanHandleTokenEndpointRequest reports whether the 'grant_type' is exactly
// 'urn:ietf:params:oauth:grant-type:device_code'.
func (c *DeviceCodeTokenHandler) CanHandleTokenEndpointRequest(_ context.Context, request oauth2.AccessRequester) (handle bool) {
	return request.GetGrantTypes().ExactOne(string(oauth2.GrantTypeDeviceCode))
}

// DeviceCodeSignature returns the signature of the device code from the configured strategy.
func (c *DeviceCodeTokenHandler) DeviceCodeSignature(ctx context.Context, code string) (signature string, err error) {
	return c.Strategy.RFC8628DeviceCodeSignature(ctx, code)
}

// GrantTypesSupported returns the grant types this handler serves.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
func (c *DeviceAuthorizeTokenEndpointHandler) GrantTypesSupported(ctx context.Context) (types []string) {
	return []string{consts.GrantTypeOAuthDeviceCode}
}

var (
	_ hoauth2.CodeTokenEndpointHandler = (*DeviceCodeTokenHandler)(nil)
	_ oauth2.TokenEndpointHandler      = (*DeviceAuthorizeTokenEndpointHandler)(nil)
)
