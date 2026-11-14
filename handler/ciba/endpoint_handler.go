// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ciba

import (
	"context"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

// EndpointHandler issues the 'auth_req_id' of an OpenID Connect CIBA authentication request and persists the request.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.3
type EndpointHandler struct {
	Strategy AuthRequestIDStrategy
	Storage  Storage
	Config   interface {
		oauth2.CIBAConfigProvider
	}
}

// HandleBackChannelAuthenticationEndpointRequest generates the 'auth_req_id', records its signature, expiry, status and
// polling interval on the request, stores the request without its 'user_code' and populates the response. The 'interval' member is returned to
// poll and ping clients only.
func (h *EndpointHandler) HandleBackChannelAuthenticationEndpointRequest(ctx context.Context, request oauth2.BackChannelAuthenticationRequester, response oauth2.BackChannelAuthenticationResponder) (err error) {
	var id, signature string

	if id, signature, err = h.Strategy.GenerateCIBAAuthRequestID(ctx); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	// The 'expires_in' and 'interval' members are positive integers, so both are rounded up to whole seconds.
	//
	// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.3
	lifespan := ceilSeconds(oauth2.GetCIBAAuthRequestLifespan(ctx, h.Config, request))

	interval := ceilSeconds(h.Config.GetCIBAPollingInterval(ctx))
	mode := request.GetDeliveryMode()

	request.SetAuthRequestIDSignature(signature)
	request.SetStatus(oauth2.CIBAStatusPending)
	request.SetPollingInterval(interval)

	if req, ok := request.(*oauth2.BackChannelAuthenticationRequest); ok {
		req.AuthRequestID = ""

		if mode == consts.CIBAModePing || mode == consts.CIBAModePush {
			req.AuthRequestID = id
		}
	}

	request.GetSession().SetExpiresAt(oauth2.CIBAAuthRequestID, time.Now().UTC().Add(lifespan).Truncate(jwt.TimePrecision))

	var stored oauth2.BackChannelAuthenticationRequester

	if stored, err = withoutUserCode(request); err != nil {
		return err
	}

	if err = h.Storage.CreateCIBASession(ctx, signature, stored); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	response.SetAuthRequestID(id)
	response.SetExpiresIn(int64(lifespan / time.Second))

	if mode == consts.CIBAModePush {
		response.SetInterval(0)
	} else {
		response.SetInterval(int64(interval / time.Second))
	}

	return nil
}

// withoutUserCode returns request, or a copy of it without the 'user_code', which the application verified before the
// request is stored and which is a credential of the end user, so it is never persisted. A custom requester carrying a
// 'user_code' cannot be copied without it, so it is oauth2.ErrServerError.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1
func withoutUserCode(request oauth2.BackChannelAuthenticationRequester) (stored oauth2.BackChannelAuthenticationRequester, err error) {
	if request.GetUserCode() == "" {
		return request, nil
	}

	req, ok := request.(*oauth2.BackChannelAuthenticationRequest)
	if !ok {
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("The backchannel authentication request carries a 'user_code' but is not a *oauth2.BackChannelAuthenticationRequest, so it cannot be stored without it."))
	}

	clone := *req
	clone.UserCode = ""

	return &clone, nil
}

func ceilSeconds(d time.Duration) time.Duration {
	if remainder := d % time.Second; d > 0 && remainder != 0 {
		return d - remainder + time.Second
	}

	return d
}

var (
	_ oauth2.BackChannelAuthenticationEndpointHandler = (*EndpointHandler)(nil)
)

// IsCIBAEndpointHandler marks this handler as the OpenID Connect CIBA backchannel authentication endpoint handler.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4
func (h *EndpointHandler) IsCIBAEndpointHandler() {}
