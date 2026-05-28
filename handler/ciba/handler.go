// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ciba

import (
	"context"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

// OpenIDConnectCIBAHandler implements the OpenID Connect Client Initiated Backchannel Authentication (CIBA)
// backchannel authentication endpoint's authorization server side per Section 7 of the specification. The handler
// issues an auth_req_id, persists the request via Storage, and populates the response with the lifetime and polling
// interval values from configuration.
//
// See https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html.
type OpenIDConnectCIBAHandler struct {
	Storage  Storage
	Strategy AuthRequestIDStrategy
	Config   interface {
		oauth2.OpenIDCIBAConfigProvider
	}
}

// HandleOpenIDCIBAEndpointRequest issues an auth_req_id for the supplied CIBA request, marks the request as new and
// persists it to storage. The response is populated with the auth_req_id, the lifetime in seconds and the polling
// interval the client must observe when calling the token endpoint.
func (h *OpenIDConnectCIBAHandler) HandleOpenIDCIBAEndpointRequest(ctx context.Context, request oauth2.CIBARequester, response oauth2.CIBAResponder) (err error) {
	session := request.GetSession()
	if session == nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to handle OpenID Connect CIBA request because the session is nil."))
	}

	var (
		id, signature string
	)

	if id, signature, err = h.Strategy.GenerateAuthRequestID(ctx); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	request.SetStatus(oauth2.CIBAStatusNew)
	request.SetAuthRequestIDSignature(signature)

	expireAt := time.Now().UTC().Add(h.Config.GetOpenIDCIBALifespan(ctx)).Truncate(jwt.TimePrecision)
	session.SetExpiresAt(oauth2.CIBAAuthRequestID, expireAt)

	if err = h.Storage.CreateOpenIDCIBASession(ctx, signature, request); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	response.SetAuthRequestID(id)
	response.SetExpiresIn(int64(time.Until(expireAt).Seconds()))
	response.SetInterval(int(h.Config.GetOpenIDCIBAPollingInterval(ctx).Seconds()))

	return nil
}

var (
	_ oauth2.OpenIDCIBAEndpointHandler = (*OpenIDConnectCIBAHandler)(nil)
)
