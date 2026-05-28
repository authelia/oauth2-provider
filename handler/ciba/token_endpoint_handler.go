// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ciba

import (
	"context"
	"time"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// CIBATokenHandler implements the CodeTokenEndpointHandler contract for the OpenID Connect Client Initiated Backchannel
// Authentication (CIBA) grant. It is composed with hoauth2.GenericCodeTokenEndpointHandler via CIBATokenEndpointHandler
// to share the standard access/refresh token issuance logic with the authorization code and device code flows.
//
// See https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#token_request.
type CIBATokenHandler struct {
	Storage  Storage
	Strategy AuthRequestIDStrategy
	Config   interface {
		oauth2.OpenIDCIBAConfigProvider
	}
}

// CIBATokenEndpointHandler is the OpenID Connect CIBA token endpoint handler wired around the generic code token
// endpoint handler so the access/refresh token issuance follows the same path as the other code-based grants.
type CIBATokenEndpointHandler struct {
	hoauth2.GenericCodeTokenEndpointHandler
}

// ValidateGrantTypes ensures the client is registered for the CIBA grant.
func (c *CIBATokenHandler) ValidateGrantTypes(_ context.Context, request oauth2.AccessRequester) (err error) {
	if !request.GetClient().GetGrantTypes().Has(string(oauth2.GrantTypeOpenIDCIBA)) {
		return errorsx.WithStack(oauth2.ErrUnauthorizedClient.WithHintf("The OAuth 2.0 Client is not allowed to use authorization grant '%s'.", consts.GrantTypeOpenIDCIBA))
	}

	return nil
}

// ValidateCodeAndSession delegates to the auth_req_id strategy to ensure the auth_req_id is bound to the request.
func (c *CIBATokenHandler) ValidateCodeAndSession(ctx context.Context, _ oauth2.AccessRequester, authorizeRequest oauth2.Requester, code string) (err error) {
	return c.Strategy.ValidateAuthRequestID(ctx, authorizeRequest, code)
}

// GetCodeAndSession retrieves the auth_req_id from the request, hydrates the persisted CIBA session, enforces the
// polling interval per Section 11 of the specification, and returns the appropriate polling error (slow_down,
// authorization_pending, access_denied or expired_token) based on the session state.
//
//nolint:gocyclo
func (c *CIBATokenHandler) GetCodeAndSession(ctx context.Context, request oauth2.AccessRequester) (code string, signature string, r oauth2.Requester, err error) {
	code = request.GetRequestForm().Get(consts.FormParameterAuthReqID)

	if len(code) == 0 {
		return "", "", nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The 'auth_req_id' parameter is required when using the OpenID Connect CIBA grant."))
	}

	if signature, err = c.Strategy.AuthRequestIDSignature(ctx, code); err != nil {
		return code, "", nil, errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	var session oauth2.CIBARequester

	if session, err = c.Storage.GetOpenIDCIBASession(ctx, signature, request.GetSession()); err != nil {
		return code, signature, nil, err
	}

	if session.GetClient().GetID() != request.GetClient().GetID() {
		return code, signature, session, errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The OAuth 2.0 Client ID from this request does not match the one from the backchannel authentication request."))
	}

	requestedAt := request.GetRequestedAt()
	if requestedAt.IsZero() {
		requestedAt = time.Now()
	}

	if expiry := session.GetSession().GetExpiresAt(oauth2.CIBAAuthRequestID); !expiry.IsZero() && expiry.Before(requestedAt) {
		return code, signature, session, errorsx.WithStack(oauth2.ErrDeviceExpiredToken.WithHint("The 'auth_req_id' has expired and the backchannel authentication session has concluded."))
	}

	interval := c.Config.GetOpenIDCIBAPollingInterval(ctx)
	last := session.GetLastChecked()

	if !last.IsZero() && last.Add(interval).After(requestedAt) {
		_ = c.updateLastChecked(ctx, requestedAt, session)

		return code, signature, session, errorsx.WithStack(oauth2.ErrSlowDown.WithHintf("The client made a token endpoint request within '%d' seconds of the previous attempt. This request will not be processed.", int(interval.Seconds())))
	}

	switch session.GetStatus() {
	case oauth2.CIBAStatusNew:
		_ = c.updateLastChecked(ctx, requestedAt, session)

		return code, signature, session, errorsx.WithStack(oauth2.ErrAuthorizationPending.WithHint("The end user has not yet completed the backchannel authentication."))
	case oauth2.CIBAStatusDenied:
		return code, signature, session, errorsx.WithStack(oauth2.ErrAccessDenied.WithHint("The end user denied the backchannel authentication request."))
	case oauth2.CIBAStatusApproved:
		// continue
	}

	return code, signature, session, nil
}

func (c *CIBATokenHandler) updateLastChecked(ctx context.Context, at time.Time, request oauth2.CIBARequester) error {
	request.SetLastChecked(at)

	return c.Storage.UpdateOpenIDCIBASession(ctx, request.GetAuthRequestIDSignature(), request)
}

// UpdateLastChecked records the latest polling attempt against the CIBA session so the next call can enforce the
// polling interval.
func (c *CIBATokenHandler) UpdateLastChecked(ctx context.Context, request oauth2.AccessRequester, authorizeRequest oauth2.Requester) (err error) {
	r, ok := authorizeRequest.(oauth2.CIBARequester)
	if !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to update the CIBA polling timestamp because the authorize request is not of the right type."))
	}

	requestedAt := request.GetRequestedAt()
	if requestedAt.IsZero() {
		requestedAt = time.Now()
	}

	return c.updateLastChecked(ctx, requestedAt, r)
}

// InvalidateSession invalidates the CIBA session after a successful token exchange so the auth_req_id can not be
// reused.
func (c *CIBATokenHandler) InvalidateSession(ctx context.Context, signature string, _ oauth2.Requester) error {
	return c.Storage.InvalidateOpenIDCIBASession(ctx, signature)
}

// CanSkipClientAuth indicates that client authentication may never be skipped for the CIBA grant.
func (c *CIBATokenHandler) CanSkipClientAuth(_ context.Context, _ oauth2.AccessRequester) bool {
	return false
}

// CanHandleTokenEndpointRequest reports whether the request uses the OpenID Connect CIBA grant_type.
func (c *CIBATokenHandler) CanHandleTokenEndpointRequest(_ context.Context, request oauth2.AccessRequester) bool {
	return request.GetGrantTypes().ExactOne(string(oauth2.GrantTypeOpenIDCIBA))
}

// DeviceCodeSignature satisfies the CodeTokenEndpointHandler contract. For CIBA the auth_req_id signature is returned.
// The legacy method name comes from the shared interface used by the device authorization flow.
func (c *CIBATokenHandler) DeviceCodeSignature(ctx context.Context, code string) (signature string, err error) {
	return c.Strategy.AuthRequestIDSignature(ctx, code)
}

var (
	_ hoauth2.CodeTokenEndpointHandler = (*CIBATokenHandler)(nil)
	_ oauth2.TokenEndpointHandler      = (*CIBATokenEndpointHandler)(nil)
)
