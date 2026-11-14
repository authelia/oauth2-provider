// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ciba

import (
	"context"
	"errors"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/x/errorsx"
)

// DecisionHandler records the end user's decision on an OpenID Connect CIBA authentication request. The decision is
// written only while the stored request is pending, so of concurrent decisions exactly one is recorded.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.8
type DecisionHandler struct {
	Storage  Storage
	Strategy AuthRequestIDStrategy
	Config   interface {
		oauth2.CIBAConfigProvider
	}
}

// HandleBackChannelAuthenticationDecision stores the decided request. A request another decision has already decided
// is oauth2.ErrInvalidRequest.
func (h *DecisionHandler) HandleBackChannelAuthenticationDecision(ctx context.Context, request oauth2.BackChannelAuthenticationRequester, _ *oauth2.BackChannelAuthenticationDecisionResult) (err error) {
	switch request.GetStatus() {
	case oauth2.CIBAStatusApproved, oauth2.CIBAStatusDenied, oauth2.CIBAStatusFailed:
	default:
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("The backchannel authentication request has not been decided."))
	}

	err = h.Storage.DecideCIBASession(ctx, request.GetAuthRequestIDSignature(), request)

	switch {
	case err == nil:
		return nil
	case errors.Is(err, oauth2.ErrCIBADecided):
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The backchannel authentication request is already decided.").WithWrap(err).WithDebugError(err))
	case errors.Is(err, oauth2.ErrNotFound):
		return errorsx.WithStack(err)
	default:
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}
}

var (
	_ oauth2.BackChannelAuthenticationDecisionHandler = (*DecisionHandler)(nil)
)
