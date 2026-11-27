// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"time"
)

// NewRFC8628UserAuthorizeResponse dispatches the user-facing device authorization request to each configured handler
// to populate the response with the user's authorization decision and any extension parameters. The handlers run in
// the order they are registered and the first error ends the request, so a handler which can reject the decision must
// be registered before the handler which records it. A session with a SetRequestedAt method is given the time the
// device authorization request was received, which the 'max_age' and 'prompt' of the request are measured from. When EnforceAuthenticationRequirements is enabled an approval
// that does not meet the 'acr_values' and 'max_age' of the device authorization request fails with
// unmet_authentication_requirements before any handler runs, so the decision is not recorded and the user code can be
// approved again after the End-User authenticates as required.
func (f *Fosite) NewRFC8628UserAuthorizeResponse(ctx context.Context, requester DeviceAuthorizeRequester, session Session) (responder DeviceUserAuthorizeResponder, err error) {
	carrySessionBinding(requester.GetSession(), session)

	// The 'max_age' and 'prompt' of the request are measured from when the device authorization request was received.
	//
	// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
	if s, ok := session.(interface{ SetRequestedAt(rat time.Time) }); ok {
		if rat := deviceAuthorizeRequestedAt(requester); !rat.IsZero() {
			s.SetRequestedAt(rat)
		}
	}

	requester.SetSession(session)

	RecordAuthenticationContextRequirements(requester, session)

	if f.isAuthenticationRequirementsEnforced(ctx) && requester.GetStatus() == DeviceAuthorizeStatusApproved {
		if err = validateAuthenticationRequirements(requester, session); err != nil {
			return nil, err
		}
	}

	responder = NewRFC8628UserAuthorizeResponse()

	for _, h := range f.Config.GetRFC8628UserAuthorizeEndpointHandlers(ctx) {
		if err = h.PopulateRFC8628UserAuthorizeEndpointResponse(ctx, requester, responder); err != nil {
			return nil, err
		}
	}

	return responder, nil
}

func deviceAuthorizeRequestedAt(requester DeviceAuthorizeRequester) (rat time.Time) {
	if rat = requester.GetRequestedAt(); !rat.IsZero() {
		return rat
	}

	if s, ok := requester.GetSession().(interface{ GetRequestedAt() (rat time.Time) }); ok {
		return s.GetRequestedAt()
	}

	return time.Time{}
}
