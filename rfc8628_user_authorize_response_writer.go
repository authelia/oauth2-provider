// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import "context"

// NewRFC8628UserAuthorizeResponse dispatches the user-facing device authorization request to each configured handler
// to populate the response with the user's authorization decision and any extension parameters.
func (f *Fosite) NewRFC8628UserAuthorizeResponse(ctx context.Context, requester DeviceAuthorizeRequester, session Session) (responder DeviceUserAuthorizeResponder, err error) {
	requester.SetSession(session)
	responder = NewRFC8628UserAuthorizeResponse()

	for _, h := range f.Config.GetRFC8628UserAuthorizeEndpointHandlers(ctx) {
		if err = h.PopulateRFC8628UserAuthorizeEndpointResponse(ctx, requester, responder); err != nil {
			return nil, err
		}
	}

	return responder, nil
}
