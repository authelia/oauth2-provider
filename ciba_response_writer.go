// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
)

// NewOpenIDCIBAResponse dispatches the OpenID Connect CIBA backchannel authentication request to each configured
// endpoint handler to issue an auth_req_id, persist the CIBA session, and populate the response with the polling
// interval and expires_in values.
func (f *Fosite) NewOpenIDCIBAResponse(ctx context.Context, request CIBARequester, session Session) (CIBAResponder, error) {
	request.SetSession(session)
	response := NewCIBAResponse()

	for _, h := range f.Config.GetOpenIDCIBAEndpointHandlers(ctx) {
		if err := h.HandleOpenIDCIBAEndpointRequest(ctx, request, response); err != nil {
			return nil, err
		}
	}

	return response, nil
}
