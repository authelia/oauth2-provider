// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"
)

// NewRFC7592ClientConfigurationResponse executes the configured client configuration endpoint handlers and builds
// the response.
//
// See: https://datatracker.ietf.org/doc/html/rfc7592#section-2
func (f *Fosite) NewRFC7592ClientConfigurationResponse(ctx context.Context, requester ClientConfigurationRequester) (responder ClientConfigurationResponder, err error) {
	response := NewClientRegistrationResponse()

	for _, h := range f.Config.GetRFC7592ClientConfigurationEndpointHandlers(ctx) {
		if err = h.HandleRFC7592ClientConfigurationEndpointRequest(ctx, requester, response); err != nil {
			return nil, err
		}
	}

	return response, nil
}

// WriteRFC7592ClientConfigurationResponse writes the client configuration response. A 204 status, written for a
// successful DELETE, carries no body at all, not '{}'.
//
// See: https://datatracker.ietf.org/doc/html/rfc7592#section-2.3
func (f *Fosite) WriteRFC7592ClientConfigurationResponse(ctx context.Context, rw http.ResponseWriter, requester ClientConfigurationRequester, responder ClientConfigurationResponder) {
	f.writeClientRegistrationResponse(ctx, rw, responder)
}

// WriteRFC7592ClientConfigurationError writes a client configuration endpoint error response.
//
// The following specs must be considered in any implementation of this method:
// * https://datatracker.ietf.org/doc/html/rfc7592#section-3
//
//	400 (Bad Request), 401 (Unauthorized), 403 (Forbidden), and 404 (Not Found) status codes are all used, as
//	appropriate, to indicate errors as described in Section 3.2.
//
// This implementation reports 401 (accompanied by a 'WWW-Authenticate: Bearer' header per RFC 6750 Section 3) for a
// missing or invalid registration access token, 404 for an unknown client_id, and 405 for a method other than GET,
// PUT, or DELETE. RFC 7592 also describes 403 for a token that is otherwise valid but not authorized for the target
// client; DefaultEndpointAuthStrategy (handler/rfc7591) reports that case as 401 as well, the same as
// any other authentication failure, so an attacker cannot use the status code to distinguish an unknown token from
// one that is simply not authorized for this client. See that type's doc comment for the rationale.
func (f *Fosite) WriteRFC7592ClientConfigurationError(ctx context.Context, rw http.ResponseWriter, requester ClientConfigurationRequester, err error) {
	f.writeClientRegistrationError(ctx, rw, requester, err, true)
}
