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

// WriteRFC7592ClientConfigurationResponse writes the client configuration response. A 204 status - written for a
// successful DELETE - carries no body at all, not '{}'.
//
// See: https://datatracker.ietf.org/doc/html/rfc7592#section-2.3
func (f *Fosite) WriteRFC7592ClientConfigurationResponse(ctx context.Context, rw http.ResponseWriter, requester ClientConfigurationRequester, responder ClientConfigurationResponder) {
	f.writeClientRegistrationResponse(ctx, rw, responder)
}

// WriteRFC7592ClientConfigurationError writes a client configuration endpoint error response.
//
// It reports 401 with a 'WWW-Authenticate: Bearer' header for a missing or invalid registration access token, 404 for
// an unknown client_id, and 405 for a method other than GET, PUT, or DELETE. A valid token not authorized for the
// target client is reported as 401 rather than 403 by DefaultEndpointAuthStrategy (handler/rfc7591), so the status
// code does not distinguish it from an unknown token.
//
// See: https://datatracker.ietf.org/doc/html/rfc7592#section-3
func (f *Fosite) WriteRFC7592ClientConfigurationError(ctx context.Context, rw http.ResponseWriter, requester ClientConfigurationRequester, err error) {
	f.writeClientRegistrationError(ctx, rw, requester, err, true)
}
