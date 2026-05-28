// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"
)

// WriteAuthorizeResponse writes a successful authorization endpoint response by dispatching to the configured
// ResponseModeHandler that supports the request's response_mode. If no handler matches, an internal server error is
// written instead.
func (f *Fosite) WriteAuthorizeResponse(ctx context.Context, rw http.ResponseWriter, request AuthorizeRequester, response AuthorizeResponder) {
	for _, handler := range f.Config.GetResponseModeHandlers(ctx) {
		if handler.ResponseModes().Has(request.GetResponseMode()) {
			handler.WriteAuthorizeResponse(ctx, rw, request, response)

			return
		}
	}

	f.handleWriteAuthorizeErrorFieldResponse(ctx, rw, request, ErrServerError.WithHint("The Authorization Server was unable to process the requested Response Mode."))
}
