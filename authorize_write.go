// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"

	"authelia.com/provider/oauth2/internal/consts"
)

func (f *Fosite) WriteAuthorizeResponse(ctx context.Context, rw http.ResponseWriter, requester AuthorizeRequester, responder AuthorizeResponder) {
	for _, handler := range f.ResponseModeHandlers(ctx) {
		if handler.ResponseModes().Has(requester.GetResponseMode()) {
			handler.WriteAuthorizeResponse(ctx, rw, requester, responder)

			return
		}
	}

	f.handleWriteAuthorizeErrorJSON(ctx, rw, ErrServerError.WithHint("The Authorization Server was unable to process the requested Response Mode."))
}

// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
// When a decision is established, the authorization server directs the
// user-agent to the provided client redirection URI using an HTTP
// redirection response, or by other means available to it via the
// user-agent.
func sendRedirect(url string, rw http.ResponseWriter) {
	rw.Header().Set(consts.HeaderLocation, url)
	rw.WriteHeader(http.StatusSeeOther)
}
