// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"
)

func (f *Fosite) WriteAuthorizeResponse(ctx context.Context, rw http.ResponseWriter, requester AuthorizeRequester, responder AuthorizeResponder) {
	for _, handler := range f.Config.GetResponseModeHandlers(ctx) {
		if handler.ResponseModes().Has(requester.GetResponseMode()) {
			handler.WriteAuthorizeResponse(ctx, rw, requester, responder)

			return
		}
	}

	f.handleWriteAuthorizeErrorFieldResponse(ctx, rw, requester, ErrServerError.WithHint("The Authorization Server was unable to process the requested Response Mode."))
}
