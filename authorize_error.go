// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"authelia.com/provider/oauth2/internal/consts"
)

func (f *Fosite) WriteAuthorizeError(ctx context.Context, rw http.ResponseWriter, requester AuthorizeRequester, err error) {
	rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)

	for _, handler := range f.ResponseModeHandlers(ctx) {
		if handler.ResponseModes().Has(requester.GetResponseMode()) {
			handler.WriteAuthorizeError(ctx, rw, requester, err)

			return
		}
	}

	f.handleWriteAuthorizeErrorJSON(ctx, rw, ErrServerError.WithHint("The Authorization Server was unable to process the requested Response Mode."))
}

func (f *Fosite) handleWriteAuthorizeErrorJSON(ctx context.Context, rw http.ResponseWriter, rfc *RFC6749Error) {
	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)

	var (
		data []byte
		err  error
	)

	if data, err = json.Marshal(rfc); err != nil {
		if f.Config.GetSendDebugMessagesToClients(ctx) {
			errorMessage := EscapeJSONString(err.Error())
			http.Error(rw, fmt.Sprintf(`{"error":"server_error","error_description":"%s"}`, errorMessage), http.StatusInternalServerError)
		} else {
			http.Error(rw, `{"error":"server_error"}`, http.StatusInternalServerError)
		}

		return
	}

	rw.WriteHeader(rfc.CodeField)
	_, _ = rw.Write(data)
}
