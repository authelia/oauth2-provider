// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"authelia.com/provider/oauth2/internal/consts"
)

func (f *Fosite) WriteAccessError(ctx context.Context, rw http.ResponseWriter, request AccessRequester, err error) {
	f.writeJsonError(ctx, rw, request, err)
}

func (f *Fosite) writeJsonError(ctx context.Context, rw http.ResponseWriter, request AccessRequester, err error) {
	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)
	rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)

	rfc := ErrorToRFC6749Error(err).WithLegacyFormat(f.Config.GetUseLegacyErrorFormat(ctx)).WithExposeDebug(f.Config.GetSendDebugMessagesToClients(ctx))

	if request != nil {
		rfc = rfc.WithLocalizer(f.Config.GetMessageCatalog(ctx), getLangFromRequester(request))
	}

	js, err := json.Marshal(rfc)
	if err != nil {
		if f.Config.GetSendDebugMessagesToClients(ctx) {
			errorMessage := EscapeJSONString(err.Error())
			http.Error(rw, fmt.Sprintf(`{"error":"server_error","error_description":"%s"}`, errorMessage), http.StatusInternalServerError)
		} else {
			http.Error(rw, `{"error":"server_error"}`, http.StatusInternalServerError)
		}
		return
	}

	rw.WriteHeader(rfc.CodeField)
	// ignoring the error because the connection is broken when it happens
	_, _ = rw.Write(js)
}
