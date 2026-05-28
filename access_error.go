// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"net/http"

	"authelia.com/provider/oauth2/internal/consts"
)

// WriteAccessError writes an error response for the token endpoint per RFC 6749 section 5.2. The response is encoded as
// JSON with cache-control headers set to 'no-store' and 'no-cache' as required by the specification. When request is
// non-nil its language preference is used to localize the error description.
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

	var data []byte

	if data, err = json.Marshal(rfc); err != nil {
		f.writeFallbackJSONError(ctx, rw, err)

		return
	}

	rw.WriteHeader(rfc.CodeField)
	_, _ = rw.Write(data)
}
