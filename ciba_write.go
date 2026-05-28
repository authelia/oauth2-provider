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

// WriteOpenIDCIBAResponse writes a successful OpenID Connect CIBA backchannel authentication response as JSON per
// Section 7.3 of the specification, with the cache-control headers mandated for token-like responses.
func (f *Fosite) WriteOpenIDCIBAResponse(ctx context.Context, rw http.ResponseWriter, _ CIBARequester, responder CIBAResponder) {
	headers := responder.GetHeader()
	for header := range headers {
		rw.Header().Set(header, headers.Get(header))
	}

	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)
	rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)

	data, err := json.Marshal(responder.ToMap())
	if err != nil {
		f.writeFallbackJSONError(ctx, rw, err)

		return
	}

	_, _ = rw.Write(data)
}

// WriteOpenIDCIBAError writes an error response for the OpenID Connect CIBA backchannel authentication endpoint as
// JSON per Section 13 of the specification. Debug information is included only when the provider is configured to
// send debug messages to clients.
func (f *Fosite) WriteOpenIDCIBAError(ctx context.Context, rw http.ResponseWriter, request CIBARequester, err error) {
	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)
	rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)

	rfcerr := ErrorToRFC6749Error(err).WithExposeDebug(f.Config.GetSendDebugMessagesToClients(ctx)).WithLocalizer(f.Config.GetMessageCatalog(ctx), getLangFromRequester(request))

	var data []byte

	if data, err = json.Marshal(rfcerr); err != nil {
		f.writeFallbackJSONError(ctx, rw, err)

		return
	}

	rw.WriteHeader(rfcerr.CodeField)
	_, _ = rw.Write(data)
}
