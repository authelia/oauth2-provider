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

// WriteRFC8628UserAuthorizeResponse writes a successful user-facing device authorization response as JSON with the
// cache-control headers required by RFC 8628.
func (f *Fosite) WriteRFC8628UserAuthorizeResponse(ctx context.Context, rw http.ResponseWriter, _ DeviceAuthorizeRequester, responder DeviceUserAuthorizeResponder) {
	headers := responder.GetHeader()

	for header := range headers {
		rw.Header().Set(header, headers.Get(header))
	}

	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)
	rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)

	var (
		data []byte
		err  error
	)

	if data, err = json.Marshal(responder.ToMap()); err != nil {
		f.writeFallbackJSONError(ctx, rw, err)

		return
	}

	_, _ = rw.Write(data)
}

// WriteRFC8628UserAuthorizeError writes an error response for the user-facing device authorization endpoint as JSON.
// Debug information is included only when the provider is configured to send debug messages to clients.
func (f *Fosite) WriteRFC8628UserAuthorizeError(ctx context.Context, rw http.ResponseWriter, req DeviceAuthorizeRequester, err error) {
	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)
	rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)

	rfcerr := ErrorToRFC6749Error(err).WithExposeDebug(f.Config.GetSendDebugMessagesToClients(ctx)).WithLocalizer(f.Config.GetMessageCatalog(ctx), getLangFromRequester(req))

	var data []byte

	if data, err = json.Marshal(rfcerr); err != nil {
		f.writeFallbackJSONError(ctx, rw, err)

		return
	}

	rw.WriteHeader(rfcerr.CodeField)
	_, _ = rw.Write(data)
}
