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

// WriteRFC862DeviceAuthorizeResponse writes a successful RFC 8628 device authorization endpoint response as JSON with
// the cache-control headers mandated by the specification. Any headers attached to the responder are copied to the
// HTTP response.
func (f *Fosite) WriteRFC862DeviceAuthorizeResponse(ctx context.Context, rw http.ResponseWriter, _ DeviceAuthorizeRequester, responder DeviceAuthorizeResponder) {
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
