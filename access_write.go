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

// WriteAccessResponse writes the successful token endpoint response per RFC 6749 section 5.1 as JSON with the required
// cache-control headers. Use WriteAccessError to send error responses.
func (f *Fosite) WriteAccessResponse(ctx context.Context, rw http.ResponseWriter, request AccessRequester, response AccessResponder) {
	rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)

	var (
		data []byte
		err  error
	)

	if data, err = json.Marshal(response.ToMap()); err != nil {
		f.writeFallbackJSONError(ctx, rw, err)

		return
	}

	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)

	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write(data)
}
