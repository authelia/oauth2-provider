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
// non-nil its language preference is used to localize the error description. An access_denied error is written with
// HTTP 400, as section 5.2 requires for every error other than invalid_client.
func (f *Fosite) WriteAccessError(ctx context.Context, rw http.ResponseWriter, request AccessRequester, err error) {
	if rfc := ErrorToRFC6749Error(err); rfc.ErrorField == errAccessDeniedName && rfc.CodeField == http.StatusForbidden {
		err = rfc.WithCode(http.StatusBadRequest)
	}

	if f.isErrUseDPoPNonce(ctx, err) {
		f.writeErrorDPoPJSON(ctx, rw, request, err)
	} else {
		f.writeErrorJSON(ctx, rw, request, err)
	}
}

func (f *Fosite) isErrUseDPoPNonce(ctx context.Context, err error) (is bool) {
	return f.Config.GetDPoPEnabled(ctx) && ErrorToRFC6749Error(err).ErrorField == errUseDPoPNonceName
}

func (f *Fosite) writeErrorDPoPJSON(ctx context.Context, rw http.ResponseWriter, request AccessRequester, err error) {
	strategy := f.Config.GetDPoPStrategy(ctx)
	if strategy == nil {
		f.writeErrorJSON(ctx, rw, request, err)

		return
	}

	nonce, nonceErr := strategy.NewDPoPNonce(ctx)
	if nonceErr != nil {
		f.writeErrorJSON(ctx, rw, request, nonceErr)

		return
	}

	rw.Header().Set(consts.HeaderDPoPNonce, nonce)

	f.writeErrorJSON(ctx, rw, request, err)
}

func (f *Fosite) writeErrorJSON(ctx context.Context, rw http.ResponseWriter, request AccessRequester, err error) {
	rfc := ErrorToRFC6749Error(err)

	if request != nil {
		rfc = rfc.WithLocalizer(f.Config.GetMessageCatalog(ctx), getLangFromRequester(request))
	}

	f.writeErrorJSONRFC(ctx, rw, rfc)
}

func (f *Fosite) writeErrorJSONRFC(ctx context.Context, rw http.ResponseWriter, rfc *RFC6749Error) {
	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)
	rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)

	setClientAuthenticationChallenge(rw, rfc)

	rfc = rfc.WithLegacyFormat(f.Config.GetUseLegacyErrorFormat(ctx)).WithExposeDebug(f.Config.GetSendDebugMessagesToClients(ctx))

	data, err := json.Marshal(rfc)
	if err != nil {
		f.writeFallbackJSONError(ctx, rw, err)

		return
	}

	rw.WriteHeader(rfc.CodeField)
	_, _ = rw.Write(data)
}
