package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"authelia.com/provider/oauth2/internal/consts"
)

func (f *Fosite) WriteRFC8628UserAuthorizeResponse(_ context.Context, rw http.ResponseWriter, _ DeviceAuthorizeRequester, responder RFC8628UserAuthorizeResponder) {
	wh := rw.Header()
	rh := responder.GetHeader()
	for k := range rh {
		wh.Set(k, rh.Get(k))
	}

	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)
	rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)

	js, err := json.Marshal(responder.ToMap())
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = rw.Write(js)
}

func (f *Fosite) WriteRFC8628UserAuthorizeError(ctx context.Context, rw http.ResponseWriter, req DeviceAuthorizeRequester, err error) {
	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)
	rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)

	sendDebugMessagesToClients := f.Config.GetSendDebugMessagesToClients(ctx)
	rfcerr := ErrorToRFC6749Error(err).WithExposeDebug(sendDebugMessagesToClients).WithLocalizer(f.Config.GetMessageCatalog(ctx), getLangFromRequester(req))

	js, err := json.Marshal(rfcerr)
	if err != nil {
		if f.Config.GetSendDebugMessagesToClients(ctx) {
			errorMessage := EscapeJSONString(err.Error())
			http.Error(rw, fmt.Sprintf(`{"error":"server_error","error_description":"%s"}`, errorMessage), http.StatusInternalServerError)
		} else {
			http.Error(rw, `{"error":"server_error"}`, http.StatusInternalServerError)
		}
		return
	}

	rw.WriteHeader(rfcerr.CodeField)
	_, _ = rw.Write(js)
}
