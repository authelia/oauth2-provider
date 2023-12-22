// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/errorsx"
)

// NewPushedAuthorizeResponse executes the handlers and builds the response
func (f *Fosite) NewPushedAuthorizeResponse(ctx context.Context, requester AuthorizeRequester, session Session) (responder PushedAuthorizeResponder, err error) {
	// Get handlers. If no handlers are defined, this is considered a misconfigured Fosite instance.
	provider, ok := f.Config.(PushedAuthorizeRequestHandlersProvider)
	if !ok {
		return nil, errorsx.WithStack(ErrServerError.WithHint(ErrorPARNotSupported).WithDebug(DebugPARRequestsHandlerMissing))
	}

	var response = &PushedAuthorizeResponse{
		Header: http.Header{},
		Extra:  map[string]any{},
	}

	ctx = context.WithValue(ctx, AuthorizeRequestContextKey, requester)
	ctx = context.WithValue(ctx, PushedAuthorizeResponseContextKey, response)

	requester.SetSession(session)

	for _, h := range provider.GetPushedAuthorizeEndpointHandlers(ctx) {
		if err = h.HandlePushedAuthorizeEndpointRequest(ctx, requester, response); err != nil {
			return nil, err
		}
	}

	return response, nil
}

// WritePushedAuthorizeResponse writes the PAR response
func (f *Fosite) WritePushedAuthorizeResponse(ctx context.Context, rw http.ResponseWriter, requester AuthorizeRequester, responder PushedAuthorizeResponder) {
	// Set custom headers, e.g. "X-MySuperCoolCustomHeader" or "X-DONT-CACHE-ME"...
	wh := rw.Header()
	rh := responder.GetHeader()
	for k := range rh {
		wh.Set(k, rh.Get(k))
	}

	wh.Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	wh.Set(consts.HeaderPragma, consts.PragmaNoCache)
	wh.Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)

	js, err := json.Marshal(responder.ToMap())
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)

	rw.WriteHeader(http.StatusCreated)
	_, _ = rw.Write(js)
}

// WritePushedAuthorizeError writes the PAR error
func (f *Fosite) WritePushedAuthorizeError(ctx context.Context, rw http.ResponseWriter, requester AuthorizeRequester, err error) {
	rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)
	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)

	sendDebugMessagesToClient := f.Config.GetSendDebugMessagesToClients(ctx)
	rfcerr := ErrorToRFC6749Error(err).WithLegacyFormat(f.Config.GetUseLegacyErrorFormat(ctx)).
		WithExposeDebug(sendDebugMessagesToClient).WithLocalizer(f.Config.GetMessageCatalog(ctx), getLangFromRequester(requester))

	js, err := json.Marshal(rfcerr)
	if err != nil {
		if sendDebugMessagesToClient {
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
