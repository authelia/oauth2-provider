// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"net/http"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// NewPushedAuthorizeResponse executes the handlers and builds the response
func (f *Fosite) NewPushedAuthorizeResponse(ctx context.Context, request AuthorizeRequester, session Session) (responder PushedAuthorizeResponder, err error) {
	// Get handlers. If no handlers are defined, this is considered a misconfigured Fosite instance.
	provider, ok := f.Config.(PushedAuthorizeRequestHandlersProvider)
	if !ok {
		return nil, errorsx.WithStack(ErrServerError.WithHint(ErrorPARNotSupported).WithDebug(DebugPARRequestsHandlerMissing))
	}

	var response = &PushedAuthorizeResponse{
		Header: http.Header{},
		Extra:  map[string]any{},
	}

	ctx = context.WithValue(ctx, AuthorizeRequestContextKey, request)
	ctx = context.WithValue(ctx, PushedAuthorizeResponseContextKey, response)

	request.SetSession(session)

	for _, h := range provider.GetPushedAuthorizeEndpointHandlers(ctx) {
		if err = h.HandlePushedAuthorizeEndpointRequest(ctx, request, response); err != nil {
			return nil, err
		}
	}

	return response, nil
}

// WritePushedAuthorizeResponse writes the PAR response
func (f *Fosite) WritePushedAuthorizeResponse(ctx context.Context, rw http.ResponseWriter, request AuthorizeRequester, response PushedAuthorizeResponder) {
	headers := response.GetHeader()
	for header := range headers {
		rw.Header().Set(header, headers.Get(header))
	}

	rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)
	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)

	var (
		data []byte
		err  error
	)

	if data, err = json.Marshal(response.ToMap()); err != nil {
		f.writeFallbackJSONError(ctx, rw, err)

		return
	}

	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)

	rw.WriteHeader(http.StatusCreated)
	_, _ = rw.Write(data)
}

// WritePushedAuthorizeError writes the PAR error
func (f *Fosite) WritePushedAuthorizeError(ctx context.Context, rw http.ResponseWriter, request AuthorizeRequester, err error) {
	rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)
	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)

	// RFC 9449 Section 8: a nonce is demanded with the 'use_dpop_nonce' error, and the nonce to retry with is supplied
	// in the DPoP-Nonce header. Without it a client that presented a proof to this endpoint while nonces are required
	// has no way to learn the value it must include, so the request could never succeed.
	if f.isErrUseDPoPNonce(ctx, err) {
		if strategy := f.Config.GetDPoPStrategy(ctx); strategy != nil {
			if nonce, nonceErr := strategy.NewDPoPNonce(ctx); nonceErr == nil {
				rw.Header().Set(consts.HeaderDPoPNonce, nonce)
			}
		}
	}

	rfcerr := ErrorToRFC6749Error(err).WithLegacyFormat(f.Config.GetUseLegacyErrorFormat(ctx)).
		WithExposeDebug(f.Config.GetSendDebugMessagesToClients(ctx)).WithLocalizer(f.Config.GetMessageCatalog(ctx), getLangFromRequester(request))

	var data []byte

	if data, err = json.Marshal(rfcerr); err != nil {
		f.writeFallbackJSONError(ctx, rw, err)

		return
	}

	rw.WriteHeader(rfcerr.CodeField)
	_, _ = rw.Write(data)
}
