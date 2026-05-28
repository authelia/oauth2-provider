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

// WriteAuthorizeError writes an error response for the authorization endpoint. The configured ResponseModeHandlers are
// consulted first so the error can be delivered using the requested response_mode (query, fragment, form_post, etc.).
// If no handler matches, the error is written as JSON to rw using the configured AuthorizeErrorFieldResponseStrategy.
func (f *Fosite) WriteAuthorizeError(ctx context.Context, rw http.ResponseWriter, request AuthorizeRequester, err error) {
	rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)

	for _, handler := range f.Config.GetResponseModeHandlers(ctx) {
		if handler.ResponseModes().Has(request.GetResponseMode()) {
			handler.WriteAuthorizeError(ctx, rw, request, err)

			return
		}
	}

	f.handleWriteAuthorizeErrorFieldResponse(ctx, rw, request, ErrServerError.WithHint("The Authorization Server was unable to process the requested Response Mode."))
}

func (f *Fosite) handleWriteAuthorizeErrorFieldResponse(ctx context.Context, rw http.ResponseWriter, request AuthorizeRequester, rfc *RFC6749Error) {
	if strategy := f.Config.GetAuthorizeErrorFieldResponseStrategy(ctx); strategy != nil {
		strategy.WriteErrorFieldResponse(ctx, rw, request, rfc)
	} else {
		f.handleWriteAuthorizeErrorFieldResponseJSON(ctx, rw, rfc)
	}
}

func (f *Fosite) handleWriteAuthorizeErrorFieldResponseJSON(ctx context.Context, rw http.ResponseWriter, rfc *RFC6749Error) {
	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)

	var (
		data []byte
		err  error
	)

	if data, err = json.Marshal(rfc); err != nil {
		f.writeFallbackJSONError(ctx, rw, err)

		return
	}

	rw.WriteHeader(rfc.CodeField)
	_, _ = rw.Write(data)
}

type AuthorizeErrorFieldResponseStrategy interface {
	WriteErrorFieldResponse(ctx context.Context, rw http.ResponseWriter, request AuthorizeRequester, rfc *RFC6749Error)
}

type JSONAuthorizeErrorFieldResponseStrategy struct {
	Config SendDebugMessagesToClientsProvider
}

// WriteErrorFieldResponse serializes the given RFC 6749 error as a JSON body and writes it to rw using the error's
// status code. This is the default strategy used by Fosite.WriteAuthorizeError when no response_mode handler matches.
func (s *JSONAuthorizeErrorFieldResponseStrategy) WriteErrorFieldResponse(ctx context.Context, rw http.ResponseWriter, request AuthorizeRequester, rfc *RFC6749Error) {
	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)

	var (
		data []byte
		err  error
	)

	if data, err = json.Marshal(rfc); err != nil {
		writeFallbackJSONError(ctx, s.Config, rw, err)

		return
	}

	rw.WriteHeader(rfc.CodeField)
	_, _ = rw.Write(data)
}
