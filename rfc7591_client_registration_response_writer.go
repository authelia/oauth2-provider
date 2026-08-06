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

// NewRFC7591ClientRegistrationResponse executes the configured client registration endpoint handlers and builds the
// response.
//
// See: https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.1
func (f *Fosite) NewRFC7591ClientRegistrationResponse(ctx context.Context, requester ClientRegistrationRequester) (responder ClientRegistrationResponder, err error) {
	response := NewClientRegistrationResponse()

	for _, h := range f.Config.GetRFC7591ClientRegistrationEndpointHandlers(ctx) {
		if err = h.HandleRFC7591ClientRegistrationEndpointRequest(ctx, requester, response); err != nil {
			return nil, err
		}
	}

	return response, nil
}

// WriteRFC7591ClientRegistrationResponse writes the client registration response.
//
// See: https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.1
func (f *Fosite) WriteRFC7591ClientRegistrationResponse(ctx context.Context, rw http.ResponseWriter, requester ClientRegistrationRequester, responder ClientRegistrationResponder) {
	f.writeClientRegistrationResponse(ctx, rw, responder)
}

// WriteRFC7591ClientRegistrationError writes a client registration endpoint error response.
//
// See: https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.2
func (f *Fosite) WriteRFC7591ClientRegistrationError(ctx context.Context, rw http.ResponseWriter, requester ClientRegistrationRequester, err error) {
	f.writeClientRegistrationError(ctx, rw, requester, err, false)
}

// writeClientRegistrationResponse writes a successful ClientRegistrationResponder, shared by the RFC 7591 client
// registration endpoint and the RFC 7592 client configuration endpoint since both return the same wire format (see
// ClientConfigurationResponder's doc comment). It marshals responder.ToMap() to JSON, sets the standard headers, and
// copies any additional headers set on the responder. A 204 status - written by the RFC 7592 client configuration
// endpoint's DELETE case - writes no body at all, not '{}'.
func (f *Fosite) writeClientRegistrationResponse(ctx context.Context, rw http.ResponseWriter, responder ClientRegistrationResponder) {
	headers := responder.GetHeader()
	for header := range headers {
		rw.Header().Set(header, headers.Get(header))
	}

	rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)
	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)

	code := responder.GetStatusCode()

	if code == http.StatusNoContent {
		rw.WriteHeader(code)

		return
	}

	data, err := json.Marshal(responder.ToMap())
	if err != nil {
		f.writeFallbackJSONError(ctx, rw, err)

		return
	}

	rw.WriteHeader(code)
	_, _ = rw.Write(data)
}

// writeClientRegistrationError writes an error response shared by the RFC 7591 client registration endpoint and the
// RFC 7592 client configuration endpoint. requester may be nil.
//
// mapMethodNotAllowed maps an ErrInvalidRequest to 405 rather than its usual 400. It is used by the RFC 7592 client
// configuration endpoint only: HandleRFC7592ClientConfigurationEndpointRequest (handler/rfc7591) returns
// ErrInvalidRequest naming the method when requester.GetMethod() is not GET, PUT, or DELETE, and RFC 7592 Section 3
// requires that be reported as 405, a status ErrInvalidRequest does not otherwise carry. The client registration
// endpoint only ever accepts POST, so an analogous method mismatch there is reported as the ordinary 400 - the same
// treatment NewPushedAuthorizeRequest gives a non-POST pushed authorization request.
func (f *Fosite) writeClientRegistrationError(ctx context.Context, rw http.ResponseWriter, requester Requester, err error, mapMethodNotAllowed bool) {
	rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)
	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)

	rfc := ErrorToRFC6749Error(err).WithLegacyFormat(f.Config.GetUseLegacyErrorFormat(ctx)).
		WithExposeDebug(f.Config.GetSendDebugMessagesToClients(ctx)).WithLocalizer(f.Config.GetMessageCatalog(ctx), getLangFromRequester(requester))

	if mapMethodNotAllowed && rfc.ErrorField == ErrInvalidRequest.ErrorField {
		rfc.CodeField = http.StatusMethodNotAllowed
	}

	// RFC 7592 Section 3: a missing or invalid registration access token is reported with a 401 status and a
	// 'WWW-Authenticate' header, as for any other bearer token protected resource (RFC 6750 Section 3).
	if rfc.CodeField == http.StatusUnauthorized {
		rw.Header().Set(consts.HeaderWWWAuthenticate, consts.AuthSchemeBearer)
	}

	data, merr := json.Marshal(rfc)
	if merr != nil {
		f.writeFallbackJSONError(ctx, rw, merr)

		return
	}

	rw.WriteHeader(rfc.CodeField)
	_, _ = rw.Write(data)
}
