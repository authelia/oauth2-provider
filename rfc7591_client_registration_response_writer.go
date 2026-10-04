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
// When configuration is true an ErrInvalidRequest is written as 405 (RFC 7592 Section 3, unsupported method) and a
// 401 carries the bare Bearer challenge, as a registration access token can never be DPoP bound. Otherwise the
// challenge is the one WriteBearerAuthorizationChallenge composes.
func (f *Fosite) writeClientRegistrationError(ctx context.Context, rw http.ResponseWriter, requester Requester, err error, configuration bool) {
	rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)
	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)

	rfc := ErrorToRFC6749Error(err).WithLegacyFormat(f.Config.GetUseLegacyErrorFormat(ctx)).
		WithExposeDebug(f.Config.GetSendDebugMessagesToClients(ctx)).WithLocalizer(f.Config.GetMessageCatalog(ctx), getLangFromRequester(requester))

	if configuration && rfc.ErrorField == ErrInvalidRequest.ErrorField {
		rfc = rfc.WithCode(http.StatusMethodNotAllowed)

		// RFC 9110 Section 15.5.6 requires a 405 to name the methods the target resource does support.
		rw.Header().Set(consts.HeaderAllow, clientConfigurationAllowedMethods)
	}

	switch {
	case configuration:
		// RFC 7592 Section 3: a missing or invalid registration access token is reported with a 401 status and a
		// 'WWW-Authenticate' header, as for any other bearer token protected resource (RFC 6750 Section 3).
		if rfc.CodeField == http.StatusUnauthorized {
			rw.Header().Set(consts.HeaderWWWAuthenticate, consts.AuthSchemeBearer)
		}
	case IsBearerCredentialError(err):
		// The request is not available here - WriteRFC7591ClientRegistrationError is public API taking only a
		// context - so the challenge is composed for an unestablished scheme, which RFC 9449 Section 7.2 Figure 19
		// covers.
		rfc = f.WriteBearerAuthorizationChallenge(ctx, rw, nil, rfc)
	}

	data, merr := json.Marshal(rfc)
	if merr != nil {
		f.writeFallbackJSONError(ctx, rw, merr)

		return
	}

	rw.WriteHeader(rfc.CodeField)
	_, _ = rw.Write(data)
}

const clientConfigurationAllowedMethods = http.MethodGet + ", " + http.MethodPut + ", " + http.MethodDelete
