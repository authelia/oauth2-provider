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
// r is the request being answered and may be nil. A request which included no access token is answered with HTTP 401
// and the 'WWW-Authenticate' challenge alone, without a body (RFC 6750 Section 3.1). Without r the challenge omits the
// RFC 9728 Section 5.1 'resource_metadata' parameter and the body is written.
//
// See: https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.2
func (f *Fosite) WriteRFC7591ClientRegistrationError(ctx context.Context, rw http.ResponseWriter, r *http.Request, requester ClientRegistrationRequester, err error) {
	f.writeClientRegistrationError(ctx, rw, r, requester, err, false)
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
// RFC 7592 client configuration endpoint. r and requester may be nil.
//
// When configuration is true an ErrInvalidRequest is written as 405 (RFC 7592 Section 3, unsupported method) and a
// 401 carries the Bearer challenge alone, as a registration access token can never be DPoP bound. Otherwise the
// challenge is the one WriteBearerAuthorizationChallenge composes. Either carries the RFC 9728 Section 5.1
// 'resource_metadata' parameter only when r is not nil. When r included no token the 401 carries the challenge alone,
// without a body (RFC 6750 Section 3.1).
func (f *Fosite) writeClientRegistrationError(ctx context.Context, rw http.ResponseWriter, r *http.Request, requester Requester, err error, configuration bool) {
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
			rw.Header().Set(consts.HeaderWWWAuthenticate, f.clientConfigurationChallenge(ctx, r))

			if r != nil && len(presentedSchemes(authorizationHeaderSchemes(r), false)) == 0 {
				writeBareAuthorizationChallenge(rw)

				return
			}
		}
	case IsBearerCredentialError(err):
		var bare bool

		// Without the request the challenge is composed for an unestablished scheme, which RFC 9449 Section 7.2
		// Figure 19 covers.
		if rfc, bare = f.writeBearerAuthorizationChallenge(ctx, rw, r, rfc); bare {
			writeBareAuthorizationChallenge(rw)

			return
		}
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

// clientConfigurationChallenge returns the Bearer challenge of the RFC 7592 client configuration endpoint, with the
// RFC 9728 Section 5.1 'resource_metadata' parameter when the Configurator locates the metadata for r.
func (f *Fosite) clientConfigurationChallenge(ctx context.Context, r *http.Request) (value string) {
	provider, ok := f.Config.(ProtectedResourceMetadataURLProvider)
	if !ok || r == nil {
		return consts.AuthSchemeBearer
	}

	location := provider.GetProtectedResourceMetadataURL(ctx, r)
	if location == "" {
		return consts.AuthSchemeBearer
	}

	return consts.AuthSchemeBearer + " " + consts.ChallengeParameterResourceMetadata + "=" + challengeQuotedString(location)
}
