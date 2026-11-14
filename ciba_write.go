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

// WriteBackChannelAuthenticationResponse writes the successful authentication request acknowledgement as JSON. A
// request bound to a DPoP key is sent a fresh DPoP-Nonce when nonces are required, as at the token endpoint.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.3
// See: https://www.rfc-editor.org/rfc/rfc9449#section-8
func (f *Fosite) WriteBackChannelAuthenticationResponse(ctx context.Context, rw http.ResponseWriter, request BackChannelAuthenticationRequester, response BackChannelAuthenticationResponder) {
	data, err := json.Marshal(response.ToMap())
	if err != nil {
		f.writeFallbackJSONError(ctx, rw, err)

		return
	}

	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)
	rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)

	f.writeDPoPNonceOnSuccess(ctx, rw, request)

	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write(data)
}

// WriteBackChannelAuthenticationError writes an authentication error response as JSON. The status is 401 with the
// client authentication challenge for invalid_client, 403 for access_denied and the status of the error otherwise.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.13
func (f *Fosite) WriteBackChannelAuthenticationError(ctx context.Context, rw http.ResponseWriter, request BackChannelAuthenticationRequester, err error) {
	rfc := ErrorToRFC6749Error(err)

	switch rfc.ErrorField {
	case errInvalidClientName:
		rfc = rfc.WithCode(http.StatusUnauthorized)
	case errAccessDeniedName:
		rfc = rfc.WithCode(http.StatusForbidden)
	}

	if request != nil {
		rfc = rfc.WithLocalizer(f.Config.GetMessageCatalog(ctx), getLangFromRequester(request))
	}

	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)
	rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)

	// The 'use_dpop_nonce' error carries the nonce to retry with in the DPoP-Nonce header.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9449#section-8
	if f.isErrUseDPoPNonce(ctx, err) {
		if strategy := f.Config.GetDPoPStrategy(ctx); strategy != nil {
			if nonce, nonceErr := strategy.NewDPoPNonce(ctx); nonceErr == nil {
				rw.Header().Set(consts.HeaderDPoPNonce, nonce)
			}
		}
	}

	setClientAuthenticationChallenge(rw, rfc)

	rfc = rfc.WithLegacyFormat(f.Config.GetUseLegacyErrorFormat(ctx)).WithExposeDebug(f.Config.GetSendDebugMessagesToClients(ctx))

	data, merr := marshalSanitizedErrorJSON(rfc)
	if merr != nil {
		f.writeFallbackJSONError(ctx, rw, merr)

		return
	}

	rw.WriteHeader(rfc.CodeField)
	_, _ = rw.Write(data)
}

// marshalSanitizedErrorJSON encodes the error and restricts its descriptive members to the 'error_description'
// character set, which excludes '"' and '\\'.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-5.2
func marshalSanitizedErrorJSON(rfc *RFC6749Error) (data []byte, err error) {
	if data, err = json.Marshal(rfc); err != nil {
		return nil, err
	}

	members := map[string]any{}

	if err = json.Unmarshal(data, &members); err != nil {
		return nil, err
	}

	for _, key := range []string{"error_description", "error_hint", "error_debug"} {
		if value, ok := members[key].(string); ok {
			members[key] = sanitizeErrorDescription(value)
		}
	}

	return json.Marshal(members)
}
