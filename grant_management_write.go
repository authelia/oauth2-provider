// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"net/http"

	"authelia.com/provider/oauth2/i18n"
	"authelia.com/provider/oauth2/internal/consts"
)

// WriteGrantManagementResponse writes the Grant Management API response with 'Cache-Control: no-cache, no-store'. A
// response without a body, such as the 204 of a revoked grant, writes none.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-6.4
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-6.5
func (f *Fosite) WriteGrantManagementResponse(ctx context.Context, rw http.ResponseWriter, requester GrantManagementRequester, responder GrantManagementResponder) {
	rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoCacheNoStore)

	code, body := responder.GetStatusCode(), responder.GetBody()

	if code == http.StatusNoContent || body == nil {
		rw.WriteHeader(code)

		return
	}

	data, err := json.Marshal(body)
	if err != nil {
		f.writeFallbackJSONError(ctx, rw, err)

		return
	}

	rw.Header().Set(consts.HeaderContentType, consts.MediaTypeApplicationJSON)
	rw.WriteHeader(code)
	_, _ = rw.Write(data)
}

// WriteGrantManagementError writes a Grant Management API error. A grant which is not found is a 404 without a body,
// a rejected access token is answered with the RFC 6750 and RFC 9449 challenge due to r, and a 405 names the supported
// methods in the Allow header.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-6.6
// See: https://www.rfc-editor.org/rfc/rfc6750#section-3
func (f *Fosite) WriteGrantManagementError(ctx context.Context, rw http.ResponseWriter, r *http.Request, err error) {
	rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoCacheNoStore)

	var rfc *RFC6749Error

	if IsBearerCredentialError(err) {
		rfc = f.WriteBearerAuthorizationChallenge(ctx, rw, r, err)
	} else {
		rfc = ErrorToRFC6749Error(err)
	}

	switch rfc.CodeField {
	case http.StatusNotFound:
		rw.WriteHeader(http.StatusNotFound)

		return
	case http.StatusMethodNotAllowed:
		allow := http.MethodGet + ", " + http.MethodDelete

		if provider, ok := f.Config.(GrantManagementConfigProvider); ok {
			if config := provider.GetGrantManagementConfig(ctx); config != nil {
				allow = grantManagementAllowedMethods(config)
			}
		}

		rw.Header().Set(consts.HeaderAllow, allow)
	}

	rfc = rfc.WithExposeDebug(f.Config.GetSendDebugMessagesToClients(ctx)).WithLegacyFormat(f.Config.GetUseLegacyErrorFormat(ctx))

	if r != nil {
		catalog := f.Config.GetMessageCatalog(ctx)

		rfc = rfc.WithLocalizer(catalog, i18n.GetLangFromRequest(catalog, r))
	}

	data, merr := json.Marshal(rfc)
	if merr != nil {
		f.writeFallbackJSONError(ctx, rw, merr)

		return
	}

	rw.Header().Set(consts.HeaderContentType, consts.MediaTypeApplicationJSON)
	rw.WriteHeader(rfc.CodeField)
	_, _ = rw.Write(data)
}
