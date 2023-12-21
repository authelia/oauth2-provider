// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"authelia.com/provider/oauth2/internal/consts"
)

func (f *Fosite) WriteAuthorizeError(ctx context.Context, rw http.ResponseWriter, ar AuthorizeRequester, err error) {
	rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)

	if f.ResponseModeHandler(ctx).ResponseModes().Has(ar.GetResponseMode()) {
		f.ResponseModeHandler(ctx).WriteAuthorizeError(ctx, rw, ar, err)
		return
	}

	rfc := ErrorToRFC6749Error(err).WithLegacyFormat(f.Config.GetUseLegacyErrorFormat(ctx)).WithExposeDebug(f.Config.GetSendDebugMessagesToClients(ctx)).WithLocalizer(f.Config.GetMessageCatalog(ctx), getLangFromRequester(ar))
	if !ar.IsRedirectURIValid() {
		rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)

		js, err := json.Marshal(rfc)
		if err != nil {
			if f.Config.GetSendDebugMessagesToClients(ctx) {
				errorMessage := EscapeJSONString(err.Error())
				http.Error(rw, fmt.Sprintf(`{"error":"server_error","error_description":"%s"}`, errorMessage), http.StatusInternalServerError)
			} else {
				http.Error(rw, `{"error":"server_error"}`, http.StatusInternalServerError)
			}
			return
		}

		rw.WriteHeader(rfc.CodeField)
		_, _ = rw.Write(js)
		return
	}

	redirectURI := ar.GetRedirectURI()

	// The endpoint URI MUST NOT include a fragment component.
	redirectURI.Fragment = ""

	errors := rfc.ToValues()
	errors.Set(consts.FormParameterState, ar.GetState())

	var redirectURIString string
	if ar.GetResponseMode() == ResponseModeFormPost {
		rw.Header().Set(consts.HeaderContentType, consts.ContentTypeTextHTML)
		WriteAuthorizeFormPostResponse(redirectURI.String(), errors, GetPostFormHTMLTemplate(ctx, f), rw)
		return
	} else if ar.GetResponseMode() == ResponseModeFragment {
		redirectURIString = redirectURI.String() + "#" + errors.Encode()
	} else {
		for key, values := range redirectURI.Query() {
			for _, value := range values {
				errors.Add(key, value)
			}
		}
		redirectURI.RawQuery = errors.Encode()
		redirectURIString = redirectURI.String()
	}

	rw.Header().Set(consts.HeaderLocation, redirectURIString)
	rw.WriteHeader(http.StatusSeeOther)
}
