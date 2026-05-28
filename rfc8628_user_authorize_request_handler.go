// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"errors"
	"net/http"

	"authelia.com/provider/oauth2/i18n"
	"authelia.com/provider/oauth2/x/errorsx"
)

// NewRFC8628UserAuthorizeRequest parses the user-facing device authorization request and dispatches it to each
// configured RFC8628UserAuthorizeEndpointHandler. The returned DeviceAuthorizeRequester reflects the user's
// authorization decision (approval, denial, or pending) as recorded by the handlers.
func (f *Fosite) NewRFC8628UserAuthorizeRequest(ctx context.Context, r *http.Request) (requester DeviceAuthorizeRequester, err error) {
	request := NewDeviceAuthorizeRequest()
	request.Lang = i18n.GetLangFromRequest(f.Config.GetMessageCatalog(ctx), r)

	if err = r.ParseMultipartForm(1 << 20); err != nil && err != http.ErrNotMultipart {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body.").WithWrap(err).WithDebugError(err))
	}

	request.Form = r.Form

	for _, h := range f.Config.GetRFC8628UserAuthorizeEndpointHandlers(ctx) {
		if err = h.HandleRFC8628UserAuthorizeEndpointRequest(ctx, request); err != nil && !errors.Is(err, ErrUnknownRequest) {
			return nil, err
		}
	}

	return request, nil
}
