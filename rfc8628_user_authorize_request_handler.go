// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"

	"authelia.com/provider/oauth2/i18n"
	"authelia.com/provider/oauth2/internal/reflection"
	"authelia.com/provider/oauth2/x/errorsx"
)

// NewRFC8628UserAuthorizeRequest parses the user-facing device authorization request and dispatches it to each
// configured RFC8628UserAuthorizeEndpointHandler. The returned DeviceAuthorizeRequester reflects the user's
// authorization decision (approval, denial, or pending) as recorded by the handlers. The handlers read a copy of the
// form of r, which is left as parsed. The session must not be nil; it is the session the stored device authorization
// request is hydrated into. Unless RFC8628UserCodeSubjectBindingProvider disables it, the session must implement
// RFC8628UserCodeBindingSession and identify the authenticated End-User presenting the user code, which is read before
// the stored session replaces it and is the End-User an undecided user code is bound to. The approval session given to
// NewRFC8628UserAuthorizeResponse must identify the same End-User. An error for a user code which is not accepted
// wraps ErrUserCodeUnknown, ErrUserCodeExpired, ErrUserCodeDecided or ErrUserCodeClaimed. A single-valued parameter
// included more than once in the query or in the body is refused with ErrInvalidRequest; one included once in each is
// read from the body.
func (f *Fosite) NewRFC8628UserAuthorizeRequest(ctx context.Context, r *http.Request, session Session) (requester DeviceAuthorizeRequester, err error) {
	request := NewDeviceAuthorizeRequest()
	request.Lang = i18n.GetLangFromRequest(f.Config.GetMessageCatalog(ctx), r)

	if err = r.ParseForm(); err != nil {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body.").WithWrap(err).WithDebugError(err))
	}

	if err = validateRequestQueryAndBodyParametersNotRepeated(r); err != nil {
		return nil, err
	}

	request.Form = make(url.Values, len(r.Form))

	for key, values := range r.Form {
		request.Form[key] = slices.Clone(values)
	}

	if reflection.IsNil(session) {
		return nil, errors.New("Session must not be nil")
	}

	request.SetSession(session)

	ctx = context.WithValue(ctx, RequestContextKey, r)

	for _, h := range f.Config.GetRFC8628UserAuthorizeEndpointHandlers(ctx) {
		if err = h.HandleRFC8628UserAuthorizeEndpointRequest(ctx, request); err != nil && !errors.Is(err, ErrUnknownRequest) {
			return nil, err
		}
	}

	return request, nil
}
