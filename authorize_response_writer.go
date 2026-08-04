// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"
	"net/url"

	"authelia.com/provider/oauth2/x/errorsx"
)

// NewAuthorizeResponse dispatches the authorize request to each configured AuthorizeEndpointHandler to produce the
// response parameters. Returns ErrUnsupportedResponseType when not every requested response_type was handled, or
// ErrUnsupportedResponseMode if the negotiated response mode would expose tokens via the URL query for a flow that
// defaults to fragment delivery.
func (f *Fosite) NewAuthorizeResponse(ctx context.Context, request AuthorizeRequester, session Session) (responder AuthorizeResponder, err error) {
	var response = &AuthorizeResponse{
		Header:     http.Header{},
		Parameters: url.Values{},
	}

	ctx = context.WithValue(ctx, AuthorizeRequestContextKey, request)
	ctx = context.WithValue(ctx, AuthorizeResponseContextKey, response)

	request.SetSession(session)

	// Binding handlers run first so that a proof-of-possession binding is present on the session before any
	// handler persists a copy of it, which the handlers that issue an authorization code do as they run.
	for _, h := range f.Config.GetAuthorizeEndpointBindingHandlers(ctx) {
		if err = h.BindAuthorizeRequest(ctx, request); err != nil {
			return nil, err
		}
	}

	for _, h := range f.Config.GetAuthorizeEndpointHandlers(ctx) {
		if err = h.HandleAuthorizeEndpointRequest(ctx, request, response); err != nil {
			return nil, err
		}
	}

	if !request.DidHandleAllResponseTypes() {
		return nil, errorsx.WithStack(ErrUnsupportedResponseType)
	}

	if request.GetDefaultResponseMode() == ResponseModeFragment && request.GetResponseMode() == ResponseModeQuery {
		return nil, ErrUnsupportedResponseMode.WithHintf("Insecure response_mode '%s' for the response_type '%s'.", request.GetResponseMode(), request.GetResponseTypes())
	}

	return response, nil
}
