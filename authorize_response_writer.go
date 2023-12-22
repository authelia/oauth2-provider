// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"
	"net/url"

	"authelia.com/provider/oauth2/internal/errorsx"
)

func (f *Fosite) NewAuthorizeResponse(ctx context.Context, requester AuthorizeRequester, session Session) (responder AuthorizeResponder, err error) {
	var response = &AuthorizeResponse{
		Header:     http.Header{},
		Parameters: url.Values{},
	}

	ctx = context.WithValue(ctx, AuthorizeRequestContextKey, requester)
	ctx = context.WithValue(ctx, AuthorizeResponseContextKey, response)

	requester.SetSession(session)
	for _, h := range f.Config.GetAuthorizeEndpointHandlers(ctx) {
		if err = h.HandleAuthorizeEndpointRequest(ctx, requester, response); err != nil {
			return nil, err
		}
	}

	if !requester.DidHandleAllResponseTypes() {
		return nil, errorsx.WithStack(ErrUnsupportedResponseType)
	}

	if requester.GetDefaultResponseMode() == ResponseModeFragment && requester.GetResponseMode() == ResponseModeQuery {
		return nil, ErrUnsupportedResponseMode.WithHintf("Insecure response_mode '%s' for the response_type '%s'.", requester.GetResponseMode(), requester.GetResponseTypes())
	}

	return response, nil
}
