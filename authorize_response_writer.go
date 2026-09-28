// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"
	"net/url"

	"authelia.com/provider/oauth2/token/jwt"
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

	if request.GetDefaultResponseMode() == ResponseModeFragment {
		switch mode := request.GetResponseMode(); {
		case mode == ResponseModeQuery:
			return nil, ErrUnsupportedResponseMode.WithHintf("Insecure response_mode '%s' for the response_type '%s'.", mode, request.GetResponseTypes())
		case mode == ResponseModeQueryJWT && !isEncryptedJARMClient(request.GetClient()):
			// JWT Secured Authorization Response Mode for OAuth 2.0 (JARM) Section 2.3.1: 'query.jwt' MUST NOT be used
			// with response types containing 'token' or 'id_token' unless the response JWT is encrypted.
			return nil, ErrUnsupportedResponseMode.WithHintf("Insecure response_mode '%s' for the response_type '%s' unless the authorization response is encrypted.", mode, request.GetResponseTypes())
		}
	}

	return response, nil
}

func isEncryptedJARMClient(client Client) bool {
	if c, ok := client.(jwt.JARMClient); ok {
		return c.GetAuthorizationEncryptedResponseAlg() != ""
	}

	return false
}
