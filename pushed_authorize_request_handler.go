// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"errors"
	"net/http"

	"authelia.com/provider/oauth2/i18n"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

const (
	ErrorPARNotSupported           = "The OAuth 2.0 provider does not support Pushed Authorization Requests"
	DebugPARStorageInvalid         = "The Pushed Authorization Request storage is not implemented"
	DebugPARConfigMissing          = "'PushedAuthorizeRequestConfigProvider' not implemented"
	DebugPARRequestsHandlerMissing = "'PushedAuthorizeRequestHandlersProvider' not implemented"
)

// NewPushedAuthorizeRequest validates the request and produces an AuthorizeRequester object that can be stored
func (f *Fosite) NewPushedAuthorizeRequest(ctx context.Context, r *http.Request) (requester AuthorizeRequester, err error) {
	request := NewAuthorizeRequest()
	request.Lang = i18n.GetLangFromRequest(f.Config.GetMessageCatalog(ctx), r)

	if r.Method != http.MethodPost {
		return request, errorsx.WithStack(ErrInvalidRequest.WithHintf("HTTP method is '%s', expected 'POST'.", r.Method))
	}

	if err = r.ParseMultipartForm(1 << 20); err != nil && err != http.ErrNotMultipart {
		return request, errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body.").WithWrap(err).WithDebugError(err))
	}

	request.Form = r.Form
	request.State = request.Form.Get(consts.FormParameterState)

	var client Client

	// Authenticate the client in the same way as at the token endpoint (Section 2.3 of [RFC6749]).
	if client, _, err = f.AuthenticateClient(ctx, r, r.Form); err != nil {
		var rfcerr *RFC6749Error
		if errors.As(err, &rfcerr) && rfcerr.ErrorField != ErrInvalidClient.ErrorField {
			return request, errorsx.WithStack(ErrInvalidClient.WithHint("The requested OAuth 2.0 Client could not be authenticated.").WithWrap(err).WithDebugError(err))
		}

		return request, err
	}

	request.Client = client

	// Reject the request if the "request_uri" authorization request parameter is provided.
	if r.Form.Get(consts.FormParameterRequestURI) != "" {
		return request, errorsx.WithStack(ErrInvalidRequest.WithHint("The request must not contain 'request_uri'."))
	}

	// For private_key_jwt or basic auth client authentication, "client_id" may not be inside the form.
	// However this is required by NewAuthorizeRequest implementation.
	if len(r.Form.Get(consts.ClaimClientIdentifier)) == 0 {
		r.Form.Set(consts.ClaimClientIdentifier, client.GetID())
	}

	var frequest AuthorizeRequester

	// Validate as if this is a new authorize request.
	if frequest, err = f.newAuthorizeRequest(ctx, r, true); err != nil {
		return frequest, err
	}

	if frequest.GetRequestedScopes().Has(consts.ScopeOpenID) && r.Form.Get(consts.FormParameterRedirectURI) == "" {
		return frequest, errorsx.WithStack(ErrInvalidRequest.WithHint("Query parameter 'redirect_uri' is required when performing an OpenID Connect flow."))
	}

	return frequest, nil
}
