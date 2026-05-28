// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2/x/errorsx"
)

// NewAccessResponse dispatches the access request to each configured TokenEndpointHandler to populate the response. It
// returns ErrServerError if no handler issued an access token. Use WriteAccessResponse to send the result, or
// WriteAccessError if this method returns an error.
func (f *Fosite) NewAccessResponse(ctx context.Context, request AccessRequester) (AccessResponder, error) {
	var err error
	var tk TokenEndpointHandler

	response := NewAccessResponse()

	ctx = context.WithValue(ctx, AccessRequestContextKey, request)
	ctx = context.WithValue(ctx, AccessResponseContextKey, response)

	for _, tk = range f.Config.GetTokenEndpointHandlers(ctx) {
		if err = tk.PopulateTokenEndpointResponse(ctx, request, response); err == nil {
			// do nothing
		} else if errors.Is(err, ErrUnknownRequest) {
			// do nothing
		} else if err != nil {
			return nil, err
		}
	}

	if response.GetAccessToken() == "" || response.GetTokenType() == "" {
		return nil, errorsx.WithStack(ErrServerError.
			WithHint("An internal server occurred while trying to complete the request.").
			WithDebug("Access token or token type not set by TokenEndpointHandlers.").
			WithLocalizer(f.Config.GetMessageCatalog(ctx), getLangFromRequester(request)))
	}

	return response, nil
}
