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

// NewRFC862DeviceAuthorizeRequest parses and validates an RFC 8628 device authorization endpoint request. The HTTP
// method must be POST as specified by section 3.1 of the RFC. The client is authenticated using the token endpoint
// authentication method (section 3.1 also requires this), the client must hold the device_code grant type, and the
// requested scopes, audience, and RFC 8707 resource indicators are validated against the client's registration.
func (f *Fosite) NewRFC862DeviceAuthorizeRequest(ctx context.Context, r *http.Request) (requester DeviceAuthorizeRequester, err error) {
	request := NewDeviceAuthorizeRequest()
	request.Lang = i18n.GetLangFromRequest(f.Config.GetMessageCatalog(ctx), r)

	if r.Method != http.MethodPost {
		return request, errorsx.WithStack(ErrInvalidRequest.WithHintf("HTTP method is '%s', expected 'POST'.", r.Method))
	}

	if err = r.ParseMultipartForm(1 << 20); err != nil && err != http.ErrNotMultipart {
		return request, errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body.").WithWrap(err).WithDebugError(err))
	}

	request.Form = r.PostForm

	// Authenticate the client in the same way as at the token endpoint (Section 2.3 of [RFC6749]).
	client, _, err := f.AuthenticateClient(ctx, r, r.Form)
	if err != nil {
		var rfcerr *RFC6749Error
		if errors.As(err, &rfcerr) && rfcerr.ErrorField != ErrInvalidClient.ErrorField {
			return request, errorsx.WithStack(ErrInvalidClient.WithHint("The requested OAuth 2.0 Client could not be authenticated.").WithWrap(err).WithDebugError(err))
		}

		return request, err
	}

	request.Client = client

	if !client.GetGrantTypes().Has(string(GrantTypeDeviceCode)) {
		return nil, errorsx.WithStack(ErrInvalidGrant.WithHint("The requested OAuth 2.0 Client does not have the 'urn:ietf:params:oauth:grant-type:device_code' grant."))
	}

	if err = f.validateScope(ctx, r, request); err != nil {
		return request, err
	}

	if err = ValidateResourceIndicators(request.Form); err != nil {
		return request, err
	}

	if err = f.validateAudience(ctx, r, request); err != nil {
		return request, err
	}

	return request, nil
}
