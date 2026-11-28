// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"

	"authelia.com/provider/oauth2/i18n"
	"authelia.com/provider/oauth2/x/errorsx"
)

// NewRFC862DeviceAuthorizeRequest parses and validates an RFC 8628 device authorization endpoint request. The HTTP
// method must be POST as specified by section 3.1 of the RFC. The client is authenticated using the token endpoint
// authentication method (section 3.1 also requires this), the client must hold the device_code grant type, and the
// requested scopes, audience, RFC 8707 resource indicators, and RFC 9396 authorization details are validated against
// the client's registration. Every RFC8628DeviceAuthorizeRequestValidator among the device authorization endpoint
// binding handlers, device authorization endpoint handlers and user authorization endpoint handlers then checks the
// request.
func (f *Fosite) NewRFC862DeviceAuthorizeRequest(ctx context.Context, r *http.Request) (requester DeviceAuthorizeRequester, err error) {
	request := NewDeviceAuthorizeRequest()
	request.Lang = i18n.GetLangFromRequest(f.Config.GetMessageCatalog(ctx), r)

	if r.Method != http.MethodPost {
		return request, errorsx.WithStack(ErrInvalidRequest.WithHintf("HTTP method is '%s', expected 'POST'.", r.Method))
	}

	if err = r.ParseForm(); err != nil {
		return request, errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body.").WithWrap(err).WithDebugError(err))
	}

	if err = ValidateRequestParametersNotRepeated(r.PostForm); err != nil {
		return request, err
	}

	request.Form = withoutClientCredentials(r.PostForm)

	// Authenticate the client in the same way as at the token endpoint (Section 2.3 of [RFC6749]).
	client, _, err := f.AuthenticateClientWithAuthHandler(ctx, r, r.PostForm, &AudienceEndpointClientAuthStrategy{EndpointClientAuthStrategy: f.Config.GetTokenEndpointClientAuthStrategy(ctx), AudienceEndpoint: EndpointDeviceAuthorization})
	if err != nil {
		return request, f.clientAuthenticationEndpointError(ctx, r, err)
	}

	request.Client = client

	if !client.GetGrantTypes().Has(string(GrantTypeDeviceCode)) {
		return request, errorsx.WithStack(ErrUnauthorizedClient.WithHint("The requested OAuth 2.0 Client does not have the 'urn:ietf:params:oauth:grant-type:device_code' grant."))
	}

	if err = f.validateScope(ctx, r, request); err != nil {
		return request, err
	}

	if err = f.validateNonceEntropy(ctx, request.Form); err != nil {
		return request, err
	}

	if err = ValidateResourceIndicators(request.Form); err != nil {
		return request, err
	}

	if err = f.validateAudience(ctx, r, request); err != nil {
		return request, err
	}

	// See: https://www.rfc-editor.org/rfc/rfc9396#section-3
	if err = f.validateAuthorizationDetails(ctx, request); err != nil {
		return request, err
	}

	if err = f.validateRFC8628DeviceAuthorizeRequest(ctx, request); err != nil {
		return request, err
	}

	return request, nil
}

func (f *Fosite) validateRFC8628DeviceAuthorizeRequest(ctx context.Context, request DeviceAuthorizeRequester) (err error) {
	for _, h := range f.Config.GetRFC8628DeviceAuthorizeEndpointBindingHandlers(ctx) {
		if v, ok := h.(RFC8628DeviceAuthorizeRequestValidator); ok {
			if err = v.ValidateRFC8628DeviceAuthorizeRequest(ctx, request); err != nil {
				return err
			}
		}
	}

	for _, h := range f.Config.GetRFC8628DeviceAuthorizeEndpointHandlers(ctx) {
		if v, ok := h.(RFC8628DeviceAuthorizeRequestValidator); ok {
			if err = v.ValidateRFC8628DeviceAuthorizeRequest(ctx, request); err != nil {
				return err
			}
		}
	}

	for _, h := range f.Config.GetRFC8628UserAuthorizeEndpointHandlers(ctx) {
		if v, ok := h.(RFC8628DeviceAuthorizeRequestValidator); ok {
			if err = v.ValidateRFC8628DeviceAuthorizeRequest(ctx, request); err != nil {
				return err
			}
		}
	}

	return nil
}
