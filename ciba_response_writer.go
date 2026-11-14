// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// NewBackChannelAuthenticationResponse runs the backchannel authentication binding handlers and then the endpoint
// handlers, which issue and persist the 'auth_req_id'. The application must have resolved the end-user and set the
// session subject first. The binding handlers read the HTTP request the authentication request was parsed from via
// RequestContextKey.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.3
func (f *Fosite) NewBackChannelAuthenticationResponse(ctx context.Context, request BackChannelAuthenticationRequester) (response BackChannelAuthenticationResponder, err error) {
	if session := request.GetSession(); session == nil || len(session.GetSubject()) == 0 {
		return nil, errorsx.WithStack(ErrServerError.WithDebug("the application must resolve the end-user and set the session subject before NewBackChannelAuthenticationResponse"))
	}

	response = NewBackChannelAuthenticationResponse()

	// The HTTP request is moved into ctx so that no endpoint handler persists it with the request.
	if req, ok := request.(*BackChannelAuthenticationRequest); ok && req.httpRequest != nil {
		ctx = context.WithValue(ctx, RequestContextKey, req.httpRequest)

		req.httpRequest = nil
	}

	for _, h := range f.Config.GetBackChannelAuthenticationEndpointBindingHandlers(ctx) {
		if err = h.BindBackChannelAuthenticationRequest(ctx, request); err != nil {
			return nil, err
		}
	}

	// A push client receives its tokens when the end-user approves, so a client that must have sender-constrained
	// tokens has to present its key material here.
	//
	// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#section-5
	if request.GetDeliveryMode() == consts.CIBAModePush {
		provider, _ := f.Config.(EnforceSenderConstrainedAccessTokensProvider)

		if IsSenderConstrainedAccessTokenEnforced(ctx, provider, request.GetClient()) && !isSenderConstrained(ctx, f.Config, request.GetSession()) {
			return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The push mode requires key material at the backchannel authentication endpoint, being a DPoP proof, a 'dpop_jkt' parameter, or a mutual-TLS client certificate, to bind the sender-constrained tokens to."))
		}
	}

	for _, h := range f.Config.GetBackChannelAuthenticationEndpointHandlers(ctx) {
		if err = h.HandleBackChannelAuthenticationEndpointRequest(ctx, request, response); err != nil {
			return nil, err
		}
	}

	return response, nil
}
