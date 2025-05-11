// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"
	"strings"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2/i18n"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// NewAccessRequest Implements
//   - https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
//     Clients in possession of a client password MAY use the HTTP Basic
//     authentication scheme as defined in [RFC2617] to authenticate with
//     the authorization server.  The client identifier is encoded using the
//     "application/x-www-form-urlencoded" encoding algorithm per
//     Appendix B, and the encoded value is used as the username; the client
//     password is encoded using the same algorithm and used as the
//     password.  The authorization server MUST support the HTTP Basic
//     authentication scheme for authenticating clients that were issued a
//     client password.
//     Including the client credentials in the request-body using the two
//     parameters is NOT RECOMMENDED and SHOULD be limited to clients unable
//     to directly utilize the HTTP Basic authentication scheme (or other
//     password-based HTTP authentication schemes).  The parameters can only
//     be transmitted in the request-body and MUST NOT be included in the
//     request URI.
//   - https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1
//   - Confidential clients or other clients issued client credentials MUST
//     authenticate with the authorization server as described in
//     Section 2.3 when making requests to the token endpoint.
//   - If the client type is confidential or the client was issued client
//     credentials (or assigned other authentication requirements), the
//     client MUST authenticate with the authorization server as described
//     in Section 3.2.1.
//
// TODO: Refactor time permitting.
//
//nolint:gocyclo
func (f *Fosite) NewAccessRequest(ctx context.Context, r *http.Request, session Session) (AccessRequester, error) {
	requester := NewAccessRequest(session)
	requester.Lang = i18n.GetLangFromRequest(f.Config.GetMessageCatalog(ctx), r)

	ctx = context.WithValue(ctx, RequestContextKey, r)
	ctx = context.WithValue(ctx, AccessRequestContextKey, requester)

	if r.Method != http.MethodPost {
		return requester, errorsx.WithStack(ErrInvalidRequest.WithHintf("HTTP method is '%s', expected 'POST'.", r.Method))
	} else if err := r.ParseMultipartForm(1 << 20); err != nil && !errors.Is(err, http.ErrNotMultipart) {
		return requester, errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body.").WithWrap(err).WithDebugError(err))
	} else if len(r.PostForm) == 0 {
		return requester, errorsx.WithStack(ErrInvalidRequest.WithHint("The POST body can not be empty."))
	}

	requester.Form = r.PostForm
	if session == nil {
		return requester, errors.New("Session must not be nil")
	}

	requester.SetRequestedScopes(RemoveEmpty(strings.Split(r.PostForm.Get(consts.FormParameterScope), " ")))
	requester.SetRequestedAudience(GetAudiences(r.PostForm))
	requester.GrantTypes = RemoveEmpty(strings.Split(r.PostForm.Get(consts.FormParameterGrantType), " "))
	if len(requester.GrantTypes) < 1 {
		return requester, errorsx.WithStack(ErrInvalidRequest.WithHint("Request parameter 'grant_type' is missing"))
	}

	client, _, clientErr := f.AuthenticateClientWithAuthHandler(ctx, r, r.PostForm, &TokenEndpointClientAuthHandler{})
	if clientErr == nil {
		requester.Client = client
	}

	var found = false
	for _, loader := range f.Config.GetTokenEndpointHandlers(ctx) {
		// Is the loader responsible for handling the request?
		if !loader.CanHandleTokenEndpointRequest(ctx, requester) {
			continue
		}

		// The handler **is** responsible!

		// Is the client supplied in the request? If not can this handler skip client auth?
		if !loader.CanSkipClientAuth(ctx, requester) && clientErr != nil {
			// No client and handler can not skip client auth -> error.
			return requester, clientErr
		}

		// All good.
		if err := loader.HandleTokenEndpointRequest(ctx, requester); err == nil {
			found = true
		} else if errors.Is(err, ErrUnknownRequest) {
			// This is a duplicate because it should already have been handled by
			// `loader.CanHandleTokenEndpointRequest(accessRequest)` but let's keep it for sanity.
			//
			continue
		} else if err != nil {
			return requester, err
		}
	}

	if !found {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithDebugf("The client with id '%s' requested grant type '%s' which is invalid, unknown, not supported, or not configured to be handled.", requester.GetRequestForm().Get(consts.FormParameterClientID), strings.Join(requester.GetGrantTypes(), " ")))
	}

	return requester, nil
}
