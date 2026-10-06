// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2/i18n"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// NewAccessRequest parses and validates a token endpoint request, authenticating the client.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1 and https://www.rfc-editor.org/rfc/rfc6749#section-3.2.1
//
// TODO: Refactor time permitting.
//
//nolint:gocyclo
func (f *Fosite) NewAccessRequest(ctx context.Context, r *http.Request, session Session) (ar AccessRequester, err error) {
	requester := NewAccessRequest(session)
	requester.Lang = i18n.GetLangFromRequest(f.Config.GetMessageCatalog(ctx), r)

	ctx = context.WithValue(ctx, RequestContextKey, r)
	ctx = context.WithValue(ctx, AccessRequestContextKey, requester)

	if r.Method != http.MethodPost {
		return requester, errorsx.WithStack(ErrInvalidRequest.WithHintf("HTTP method is '%s', expected 'POST'.", r.Method))
	} else if err = r.ParseMultipartForm(1 << 20); err != nil && !errors.Is(err, http.ErrNotMultipart) {
		return requester, errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body.").WithWrap(err).WithDebugError(err))
	} else if len(r.PostForm) == 0 {
		return requester, errorsx.WithStack(ErrInvalidRequest.WithHint("The POST body can not be empty."))
	}

	requester.Form = r.PostForm

	if session == nil {
		return requester, errors.New("Session must not be nil")
	}

	if err = ValidateResourceIndicators(requester.Form); err != nil {
		return requester, err
	}

	requester.SetRequestedScopes(RemoveEmpty(strings.Split(r.PostForm.Get(consts.FormParameterScope), " ")))
	requester.SetRequestedAudience(GetRequestedAudiences(r.PostForm))
	requester.SetRequestedResource(GetRequestedResources(r.PostForm))

	requester.GrantTypes = RemoveEmpty(strings.Split(r.PostForm.Get(consts.FormParameterGrantType), " "))

	if len(requester.GrantTypes) < 1 {
		return requester, errorsx.WithStack(ErrInvalidRequest.WithHint("Request parameter 'grant_type' is missing"))
	}

	// See: https://www.rfc-editor.org/rfc/rfc9396#section-6
	if r.PostForm.Get(consts.FormParameterAuthorizationDetails) != "" && IsAuthorizationDetailsEnabled(ctx, f.Config) && !f.canHandleAuthorizationDetails(ctx, requester) {
		return requester, errorsx.WithStack(ErrInvalidAuthorizationDetails.WithHintf("The 'authorization_details' parameter is not supported for grant type '%s'.", strings.Join(requester.GrantTypes, " ")))
	}

	client, _, clientErr := f.AuthenticateClientWithAuthHandler(ctx, r, r.PostForm, f.Config.GetTokenEndpointClientAuthStrategy(ctx))
	if clientErr == nil {
		requester.Client = client
	}

	presented := hasClientCredentials(r, r.PostForm)

	if clientErr == nil {
		var details AuthorizationDetails

		if details, err = ParseRequestedAuthorizationDetails(ctx, f.Config, requester.GetClient(), r.PostForm); err != nil {
			return requester, err
		}

		requester.SetRequestedAuthorizationDetails(details)
	}

	var found = false
	for _, loader := range f.Config.GetTokenEndpointHandlers(ctx) {
		if !loader.CanHandleTokenEndpointRequest(ctx, requester) {
			continue
		}

		if clientErr != nil && (presented || !loader.CanSkipClientAuth(ctx, requester)) {
			return requester, clientErr
		}

		if err = loader.HandleTokenEndpointRequest(ctx, requester); err == nil {
			found = true
		} else if errors.Is(err, ErrUnknownRequest) {
			// This is a duplicate because it should already have been handled by
			// `loader.CanHandleTokenEndpointRequest` but let's keep it for sanity.

			continue
		} else if err != nil {
			return requester, err
		}
	}

	if !found {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithDebugf("The client with id '%s' requested grant type '%s' which is invalid, unknown, not supported, or not configured to be handled.", requester.GetRequestForm().Get(consts.FormParameterClientID), strings.Join(requester.GetGrantTypes(), " ")))
	}

	// Created here rather than by a handler because context values do not propagate between the handlers in this
	// loop: the container must exist before the first handler runs for a later one to observe what an earlier one
	// published.
	ctx = context.WithValue(ctx, DPoPProofContextKey, &DPoPProofHolder{})

	// Binding handlers run only once a grant handler has accepted the request, so a binding handler needs neither a
	// grant type claim nor a client authentication policy of its own: by this point the accepting grant handler has
	// enforced whatever authentication it requires, or legitimately waived it.
	for _, binding := range f.Config.GetTokenEndpointBindingHandlers(ctx) {
		if err = binding.BindAccessRequest(ctx, requester); err != nil {
			return requester, err
		}
	}

	return requester, nil
}

func hasClientCredentials(r *http.Request, form url.Values) bool {
	if len(r.Header.Get(consts.HeaderAuthorization)) != 0 {
		return true
	}

	for _, parameter := range []string{consts.FormParameterClientSecret, consts.FormParameterClientAssertion, consts.FormParameterClientAssertionType} {
		if len(form.Get(parameter)) != 0 {
			return true
		}
	}

	return false
}

func (f *Fosite) canHandleAuthorizationDetails(ctx context.Context, requester AccessRequester) bool {
	for _, handler := range f.Config.GetTokenEndpointHandlers(ctx) {
		if h, ok := handler.(AuthorizationDetailsTokenEndpointHandler); ok && handler.CanHandleTokenEndpointRequest(ctx, requester) && h.CanHandleAuthorizationDetails(ctx, requester) {
			return true
		}
	}

	return false
}
