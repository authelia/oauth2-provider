// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package grantmgmt

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// ValidateAuthorizeRequest refuses an authorization request whose 'grant_management_action' and 'grant_id' parameters
// are invalid, or which names a grant that is unknown or was issued to another client.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-5.4
func (h *Handler) ValidateAuthorizeRequest(ctx context.Context, request oauth2.AuthorizeRequester) (err error) {
	responseTypes := request.GetResponseTypes()
	if responseTypes == nil {
		responseTypes = oauth2.Arguments{}
	}

	_, _, err = h.validateRequest(ctx, request.GetClient(), request.GetRequestForm(), responseTypes)

	return err
}

// BindRFC8628DeviceAuthorizeRequest refuses a device authorization request which includes the
// 'grant_management_action' or 'grant_id' parameter.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-5.1
func (h *Handler) BindRFC8628DeviceAuthorizeRequest(ctx context.Context, request oauth2.DeviceAuthorizeRequester) (err error) {
	if h.config(ctx) == nil {
		return nil
	}

	form := request.GetRequestForm()

	for _, parameter := range []string{consts.FormParameterGrantManagementAction, consts.FormParameterGrantID} {
		if slices.ContainsFunc(form[parameter], func(value string) bool { return value != "" }) {
			return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Grant management is not supported at the device authorization endpoint."))
		}
	}

	return nil
}

func (h *Handler) validateRequest(ctx context.Context, client oauth2.Client, form url.Values, responseTypes oauth2.Arguments) (action oauth2.GrantManagementAction, grant *oauth2.Grant, err error) {
	config := h.config(ctx)
	if config == nil {
		return "", nil, nil
	}

	var id string

	if action, id, err = validateParameters(config, form); err != nil || action == "" {
		return "", nil, err
	}

	if client == nil || client.IsPublic() {
		return "", nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Grant management is only available to confidential clients."))
	}

	if responseTypes != nil && (!responseTypes.Has(consts.ResponseTypeAuthorizationCodeFlow) || responseTypes.Has(consts.ResponseTypeImplicitFlowToken)) {
		return "", nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Grant management requires a response type which includes 'code' and does not include 'token'."))
	}

	if action == oauth2.GrantManagementActionCreate {
		return action, nil, nil
	}

	if grant, err = h.getGrant(ctx, client, id); err != nil {
		return "", nil, err
	}

	return action, grant, nil
}

func (h *Handler) getGrant(ctx context.Context, client oauth2.Client, id string) (grant *oauth2.Grant, err error) {
	if h.Storage == nil {
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("The grant management handler has no storage."))
	}

	if grant, err = h.Storage.GetGrant(ctx, id); err != nil {
		if errors.Is(err, oauth2.ErrNotFound) {
			return nil, errorsx.WithStack(oauth2.ErrInvalidGrantID.WithWrap(err).WithDebugError(err))
		}

		return nil, errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	if grant == nil || grant.ClientID != client.GetID() {
		return nil, errorsx.WithStack(oauth2.ErrInvalidGrantID.WithDebug("The grant was not issued to this client."))
	}

	if !grant.ExpiresAt.IsZero() && !grant.ExpiresAt.After(time.Now().UTC()) {
		return nil, errorsx.WithStack(oauth2.ErrInvalidGrantID.WithDebug("The grant has expired."))
	}

	return grant, nil
}

func validateParameters(config *oauth2.GrantManagementConfig, form url.Values) (action oauth2.GrantManagementAction, id string, err error) {
	for _, parameter := range []string{consts.FormParameterGrantManagementAction, consts.FormParameterGrantID} {
		if len(form[parameter]) > 1 {
			return "", "", errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' parameter must not be included more than once.", parameter))
		}
	}

	action = oauth2.GrantManagementAction(form.Get(consts.FormParameterGrantManagementAction))
	id = form.Get(consts.FormParameterGrantID)

	if action == "" && id == "" {
		if config.ActionRequired {
			return "", "", errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The 'grant_management_action' parameter is required."))
		}

		return "", "", nil
	}

	switch action {
	case "":
		return "", "", errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The 'grant_id' parameter must not be included without the 'grant_management_action' parameter."))
	case oauth2.GrantManagementActionCreate, oauth2.GrantManagementActionMerge, oauth2.GrantManagementActionReplace:
		if !config.Supports(action) {
			return "", "", errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The 'grant_management_action' parameter value '%s' is not supported.", action))
		}
	default:
		return "", "", errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The 'grant_management_action' parameter value '%s' is not supported.", action))
	}

	switch {
	case action == oauth2.GrantManagementActionCreate && id != "":
		return "", "", errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The 'grant_id' parameter must not be included when the 'grant_management_action' parameter is 'create'."))
	case action != oauth2.GrantManagementActionCreate && id == "":
		return "", "", errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The 'grant_id' parameter is required when the 'grant_management_action' parameter is '%s'.", action))
	}

	return action, id, nil
}
