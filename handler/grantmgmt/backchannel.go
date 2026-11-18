// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package grantmgmt

import (
	"context"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/x/errorsx"
)

// BindBackChannelAuthenticationRequest binds an OpenID Connect CIBA authentication request to a grant. It applies the
// checks of ValidateAuthorizeRequest other than the response type check, and requires a grant named by 'grant_id' to
// be one the end user the request is for consented to. The session records the 'grant_id', which is new for the
// action 'create', and the action. The permissions are applied when the end user approves the request.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-5.1
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-5.4
func (h *Handler) BindBackChannelAuthenticationRequest(ctx context.Context, request oauth2.BackChannelAuthenticationRequester) (err error) {
	var (
		action oauth2.GrantManagementAction
		grant  *oauth2.Grant
	)

	if action, grant, err = h.validateRequest(ctx, request.GetClient(), request.GetRequestForm(), nil); err != nil || action == "" {
		return err
	}

	session, ok := request.GetSession().(oauth2.GrantManagementSession)
	if !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("The session does not support grant management."))
	}

	if err = validateSubject(grant, request.GetSession()); err != nil {
		return err
	}

	var id string

	if grant != nil {
		id = grant.ID
	} else if id, err = oauth2.NewGrantID(); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	session.SetGrantID(id)
	session.SetGrantManagementAction(action)

	return nil
}

// HandleBackChannelAuthenticationDecision applies the grant recorded on the session to an approved OpenID Connect CIBA
// authentication request, as BindAuthorizeRequest does to an authorization request. A grant named by 'grant_id' which
// no longer exists, or is no longer one the end user consented to for the client, is oauth2.ErrInvalidGrantID. It must
// be registered before the handler which persists the decision.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-5.2
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-5.4
func (h *Handler) HandleBackChannelAuthenticationDecision(ctx context.Context, request oauth2.BackChannelAuthenticationRequester, _ *oauth2.BackChannelAuthenticationDecisionResult) (err error) {
	if request.GetStatus() != oauth2.CIBAStatusApproved || h.config(ctx) == nil {
		return nil
	}

	session, ok := request.GetSession().(oauth2.GrantManagementSession)
	if !ok {
		return nil
	}

	action := session.GetGrantManagementAction()

	switch action {
	case "":
		return nil
	case oauth2.GrantManagementActionCreate:
		return h.applyGrant(ctx, request, session, action, nil)
	}

	var grant *oauth2.Grant

	if grant, err = h.getGrant(ctx, request.GetClient(), session.GetGrantID()); err != nil {
		return err
	}

	if err = validateSubject(grant, request.GetSession()); err != nil {
		return err
	}

	return h.applyGrant(ctx, request, session, action, grant)
}
