// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package grantmgmt

import (
	"context"
	"errors"
	"slices"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// BindAccessRequest checks the grant recorded on the session when an authorization code or an OpenID Connect CIBA
// authentication request is redeemed, and writes nothing. A grant the actions 'merge' and 'replace' apply to which no
// longer exists, has expired, or is no longer one the resource owner consented to for the client is
// oauth2.ErrInvalidGrant.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-5.2
func (h *Handler) BindAccessRequest(ctx context.Context, request oauth2.AccessRequester) (err error) {
	_, _, err = h.resolve(ctx, request)

	return err
}

// CommitAccessRequest writes the grant recorded on the session once the token request has passed every check before
// issuance. The action 'create' stores a new grant. The action 'merge' adds the permissions recorded on the session to
// those of the grant and the action 'replace' sets them, both revoke the refresh tokens issued under the grant, and
// the action 'replace' revokes the access tokens too. A request repeated after a failure later in the same token
// request has the same result as the first.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-5.2
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-5.5
func (h *Handler) CommitAccessRequest(ctx context.Context, request oauth2.AccessRequester) (err error) {
	var (
		session oauth2.GrantManagementSession
		grant   *oauth2.Grant
	)

	if session, grant, err = h.resolve(ctx, request); err != nil || session == nil {
		return err
	}

	if grant == nil {
		return h.createGrant(ctx, request, session.GetGrantID(), session.GetGrantPermissions())
	}

	return h.updateGrant(ctx, request, session.GetGrantManagementAction(), grant, session.GetGrantPermissions())
}

func (h *Handler) resolve(ctx context.Context, request oauth2.AccessRequester) (session oauth2.GrantManagementSession, grant *oauth2.Grant, err error) {
	if h.config(ctx) == nil {
		return nil, nil, nil
	}

	if types := request.GetGrantTypes(); !types.ExactOne(consts.GrantTypeAuthorizationCode) && !types.ExactOne(consts.GrantTypeOpenIDCIBA) {
		return nil, nil, nil
	}

	var ok bool

	if session, ok = request.GetSession().(oauth2.GrantManagementSession); !ok {
		return nil, nil, nil
	}

	action := session.GetGrantManagementAction()
	if action == "" {
		return nil, nil, nil
	}

	if h.Storage == nil {
		return nil, nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("The grant management handler has no storage."))
	}

	id := session.GetGrantID()

	if id == "" || session.GetGrantPermissions() == nil {
		return nil, nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("The session records a grant management action without the grant it applies to."))
	}

	switch action {
	case oauth2.GrantManagementActionCreate:
		if request.GetSession().GetSubject() == "" {
			return nil, nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("The session records no resource owner to create the grant for."))
		}

		return session, nil, nil
	case oauth2.GrantManagementActionMerge, oauth2.GrantManagementActionReplace:
	default:
		return nil, nil, errorsx.WithStack(oauth2.ErrServerError.WithDebugf("The session records the unknown grant management action '%s'.", action))
	}

	if grant, err = h.getGrant(ctx, request.GetClient(), id); err == nil {
		err = validateSubject(grant, request.GetSession())
	}

	if err != nil {
		if errors.Is(err, oauth2.ErrInvalidGrantID) {
			return nil, nil, errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The grant the authorization applies to is no longer available.").WithDebugError(err))
		}

		return nil, nil, err
	}

	return session, grant, nil
}

// PopulateBoundTokenEndpointResponse adds the 'grant_id' recorded on the session to the token response of the
// authorization code, OpenID Connect CIBA and refresh token grants, when the session also records the action the
// grant was authorized with.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-5.5
func (h *Handler) PopulateBoundTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
	if h.config(ctx) == nil {
		return nil
	}

	if types := request.GetGrantTypes(); !types.ExactOne(consts.GrantTypeAuthorizationCode) && !types.ExactOne(consts.GrantTypeOpenIDCIBA) && !types.ExactOne(consts.GrantTypeRefreshToken) {
		return nil
	}

	session, ok := request.GetSession().(oauth2.GrantManagementSession)
	if !ok || session.GetGrantManagementAction() == "" {
		return nil
	}

	if id := session.GetGrantID(); id != "" {
		response.SetExtra(consts.AccessResponseGrantID, id)
	}

	return nil
}

func (h *Handler) createGrant(ctx context.Context, request oauth2.AccessRequester, id string, permissions *oauth2.GrantPermissions) (err error) {
	now := time.Now().UTC()

	grant := &oauth2.Grant{
		ID:          id,
		ClientID:    request.GetClient().GetID(),
		Subject:     request.GetSession().GetSubject(),
		Permissions: *permissions.Clone(),
		CreatedAt:   now,
		UpdatedAt:   now,
		UpdatedBy:   oauth2.GrantUpdatedByClient,
		RequestIDs:  []string{request.GetID()},
	}

	if err = h.Storage.CreateGrant(ctx, grant); err == nil {
		return nil
	}

	if existing, gerr := h.Storage.GetGrant(ctx, id); gerr == nil && existing != nil && existing.ClientID == grant.ClientID && existing.Subject == grant.Subject && slices.Equal(existing.RequestIDs, grant.RequestIDs) {
		return nil
	}

	return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
}

func (h *Handler) updateGrant(ctx context.Context, request oauth2.AccessRequester, action oauth2.GrantManagementAction, grant *oauth2.Grant, permissions *oauth2.GrantPermissions) (err error) {
	var (
		prior   []string
		current = request.GetID()
		replace = action == oauth2.GrantManagementActionReplace
	)

	if replace {
		prior, err = h.Storage.ReplaceGrantRequestIDs(ctx, grant.ID, []string{current})
	} else if err = h.Storage.AppendGrantRequestID(ctx, grant.ID, current); err == nil {
		if grant, err = h.Storage.GetGrant(ctx, grant.ID); err == nil && grant != nil {
			prior = grant.RequestIDs
		}
	}

	switch {
	case errors.Is(err, oauth2.ErrNotFound), err == nil && grant == nil:
		return errGrantUnavailable()
	case err != nil:
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	ctx = context.WithoutCancel(ctx)

	if err = h.revokeRequests(ctx, prior, current, replace); err != nil {
		if replace {
			h.restoreRequestIDs(ctx, grant.ID, prior)
		}

		return err
	}

	if replace {
		grant.Permissions = *permissions.Clone()
	} else {
		grant.Permissions = *h.allowedPermissions(ctx, request.GetClient(), &grant.Permissions).Merge(permissions)
	}

	grant.UpdatedAt = time.Now().UTC()
	grant.UpdatedBy = oauth2.GrantUpdatedByClient

	switch err = h.Storage.UpdateGrant(ctx, grant); {
	case errors.Is(err, oauth2.ErrNotFound):
		return errGrantUnavailable()
	case err != nil:
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	return nil
}

func (h *Handler) revokeRequests(ctx context.Context, ids []string, current string, access bool) (err error) {
	for _, id := range ids {
		if id == current {
			continue
		}

		if err = revoked(h.Storage.RevokeRefreshToken(ctx, id)); err != nil {
			return err
		}

		if !access {
			continue
		}

		if err = revoked(h.Storage.RevokeAccessToken(ctx, id)); err != nil {
			return err
		}
	}

	return nil
}

func (h *Handler) restoreRequestIDs(ctx context.Context, id string, requestIDs []string) {
	for _, requestID := range requestIDs {
		_ = h.Storage.AppendGrantRequestID(ctx, id, requestID)
	}
}

func errGrantUnavailable() error {
	return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The grant the authorization applies to is no longer available.").WithDebug("The grant does not exist."))
}

func revoked(err error) error {
	if err == nil || errors.Is(err, oauth2.ErrNotFound) || errors.Is(err, oauth2.ErrInactiveToken) {
		return nil
	}

	return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
}
