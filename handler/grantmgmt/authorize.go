// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package grantmgmt

import (
	"context"
	"slices"
	"strings"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// BindAuthorizeRequest binds the authorization request to a grant. It applies the checks of ValidateAuthorizeRequest
// and requires a grant named by 'grant_id' to be one the resource owner of the session consented to. The action 'merge'
// grants the permissions of the grant on the request, so the tokens it issues carry the union, other than a scope or
// audience value the client is no longer allowed, which is dropped from the resulting grant, and the scope 'openid'
// when the request did not request it, which stays in the resulting grant. The session records the 'grant_id', which
// is new for the action 'create', the action, and the permissions of the resulting grant.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-5.2
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-5.4
func (h *Handler) BindAuthorizeRequest(ctx context.Context, request oauth2.AuthorizeRequester) (err error) {
	responseTypes := request.GetResponseTypes()
	if responseTypes == nil {
		responseTypes = oauth2.Arguments{}
	}

	var (
		action oauth2.GrantManagementAction
		grant  *oauth2.Grant
	)

	if action, grant, err = h.validateRequest(ctx, request.GetClient(), request.GetRequestForm(), responseTypes); err != nil || action == "" {
		return err
	}

	session, ok := request.GetSession().(oauth2.GrantManagementSession)
	if !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("The session does not support grant management."))
	}

	if err = validateSubject(grant, request.GetSession()); err != nil {
		return err
	}

	return h.applyGrant(ctx, request, session, action, grant)
}

func (h *Handler) applyGrant(ctx context.Context, request oauth2.Requester, session oauth2.GrantManagementSession, action oauth2.GrantManagementAction, grant *oauth2.Grant) (err error) {
	if action != oauth2.GrantManagementActionCreate && grant == nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebugf("The grant management action '%s' requires a grant.", action))
	}

	snapshot := permissionsFromRequest(request)

	var id string

	switch action {
	case oauth2.GrantManagementActionCreate:
		if id, err = oauth2.NewGrantID(); err != nil {
			return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
		}
	case oauth2.GrantManagementActionMerge:
		id = grant.ID

		permissions := h.allowedPermissions(ctx, request.GetClient(), &grant.Permissions)

		grantPermissions(request, permissions)

		snapshot = permissions.Merge(snapshot)
	default:
		id = grant.ID
	}

	session.SetGrantID(id)
	session.SetGrantManagementAction(action)
	session.SetGrantPermissions(snapshot)

	return nil
}

func validateSubject(grant *oauth2.Grant, session oauth2.Session) (err error) {
	if grant == nil {
		return nil
	}

	if subject := session.GetSubject(); subject == "" || subject != grant.Subject {
		return errorsx.WithStack(oauth2.ErrInvalidGrantID.WithDebug("The grant was not consented to by the resource owner of the request."))
	}

	return nil
}

func (h *Handler) allowedPermissions(ctx context.Context, client oauth2.Client, permissions *oauth2.GrantPermissions) (allowed *oauth2.GrantPermissions) {
	allowed = permissions.Clone()

	scopes, audiences := oauth2.GetScopeStrategy(ctx, h.Config, client), oauth2.GetAudienceStrategy(ctx, h.Config, client)

	allowed.Scopes = nil

	for _, scope := range permissions.Scopes {
		values := slices.DeleteFunc(strings.Fields(scope.Scope), func(value string) bool {
			return !scopes(client.GetScopes(), value)
		})

		if len(values) != 0 {
			allowed.Scopes = append(allowed.Scopes, oauth2.GrantScope{Scope: strings.Join(values, " "), Resource: slices.Clone(scope.Resource)})
		}
	}

	allowed.Audience = slices.DeleteFunc(allowed.Audience, func(value string) bool {
		return audiences(client.GetAudience(), []string{value}) != nil
	})

	if len(allowed.Audience) == 0 {
		allowed.Audience = nil
	}

	return allowed
}

func grantPermissions(request oauth2.Requester, permissions *oauth2.GrantPermissions) {
	for _, scope := range permissions.ScopeValues() {
		if scope == consts.ScopeOpenID && !request.GetRequestedScopes().Has(scope) {
			continue
		}

		if !request.GetGrantedScopes().Has(scope) {
			request.GrantScope(scope)
		}
	}

	for _, audience := range permissions.Audience {
		if !request.GetGrantedAudience().Has(audience) {
			request.GrantAudience(audience)
		}
	}

	for _, resource := range permissions.ResourceValues() {
		if !request.GetGrantedResource().Has(resource) {
			request.GrantResource(resource)
		}
	}

	if len(permissions.AuthorizationDetails) == 0 {
		return
	}

	granted := &oauth2.GrantPermissions{AuthorizationDetails: request.GetGrantedAuthorizationDetails()}

	request.SetGrantedAuthorizationDetails(granted.Merge(&oauth2.GrantPermissions{AuthorizationDetails: permissions.AuthorizationDetails}).AuthorizationDetails)
}

func permissionsFromRequest(request oauth2.Requester) *oauth2.GrantPermissions {
	permissions := &oauth2.GrantPermissions{
		Audience:             grantedValues(request.GetGrantedAudience()),
		AuthorizationDetails: request.GetGrantedAuthorizationDetails().Clone(),
	}

	if scopes := request.GetGrantedScopes(); len(scopes) != 0 {
		permissions.Scopes = []oauth2.GrantScope{{
			Scope:    strings.Join(scopes, " "),
			Resource: grantedValues(request.GetGrantedResource()),
		}}
	}

	if r, ok := request.(oauth2.ClaimsRequester); ok {
		if claims := r.GetClaims(); claims != nil {
			for name := range claims.UserInfo {
				permissions.Claims = append(permissions.Claims, name)
			}

			for name := range claims.IDToken {
				permissions.Claims = append(permissions.Claims, name)
			}

			slices.Sort(permissions.Claims)

			permissions.Claims = slices.Compact(permissions.Claims)
		}
	}

	return permissions
}

func grantedValues(granted oauth2.Arguments) []string {
	if len(granted) == 0 {
		return nil
	}

	return slices.Clone([]string(granted))
}
