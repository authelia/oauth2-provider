// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"errors"
	"net/http"
	"time"

	"authelia.com/provider/oauth2/x/errorsx"
)

// NewGrantManagementResponse queries or revokes the grant of the request. A grant which is unknown or belongs to
// another client is not found. A grant which has expired is not found by a query and is revoked by a revocation.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-6.4
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-6.5
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-6.6
func (f *Fosite) NewGrantManagementResponse(ctx context.Context, requester GrantManagementRequester) (responder GrantManagementResponder, err error) {
	var (
		config  *GrantManagementConfig
		storage GrantManagementStorage
	)

	if config, storage, err = f.grantManagement(ctx); err != nil {
		return nil, err
	}

	if _, err = grantManagementMethodScope(config, requester.GetMethod()); err != nil {
		return nil, err
	}

	client := requester.GetClient()

	if client == nil || client.GetID() == "" || requester.GetGrantID() == "" {
		return nil, errorsx.WithStack(ErrNotFound.WithDebug("The request does not identify a client and a grant."))
	}

	var grant *Grant

	if grant, err = getGrant(ctx, storage, requester.GetGrantID()); err != nil {
		return nil, err
	}

	if grant.ClientID != client.GetID() {
		return nil, errorsx.WithStack(ErrNotFound.WithDebug("The grant belongs to another client."))
	}

	if requester.GetMethod() == http.MethodDelete {
		if err = revokeGrant(ctx, storage, grant.ID); err != nil {
			return nil, err
		}

		return &GrantManagementResponse{StatusCode: http.StatusNoContent}, nil
	}

	if !grant.ExpiresAt.IsZero() && !grant.ExpiresAt.After(time.Now().UTC()) {
		return nil, errorsx.WithStack(ErrNotFound.WithDebug("The grant has expired."))
	}

	return &GrantManagementResponse{
		StatusCode: http.StatusOK,
		Body: &GrantManagementResponseBody{
			Scopes:               grant.Permissions.Scopes,
			Claims:               grant.Permissions.Claims,
			AuthorizationDetails: grant.Permissions.AuthorizationDetails,
			CreatedAt:            unixOrZero(grant.CreatedAt),
			LastUpdatedAt:        unixOrZero(grant.UpdatedAt),
			ExpiresAt:            unixOrZero(grant.ExpiresAt),
			UpdatedBy:            grant.UpdatedBy,
		},
	}, nil
}

// RevokeGrant revokes the refresh tokens and access tokens issued under the grant and then deletes it, whether or
// not it has expired. It returns ErrNotFound when there is no such grant.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-6.5
func (f *Fosite) RevokeGrant(ctx context.Context, id string) (err error) {
	var storage GrantManagementStorage

	if _, storage, err = f.grantManagement(ctx); err != nil {
		return err
	}

	return revokeGrant(ctx, storage, id)
}

func getGrant(ctx context.Context, storage GrantManagementStorage, id string) (grant *Grant, err error) {
	if grant, err = storage.GetGrant(ctx, id); errors.Is(err, ErrNotFound) {
		return nil, errorsx.WithStack(ErrNotFound.WithWrap(err).WithDebug("The grant does not exist."))
	} else if err != nil {
		return nil, errorsx.WithStack(ErrServerError.WithWrap(err).WithDebugError(err))
	}

	if grant == nil {
		return nil, errorsx.WithStack(ErrNotFound.WithDebug("The grant does not exist."))
	}

	return grant, nil
}

func revokeGrant(ctx context.Context, storage GrantManagementStorage, id string) (err error) {
	var previous, final []string

	if previous, err = storage.ReplaceGrantRequestIDs(ctx, id, nil); err != nil {
		return grantNotDeleted(err)
	}

	ctx = context.WithoutCancel(ctx)

	if err = revokeGrantRequests(ctx, storage, previous); err != nil {
		for _, requestID := range previous {
			_ = storage.AppendGrantRequestID(ctx, id, requestID)
		}

		return err
	}

	if final, err = storage.DeleteGrant(ctx, id); errors.Is(err, ErrNotFound) {
		return nil
	} else if err != nil {
		return grantNotDeleted(err)
	}

	return revokeGrantRequests(ctx, storage, final)
}

func revokeGrantRequests(ctx context.Context, storage GrantManagementStorage, requestIDs []string) (err error) {
	for _, requestID := range requestIDs {
		if err = grantTokensRevoked(storage.RevokeRefreshToken(ctx, requestID)); err != nil {
			return err
		}

		if err = grantTokensRevoked(storage.RevokeAccessToken(ctx, requestID)); err != nil {
			return err
		}
	}

	return nil
}

func grantNotDeleted(err error) error {
	if errors.Is(err, ErrNotFound) {
		return errorsx.WithStack(ErrNotFound.WithWrap(err).WithDebug("The grant does not exist."))
	}

	return errorsx.WithStack(ErrServerError.WithWrap(err).WithDebugError(err))
}

func grantTokensRevoked(err error) error {
	if err == nil || errors.Is(err, ErrNotFound) || errors.Is(err, ErrInactiveToken) {
		return nil
	}

	return errorsx.WithStack(ErrServerError.WithWrap(err).WithDebugError(err))
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}

	return t.Unix()
}
