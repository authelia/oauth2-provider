// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"context"
	"time"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/x/errorsx"
)

func propagateGrant(ctx context.Context, store any, subject oauth2.Session, issued oauth2.Session, requestID string) (err error) {
	source, ok := subject.(oauth2.GrantManagementSession)
	if !ok {
		return nil
	}

	id := source.GetGrantID()
	if id == "" {
		return nil
	}

	storage, ok := store.(oauth2.GrantManagementStorage)
	if !ok {
		return nil
	}

	target, ok := issued.(oauth2.GrantManagementSession)
	if !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("The subject token was issued under a grant but the session of the token exchange cannot record it."))
	}

	var grant *oauth2.Grant

	switch grant, err = storage.GetGrant(ctx, id); {
	case errors.Is(err, oauth2.ErrNotFound):
		return errGrantGone("The grant does not exist.")
	case err != nil:
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	case grant == nil:
		return errGrantGone("The grant does not exist.")
	case !grant.ExpiresAt.IsZero() && !grant.ExpiresAt.After(time.Now().UTC()):
		return errGrantGone("The grant has expired.")
	}

	switch err = storage.AppendGrantRequestID(ctx, id, requestID); {
	case errors.Is(err, oauth2.ErrNotFound):
		return errGrantGone("The grant does not exist.")
	case err != nil:
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	target.SetGrantID(id)
	target.SetGrantManagementAction("")
	target.SetGrantPermissions(nil)

	return nil
}

func subjectTokenSession(request oauth2.Requester) oauth2.Session {
	session, ok := request.GetSession().(Session)
	if !ok {
		return nil
	}

	subject := session.GetSubjectRequester()
	if subject == nil {
		return nil
	}

	return subject.GetSession()
}

func errGrantGone(debug string) error {
	return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The grant the subject token was issued under is no longer available.").WithDebug(debug))
}
