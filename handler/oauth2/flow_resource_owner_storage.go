// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
)

// ResourceOwnerPasswordCredentialsGrantStorage is the storage the resource owner password credentials grant requires.
type ResourceOwnerPasswordCredentialsGrantStorage interface {
	AccessTokenStorage
	RefreshTokenStorage

	// Authenticate verifies the resource owner credentials and returns the subject. It returns oauth2.ErrNotFound when the
	// credentials are not valid, which answers invalid_grant, and any other error answers server_error.
	Authenticate(ctx context.Context, name string, secret string) (subject string, err error)
}

// ResourceOwnerSession is a session that can record the subject.
type ResourceOwnerSession interface {
	// SetSubject records the subject of the authenticated resource owner on the session.
	SetSubject(subject string)
}
