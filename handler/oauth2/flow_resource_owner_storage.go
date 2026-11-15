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

	Authenticate(ctx context.Context, name string, secret string) (subject string, err error)
}

// ResourceOwnerSession is a session that can record the subject.
type ResourceOwnerSession interface {
	SetSubject(subject string)
}
