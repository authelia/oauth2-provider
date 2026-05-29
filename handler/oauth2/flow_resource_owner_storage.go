// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
)

type ResourceOwnerPasswordCredentialsGrantStorage interface {
	AccessTokenStorage
	RefreshTokenStorage

	Authenticate(ctx context.Context, name string, secret string) (subject string, err error)
}

type ResourceOwnerSession interface {
	SetSubject(subject string)
}
