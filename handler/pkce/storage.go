// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package pkce

import (
	"context"

	"github.com/authelia/goauth2"
)

type PKCERequestStorage interface {
	GetPKCERequestSession(ctx context.Context, signature string, session goauth2.Session) (goauth2.Requester, error)
	CreatePKCERequestSession(ctx context.Context, signature string, requester goauth2.Requester) error
	DeletePKCERequestSession(ctx context.Context, signature string) error
}
