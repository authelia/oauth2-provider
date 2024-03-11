// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package pkce

import (
	"context"

	"authelia.com/provider/oauth2"
)

type Storage interface {
	GetPKCERequestSession(ctx context.Context, signature string, session oauth2.Session) (oauth2.Requester, error)
	CreatePKCERequestSession(ctx context.Context, signature string, requester oauth2.Requester) error
	DeletePKCERequestSession(ctx context.Context, signature string) error
}
