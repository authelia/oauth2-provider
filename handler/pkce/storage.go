// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package pkce

import (
	"context"

	"authelia.com/provider/oauth2"
)

type Storage interface {
	GetPKCERequestSession(ctx context.Context, signature string, session oauth2.Session) (oauth2.Requester, error)
	CreatePKCERequestSession(ctx context.Context, signature string, request oauth2.Requester) error
	DeletePKCERequestSession(ctx context.Context, signature string) error
}
