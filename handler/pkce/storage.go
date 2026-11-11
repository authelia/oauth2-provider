// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package pkce

import (
	"context"
	"time"

	"authelia.com/provider/oauth2"
)

type Storage interface {
	GetPKCERequestSession(ctx context.Context, signature string, session oauth2.Session) (oauth2.Requester, error)
	CreatePKCERequestSession(ctx context.Context, signature string, request oauth2.Requester) error
	DeletePKCERequestSession(ctx context.Context, signature string) error

	// SetPKCEChallengeUsed atomically records that the client used the 'code_challenge' in an accepted authorization
	// request, keeping the record until expiresAt. It must return oauth2.ErrPKCEChallengeReused, without changing the
	// existing record, when the client already used the challenge and that record has not expired. A record for another
	// client must not affect the result. Implementations may store a digest of the challenge rather than the value.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1
	SetPKCEChallengeUsed(ctx context.Context, clientID, challenge string, expiresAt time.Time) (err error)
}
