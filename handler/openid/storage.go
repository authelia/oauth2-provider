// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"time"

	"authelia.com/provider/oauth2"
)

var ErrNoSessionFound = oauth2.ErrNotFound

type OpenIDConnectRequestStorage interface {
	// CreateOpenIDConnectSession creates an open id connect session
	// for a given authorize code. This is relevant for explicit open id connect flow.
	CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, request oauth2.Requester) error

	// GetOpenIDConnectSession returns error
	// - nil if a session was found,
	// - ErrNoSessionFound if no session was found
	// - or an arbitrary error if an error occurred.
	GetOpenIDConnectSession(ctx context.Context, authorizeCode string, request oauth2.Requester) (oauth2.Requester, error)

	// DeleteOpenIDConnectSession deletes the OpenID Connect 1.0 session from storage.
	DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error

	// SetOpenIDConnectNonceUsed atomically records that the client used the 'nonce' in an accepted authentication
	// request, keeping the record until expiresAt. It must return oauth2.ErrOpenIDConnectNonceReused, without changing
	// the existing record, when the client already used the nonce and that record has not expired. A record for another
	// client must not affect the result. Implementations may store a digest of the nonce rather than the value.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1
	SetOpenIDConnectNonceUsed(ctx context.Context, clientID, nonce string, expiresAt time.Time) (err error)
}
