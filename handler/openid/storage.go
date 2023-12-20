// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"

	"authelia.com/provider/oauth2"
)

var ErrNoSessionFound = oauth2.ErrNotFound

type OpenIDConnectRequestStorage interface {
	// CreateOpenIDConnectSession creates an open id connect session
	// for a given authorize code. This is relevant for explicit open id connect flow.
	CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, requester oauth2.Requester) error

	// GetOpenIDConnectSession returns error
	// - nil if a session was found,
	// - ErrNoSessionFound if no session was found
	// - or an arbitrary error if an error occurred.
	GetOpenIDConnectSession(ctx context.Context, authorizeCode string, requester oauth2.Requester) (oauth2.Requester, error)

	// Deprecated: DeleteOpenIDConnectSession is not called from anywhere.
	// Originally, it should remove an open id connect session from the store.
	DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error
}
