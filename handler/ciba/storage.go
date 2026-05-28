// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ciba

import (
	"context"

	"authelia.com/provider/oauth2"
)

// Storage persists OpenID Connect CIBA backchannel authentication sessions keyed by the storage signature of the
// auth_req_id issued to the client.
type Storage interface {
	// CreateOpenIDCIBASession stores the CIBA request for a given auth_req_id signature.
	CreateOpenIDCIBASession(ctx context.Context, signature string, request oauth2.CIBARequester) (err error)

	// UpdateOpenIDCIBASession replaces the CIBA request stored under the given auth_req_id signature.
	UpdateOpenIDCIBASession(ctx context.Context, signature string, request oauth2.CIBARequester) (err error)

	// GetOpenIDCIBASession hydrates the session for the supplied auth_req_id signature.
	GetOpenIDCIBASession(ctx context.Context, signature string, session oauth2.Session) (request oauth2.CIBARequester, err error)

	// InvalidateOpenIDCIBASession is called once the auth_req_id has been used to obtain tokens. Subsequent calls to
	// GetOpenIDCIBASession for the same signature should error.
	InvalidateOpenIDCIBASession(ctx context.Context, signature string) (err error)
}
