// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
)

// Storage defines the minimal storage interface.
type Storage interface {
	ClientManager
}

// PARStorage holds information needed to store and retrieve PAR context.
type PARStorage interface {
	// CreatePARSession stores the pushed authorization request context. The requestURI is used to derive the key.
	CreatePARSession(ctx context.Context, requestURI string, request AuthorizeRequester) (err error)

	// GetPARSession gets the push authorization request context. The caller is expected to merge the AuthorizeRequest.
	// The current client registration is fetched and the returned request is validated against it per RFC 9126
	// Section 7.4, unless GetDisablePushedAuthorizationRequestClientRefetch is true, in which case the client of the
	// returned request is used as is and should reflect the current client registration.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc9126#section-7.4
	GetPARSession(ctx context.Context, requestURI string) (requester AuthorizeRequester, err error)

	// DeletePARSession deletes the context. It should delete the context atomically and return ErrNotFound if the
	// context does not exist, so that concurrent redemptions of a request_uri fail after the first per RFC 9126
	// Section 4 and Section 7.3.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc9126#section-7.3
	DeletePARSession(ctx context.Context, requestURI string) (err error)
}
