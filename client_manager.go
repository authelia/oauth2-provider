// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"time"
)

// ClientRegistrationManager defines the (persistent) manager interface for dynamically registered clients. It is
// embedded in ClientManager so a store which does not support dynamic registration can return ErrNotFound from each
// method.
//
// See: https://datatracker.ietf.org/doc/html/rfc7591 and https://datatracker.ietf.org/doc/html/rfc7592.
type ClientRegistrationManager interface {
	// CreateClient persists a newly registered client. It must return an error if a client with the same ID
	// already exists.
	CreateClient(ctx context.Context, client Client) (err error)

	// UpdateClient persists changes to the client registered with the given ID. The ID is provided separately so
	// the store need not trust the client to expose an unchanged identifier. It must return an error if no client
	// with the given ID exists.
	UpdateClient(ctx context.Context, id string, client Client) (err error)

	// DeleteClient removes the client registered with the given ID. It must return an error if no client with the
	// given ID exists.
	DeleteClient(ctx context.Context, id string) (err error)
}

// ClientManager defines the (persistent) manager interface for clients.
type ClientManager interface {
	// GetClient loads the client by its ID or returns an error
	// if the client does not exist or another error occurred.
	GetClient(ctx context.Context, id string) (client Client, err error)

	// ClientAssertionJWTValid returns an error if the JTI is known for the client or the DB check failed and nil if
	// the JTI is not known. A JTI is only unique among the JWTs produced by one issuer per RFC 7519 Section 4.1.7, and
	// the issuer of a client assertion is the client per RFC 7521 Section 5.2, so the JTI must be scoped to the client.
	ClientAssertionJWTValid(ctx context.Context, clientID, jti string) (err error)

	// SetClientAssertionJWT marks a JTI as known for the client until the given expiry time, scoped to the client as
	// described for ClientAssertionJWTValid. An expired JTI can not be replayed due to the expiry, so an
	// implementation may remove expired JTIs at any time.
	//
	// The mark MUST be atomic and MUST return an error matching ErrJTIKnown when the JTI is already known and has not
	// expired, as ClientAssertionJWTValid alone can not prevent two concurrent requests using the same JTI.
	SetClientAssertionJWT(ctx context.Context, clientID, jti string, exp time.Time) (err error)

	ClientRegistrationManager
}
