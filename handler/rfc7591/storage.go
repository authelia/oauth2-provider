// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
)

// ClientRegistrationTokenStorage handles storage requests related to RFC 7592 client management tokens.
//
// Client management tokens have their own storage namespace rather than sharing the access token namespace, in the
// same way access tokens and refresh tokens each have their own. That separation is a security control: while these
// tokens lived in access token storage every consumer of an access token could load one, and both the introspection
// endpoint's bearer authentication and the RFC 8693 subject_token path accepted one as a general purpose credential.
// The client configuration endpoint's authentication now rests on it, since DefaultEndpointAuthStrategy resolves a
// management token only from here and the registration endpoint's creation token only from access token storage, so
// neither credential can be presented at the other's endpoint.
//
// An implementation MUST NOT satisfy these methods from the same namespace it uses for access tokens. A management
// token never expires and authorises full control of the client it names, and a session hydrating here is evaluated
// as one: the only checks left are that the token validates, that its granted audience names the requested client's
// registration_client_uri, and that it was issued to that client. A namespace violation therefore fails open toward
// the more privileged credential rather than failing closed.
type ClientRegistrationTokenStorage interface {
	// CreateClientRegistrationTokenSession stores the request for a given client registration token signature.
	CreateClientRegistrationTokenSession(ctx context.Context, signature string, request oauth2.Requester) (err error)

	// GetClientRegistrationTokenSession hydrates the session based on the given client registration token signature
	// and returns the request. This method should return the oauth2.ErrNotFound error if no session exists for the
	// given signature.
	GetClientRegistrationTokenSession(ctx context.Context, signature string, session oauth2.Session) (request oauth2.Requester, err error)

	// DeleteClientRegistrationTokenSession removes the session stored against the given client registration token
	// signature.
	DeleteClientRegistrationTokenSession(ctx context.Context, signature string) (err error)
}

// Storage is the persistence seam consumed by the RFC 7591 / RFC 7592 dynamic client registration handlers.
type Storage interface {
	oauth2.ClientManager
	ClientRegistrationTokenStorage

	// AccessTokenStorage is required because a client creation token is an ordinary access token: it is obtained
	// through the token endpoint and resolved here from the same storage as any other. Client management tokens
	// remain in ClientRegistrationTokenStorage, and each endpoint consults exactly one of the two namespaces, which
	// keeps a token of one kind from being presented at the other's endpoint.
	hoauth2.AccessTokenStorage
}
