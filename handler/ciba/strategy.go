// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ciba

import (
	"context"

	"authelia.com/provider/oauth2"
)

// AuthRequestIDStrategy is the strategy used to generate and validate the auth_req_id returned by the OpenID Connect
// CIBA backchannel authentication endpoint per Section 7.3 of the specification.
type AuthRequestIDStrategy interface {
	// GenerateAuthRequestID returns a freshly generated auth_req_id alongside its storage signature.
	GenerateAuthRequestID(ctx context.Context) (id, signature string, err error)

	// AuthRequestIDSignature returns the storage signature for an existing auth_req_id without performing validation.
	AuthRequestIDSignature(ctx context.Context, id string) (signature string, err error)

	// ValidateAuthRequestID verifies that the given auth_req_id is well-formed and tied to the supplied request. It is
	// invoked at the token endpoint when a client polls with grant_type=urn:openid:params:grant-type:ciba.
	ValidateAuthRequestID(ctx context.Context, request oauth2.Requester, id string) (err error)
}
