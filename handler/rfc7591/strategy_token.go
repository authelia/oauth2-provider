// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"

	"authelia.com/provider/oauth2"
)

// ClientRegistrationTokenStrategy mints, signs and validates RFC 7591 / RFC 7592 client registration tokens. Both
// hoauth2.HMACCoreStrategy and hoauth2.JWTProfileCoreStrategy satisfy it; client registration tokens are always opaque.
type ClientRegistrationTokenStrategy interface {
	// ClientRegistrationTokenSignature returns the signature of the given client registration token, or an empty
	// string when the token is not one.
	ClientRegistrationTokenSignature(ctx context.Context, tokenString string) (signature string)

	// GenerateClientRegistrationToken mints a new client registration token.
	GenerateClientRegistrationToken(ctx context.Context, requester oauth2.Requester) (tokenString string, signature string, err error)

	// ValidateClientRegistrationToken validates the given client registration token against its request.
	ValidateClientRegistrationToken(ctx context.Context, requester oauth2.Requester, tokenString string) (err error)
}
