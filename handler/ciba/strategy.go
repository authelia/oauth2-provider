// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ciba

import (
	"context"

	"authelia.com/provider/oauth2"
)

// AuthRequestIDStrategy generates, signs and validates the 'auth_req_id' of an OpenID Connect CIBA authentication
// request.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#successful_authentication_request_acknowledgement
type AuthRequestIDStrategy interface {
	// CIBAAuthRequestIDSignature returns the signature of the given 'auth_req_id'.
	CIBAAuthRequestIDSignature(ctx context.Context, id string) (signature string, err error)

	// GenerateCIBAAuthRequestID returns a new 'auth_req_id' with at least 160 bits of entropy, restricted to the
	// characters A-Z, a-z, 0-9, '.', '-' and '_', and its signature.
	GenerateCIBAAuthRequestID(ctx context.Context) (id string, signature string, err error)

	// ValidateCIBAAuthRequestID validates the 'auth_req_id' and returns oauth2.ErrDeviceExpiredToken once the request
	// has expired.
	ValidateCIBAAuthRequestID(ctx context.Context, r oauth2.Requester, id string) (err error)
}
