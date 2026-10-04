// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7523

const (
	sig   = "sig"
	token = "token"
	keyID = "my_key"

	errJWTUsedMessage = "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The JWT in 'assertion' request parameter has already been used and its 'jti' (JWT ID) claim can not be used again until it expires."
)
