// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
)

// Storage is the persistence seam consumed by the RFC 7591 / RFC 7592 dynamic client registration handlers. Client
// registration tokens are ordinary access tokens, so their sessions live in access token storage alongside every
// other access token rather than in a store of their own.
type Storage interface {
	oauth2.ClientManager
	hoauth2.AccessTokenStorage
}
