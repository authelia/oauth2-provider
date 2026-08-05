// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import "time"

// ClientIDEntropy is the number of alphanumeric runes generated for a new 'client_id'.
const ClientIDEntropy = 64

// NonExpiringTokenLifespan is the lifespan applied to a client registration access token whose configured lifespan is
// zero, i.e. one documented as never expiring - the normal expectation for an RFC 7592 'registration_access_token',
// which has no re-issue path.
//
// A zero lifespan cannot simply leave the session's 'expires_at' unset: ValidateClientRegistrationToken treats an
// unset expiry as a sign the session is malformed and rejects it outright, with no fallback to a configured lifespan
// the way ValidateAccessToken has for ordinary access tokens (see that method's doc comment). Recording an explicit
// far-future expiry instead is what makes "never expires" mean what it says.
//
// A century is chosen because it is unambiguously beyond any deployment's horizon while remaining far away from
// time.Time's and time.Duration's limits.
const NonExpiringTokenLifespan = 100 * 365 * 24 * time.Hour

// SectorIdentifierMaxBodyBytes bounds the number of bytes read from a 'sector_identifier_uri' response body. The
// URI is client-supplied, so the fetch must not be allowed to consume unbounded memory.
const SectorIdentifierMaxBodyBytes = 1 << 20
