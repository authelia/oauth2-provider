// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import "time"

// ClientIDEntropy is the number of alphanumeric runes generated for a new 'client_id'.
const ClientIDEntropy = 64

// NonExpiringTokenLifespan is the lifespan applied to a client registration access token whose configured lifespan is
// zero, i.e. one that never expires. An explicit far-future expiry is recorded because ValidateClientRegistrationToken
// rejects a session with an unset expiry.
const NonExpiringTokenLifespan = 100 * 365 * 24 * time.Hour

// SectorIdentifierMaxBodyBytes bounds the number of bytes read from a 'sector_identifier_uri' response body. The
// URI is client-supplied, so the fetch must not be allowed to consume unbounded memory.
const SectorIdentifierMaxBodyBytes = 1 << 20
