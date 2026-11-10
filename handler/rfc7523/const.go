// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7523

import (
	"authelia.com/provider/oauth2"
)

const hintAssertionUnverified = "Unable to verify the integrity of the 'assertion' value."

var errJWTUsed = oauth2.ErrInvalidGrant.WithHint("The JWT in 'assertion' request parameter has already been used and its 'jti' (JWT ID) claim can not be used again until it expires.")
