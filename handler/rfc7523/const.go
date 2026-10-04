// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7523

import (
	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
)

var assertionAlgorithms = []jose.SignatureAlgorithm{jose.HS256, jose.HS384, jose.HS512, jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512}

const hintAssertionUnverified = "Unable to verify the integrity of the 'assertion' value."

var errJWTUsed = oauth2.ErrInvalidGrant.WithHint("The JWT in 'assertion' request parameter has already been used and its 'jti' (JWT ID) claim can not be used again until it expires.")
