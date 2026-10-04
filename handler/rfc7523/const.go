// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7523

import (
	"authelia.com/provider/jose"
)

var assertionAlgorithms = []jose.SignatureAlgorithm{jose.HS256, jose.HS384, jose.HS512, jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512}

const hintAssertionUnverified = "Unable to verify the integrity of the 'assertion' value."
