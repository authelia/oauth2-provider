// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oidckb

import (
	"crypto/sha256"
	"encoding/base64"
)

// CodeHash returns the OpenID Connect Key Binding 1.0 Section 2.3 'c_s256' value for code, defined as
// BASE64URL(SHA256(ASCII(code))). Section 3.3 uses the same construction over the RFC 8628 device code.
func CodeHash(code string) (hash string) {
	sum := sha256.Sum256([]byte(code))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}
