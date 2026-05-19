// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package hmac

import (
	"crypto/rand"
	"io"

	"authelia.com/provider/oauth2/x/errorsx"
)

// RandomBytes returns n random bytes by reading from crypto/rand.Reader
func RandomBytes(n int) ([]byte, error) {
	bytes := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return []byte{}, errorsx.WithStack(err)
	}
	return bytes, nil
}
