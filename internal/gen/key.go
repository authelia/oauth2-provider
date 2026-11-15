// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package gen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
)

// MustRSAKey generates a 2048 bit RSA key and panics on failure.
func MustRSAKey() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	return key
}

// MustES256Key generates an ECDSA key on the P-256 curve and panics on failure.
func MustES256Key() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	return key
}

// MustES521Key generates an ECDSA key on the P-521 curve and panics on failure.
func MustES521Key() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}

	return key
}
