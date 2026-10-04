// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7523

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"math/big"
	"sync"

	"authelia.com/provider/jose"
	"authelia.com/provider/jose/jwt"
)

func verifyDecoy(token *jwt.JSONWebToken) {
	if len(token.Headers) == 0 {
		return
	}

	if key := decoyKey(jose.SignatureAlgorithm(token.Headers[0].Algorithm)); key != nil {
		_ = token.Claims(key, &jwt.Claims{})
	}
}

func decoyKey(alg jose.SignatureAlgorithm) any {
	switch alg {
	case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
		return decoyRSAKey()
	case jose.ES256:
		return decoyECDSAKey(elliptic.P256())
	case jose.ES384:
		return decoyECDSAKey(elliptic.P384())
	case jose.ES512:
		return decoyECDSAKey(elliptic.P521())
	case jose.HS256, jose.HS384, jose.HS512:
		return decoyHMACKey
	default:
		return nil
	}
}

func decoyECDSAKey(curve elliptic.Curve) *ecdsa.PublicKey {
	params := curve.Params()

	return &ecdsa.PublicKey{Curve: curve, X: params.Gx, Y: params.Gy}
}

var decoyRSAKey = sync.OnceValue(func() *rsa.PublicKey {
	n, _ := new(big.Int).SetString(decoyRSAModulus, 16)

	return &rsa.PublicKey{N: n, E: 65537}
})

var decoyHMACKey = make([]byte, 64)

const decoyRSAModulus = "" +
	"b7c1d714141911d15fef9fa3df0b5aae5cb382d6c0e8ecf46f5b27792dfd80092b40c317bf7ac66ae3f48a0f2997df87" +
	"ab54886bec617c557e6709318a0eb6c333caa75014cd241b083cd7ccfb9266231af2fe2ec892228d2d5d55e4529baa49" +
	"d667f81fcb6034d6eef77390bd81791e76dbcf240c47235518746e7cc4245427682f991679c679f60d7de7e2719071b8" +
	"4f62db854eba92097b72b368b98996427435e70dcdc588338f78d2eabb1b8701593825e7a270a01c05fd023ce05f5e62" +
	"0a79f65a384bdd7bc90e9a4beb6abb625a2da48cf1bf99077b69fea6211bdd96b4bac832730221bd9edf0a35005ad5fd" +
	"873d87a70d8b63686a4a205d9f4716a9"
