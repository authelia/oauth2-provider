// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"authelia.com/provider/jose"
)

// ToSignatureAlgorithms converts configured JWS 'alg' values to their typed form.
//
// See: https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.1
func ToSignatureAlgorithms(algs []string) (out []jose.SignatureAlgorithm) {
	out = make([]jose.SignatureAlgorithm, 0, len(algs))

	for _, alg := range algs {
		out = append(out, jose.SignatureAlgorithm(alg))
	}

	return out
}

// ToAsymmetricSignatureAlgorithms converts configured JWS 'alg' values to their typed form, dropping 'none' and the
// HMAC algorithms. It is for verifying a JWT from a party whose keys are public, which a symmetric algorithm would let
// anyone holding the public key forge.
//
// See: https://datatracker.ietf.org/doc/html/rfc8725#section-3.1
func ToAsymmetricSignatureAlgorithms(algs []string) (out []jose.SignatureAlgorithm) {
	out = make([]jose.SignatureAlgorithm, 0, len(algs))

	for _, alg := range algs {
		if alg == JSONWebTokenAlgNone || IsSignedJWTClientSecretAlgStr(alg) {
			continue
		}

		out = append(out, jose.SignatureAlgorithm(alg))
	}

	return out
}

// ToKeyAlgorithms converts configured JWE 'alg' values to their typed form.
//
// See: https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.1
func ToKeyAlgorithms(algs []string) (out []jose.KeyAlgorithm) {
	out = make([]jose.KeyAlgorithm, 0, len(algs))

	for _, alg := range algs {
		out = append(out, jose.KeyAlgorithm(alg))
	}

	return out
}

// ToContentEncryptions converts configured JWE 'enc' values to their typed form.
//
// See: https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.2
func ToContentEncryptions(encs []string) (out []jose.ContentEncryption) {
	out = make([]jose.ContentEncryption, 0, len(encs))

	for _, enc := range encs {
		out = append(out, jose.ContentEncryption(enc))
	}

	return out
}
