// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"

	"authelia.com/provider/oauth2/internal/consts"
)

// IsPKCECodeVerifierMatch reports whether the 'code_verifier' matches the 'code_challenge' under the given
// 'code_challenge_method', comparing in constant time. Any method other than 'S256' is compared as 'plain'.
//
// See: https://www.rfc-editor.org/rfc/rfc7636#section-4.6
func IsPKCECodeVerifierMatch(method, challenge, verifier string) (match bool) {
	if challenge == "" || verifier == "" {
		return false
	}

	if method == consts.PKCEChallengeMethodSHA256 {
		sum := sha256.Sum256([]byte(verifier))

		expected := make([]byte, base64.RawURLEncoding.EncodedLen(len(sum)))

		base64.RawURLEncoding.Strict().Encode(expected, sum[:])

		return subtle.ConstantTimeCompare(expected, []byte(challenge)) == 1
	}

	return subtle.ConstantTimeCompare([]byte(verifier), []byte(challenge)) == 1
}
